"""Integration config flow."""

from __future__ import annotations

import logging
import io
from typing import TYPE_CHECKING, Literal, TypedDict

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.data_entry_flow import section
from homeassistant.helpers.selector import SelectOptionDict, SelectSelector, SelectSelectorConfig, TextSelector, TextSelectorConfig

from findmy.accessory import KeyPair
from findmy.accessory import FindMyAccessory
from findmy.errors import InvalidCredentialsError, UnhandledProtocolError
from findmy.reports import AsyncAppleAccount, LoginState, RemoteAnisetteProvider
from findmy.reports.twofactor import (
    AsyncSecondFactorMethod,
    SmsSecondFactorMethod,
    TrustedDeviceSecondFactorMethod,
)

from .const import DEFAULT_ANISETTE_URL, DOMAIN

if TYPE_CHECKING:
    from typing import Any

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA_ACC_LOGIN = vol.Schema(
    {
        vol.Required("email"): str,
        vol.Required("password"): str,
        "advanced_options": section(
            vol.Schema(
                {
                    vol.Required("anisette_url", default=DEFAULT_ANISETTE_URL): str,
                },
            ),
            {"collapsed": True},
        ),
    },
)
DATA_SCHEME_ACC_2FA = vol.Schema(
    {
        vol.Required("code"): str,
    },
)

DATA_SCHEME_DEV_CHOOSE = vol.Schema(
    {
        "device_type": SelectSelector(
            SelectSelectorConfig(
                options=["static", "rolling"],
                translation_key="device_type",
            ),
        ),
    },
)

DATA_SCHEME_DEV_STATIC = vol.Schema(
    {
        vol.Required("name"): str,
        vol.Required("private_key"): str,
    },
)

DATA_SCHEME_DEV_ROLLING = vol.Schema(
    {
        vol.Required("name"): str,
        vol.Required("plist"): TextSelector(TextSelectorConfig(multiline=True)),
    },
)

class LoginFlowAdvancedOptions(TypedDict):
    anisette_url: str


class LoginFlowInput(TypedDict):
    """Input to the login step."""

    email: str
    password: str
    advanced_options: LoginFlowAdvancedOptions


class MfaSubmitInput(TypedDict):
    code: str


class DeviceTypeInput(TypedDict):
    device_type: Literal["static", "rolling"]


class StaticDeviceInput(TypedDict):
    name: str
    private_key: str

class RollingDeviceInput(TypedDict):
    name: str
    plist: str

class EntryDataAccount(TypedDict):
    type: Literal["account"]
    account_data: dict[Any, Any]
    anisette_url: str


class EntryDataStaticDevice(TypedDict):
    type: Literal["device_static"]
    name: str
    private_key: str

class EntryDataRollingDevice(TypedDict):
    type: Literal["device_rolling"]
    name: str
    plist: str

type EntryData = EntryDataAccount | EntryDataStaticDevice


class InitialSetupConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for initial setup."""

    VERSION, MINOR_VERSION = 1, 1

    def __init__(self, *args, **kwargs) -> None:
        """Initialize."""
        super().__init__(*args, **kwargs)

        self._anisette_url: str | None = None
        self._account: AsyncAppleAccount | None = None
        self._2fa_method: AsyncSecondFactorMethod | None = None

        self._error: Exception | None = None
        self._2fa_methods: list[AsyncSecondFactorMethod] = []

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: user - %s", self.__class__.__name__, user_input)

        return self.async_show_menu(
            step_id="user",
            menu_options={
                "start_acc": "Apple Account",
                "start_dev": "FindMy Device",
            },
        )

    ##########################
    ### Account Setup Flow ###
    ##########################

    async def async_step_start_acc(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: start_acc - %s", self.__class__.__name__, user_input)

        return self.async_show_form(
            step_id="acc_login",
            data_schema=DATA_SCHEMA_ACC_LOGIN,
        )

    async def async_step_acc_login(
        self,
        info: LoginFlowInput | None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug(
            "%s Step: acc_login - %s",
            self.__class__.__name__,
            {**(info or {}), "password": "**REDACTED**"},
        )

        if info is None:
            _LOGGER.warning("Login step called without info data")
            return self.async_show_form(
                step_id="acc_login",
                data_schema=DATA_SCHEMA_ACC_LOGIN,
            )

        await self.async_set_unique_id(info["email"].lower())
        self._abort_if_unique_id_configured()

        _LOGGER.info("Log into Apple account: %s", info["email"])

        self._anisette_url = info["advanced_options"]["anisette_url"]
        anisette = RemoteAnisetteProvider(self._anisette_url)
        self._account = AsyncAppleAccount(anisette=anisette)

        # Attempt login
        try:
            await self._account.login(info["email"], info["password"])
        except InvalidCredentialsError:
            return self.async_show_form(
                step_id="acc_login",
                data_schema=DATA_SCHEMA_ACC_LOGIN,
                errors={"base": "invalid_auth"},
            )
        except UnhandledProtocolError:
            _LOGGER.exception("Unhandled protocol exception during login")
            return self.async_abort(reason="protocol_error")

        _LOGGER.debug("State after login: %s", self._account.login_state)

        if self._account.login_state == LoginState.REQUIRE_2FA:
            return await self.async_step_acc_2fa_prompt()
        return await self.async_step_acc_done()

    async def async_step_acc_2fa_prompt(
        self,
        info: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: acc_2fa_prompt - %s", self.__class__.__name__, info)

        if self._account is None or self._account.login_state != LoginState.REQUIRE_2FA:
            _LOGGER.error("2FA step called but account configured incorrectly")
            return self.async_abort(reason="unknown_error")

        self._2fa_methods = await self._account.get_2fa_methods()

        menu_options: list[SelectOptionDict] = []
        for i, method in enumerate(self._2fa_methods):
            if isinstance(method, TrustedDeviceSecondFactorMethod):
                menu_options.append(
                    {
                        "label": "Trusted Device",
                        "value": str(i),
                    },
                )
            elif isinstance(method, SmsSecondFactorMethod):
                menu_options.append(
                    {
                        "label": f"SMS - {method.phone_number}",
                        "value": str(i),
                    },
                )
            else:
                _LOGGER.warning("Unknown 2FA method: %s", method)
                continue

        if not menu_options:
            return self.async_show_form(
                step_id="acc_login",
                data_schema=DATA_SCHEMA_ACC_LOGIN,
                errors={"base": "2fa_unavailable"},
            )

        schema = vol.Schema(
            {
                "method_id": SelectSelector(
                    SelectSelectorConfig(
                        options=menu_options,
                    ),
                ),
            },
        )
        return self.async_show_form(
            step_id="acc_2fa_request",
            data_schema=schema,
        )

    async def async_step_acc_2fa_request(
        self,
        info: dict | None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: acc_2fa_request - %s", self.__class__.__name__, info)

        if info is None:
            _LOGGER.error("2FA requested but no method ID")
            return self.async_abort(reason="unknown_error")

        try:
            method_id: int = int(info["method_id"])
            self._2fa_method = self._2fa_methods[method_id]
        except (KeyError, ValueError):
            _LOGGER.exception("Unable to look up method ID")
            return self.async_abort(reason="unknown_error")

        await self._2fa_method.request()

        return self.async_show_form(
            step_id="acc_2fa_submit",
            data_schema=DATA_SCHEME_ACC_2FA,
        )

    async def async_step_acc_2fa_submit(
        self,
        info: MfaSubmitInput,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: acc_2fa_submit - %s", self.__class__.__name__, info)

        code = info.get("code")
        if not code:
            _LOGGER.error("No 2FA code submitted")
            return self.async_show_form(
                step_id="2fa_submit",
                data_schema=DATA_SCHEME_ACC_2FA,
            )

        if self._2fa_method is None:
            _LOGGER.error("No active 2FA method in the flow")
            return self.async_abort(reason="unknown_error")

        try:
            await self._2fa_method.submit(code)
        except UnhandledProtocolError:
            _LOGGER.exception("Unhandled protocol exception during 2FA submit")
            return self.async_show_form(
                step_id="acc_2fa_submit",
                data_schema=DATA_SCHEME_ACC_2FA,
                errors={"base": "2fa_invalid"},
            )

        return await self.async_step_acc_done()

    async def async_step_acc_done(
        self,
        info: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: acc_done - %s", self.__class__.__name__, info)

        if self._anisette_url is None or self._account is None:
            _LOGGER.exception("No anisette url or account configured")
            return self.async_abort(reason="unknown_error")

        data = EntryDataAccount(
            type="account",
            account_data=self._account.to_json(),
            anisette_url=self._anisette_url,
        )

        return self.async_create_entry(
            title=f"Account: {self._account.account_name}",
            data=data,
        )

    #########################
    ### Device Setup Flow ###
    #########################

    async def async_step_start_dev(
        self,
        info: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: start_dev - %s", self.__class__.__name__, info)

        return self.async_show_form(
            step_id="dev_choose",
            data_schema=DATA_SCHEME_DEV_CHOOSE,
        )

    async def async_step_dev_choose(
        self,
        info: DeviceTypeInput | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: dev_choose - %s", self.__class__.__name__, info)

        dev_type = (info or {}).get("device_type", None)
        if dev_type == "static":
            return self.async_show_form(
                step_id="dev_static",
                data_schema=DATA_SCHEME_DEV_STATIC,
            )
        elif dev_type == "rolling":
            return self.async_show_form(
                step_id="dev_rolling",
                data_schema=DATA_SCHEME_DEV_ROLLING,
            )

        return self.async_show_form(
            step_id="dev_choose",
            data_schema=DATA_SCHEME_DEV_CHOOSE,
            errors={"base": "invalid_dev"},
        )

    async def async_step_dev_static(
        self,
        info: StaticDeviceInput | None = None,
    ) -> config_entries.ConfigFlowResult:
        _LOGGER.debug("%s Step: dev_static - %s", self.__class__.__name__, info)

        if not info:
            return self.async_show_form(
                step_id="dev_static",
                data_schema=DATA_SCHEME_DEV_STATIC,
                errors={"base": "invalid_dev"},
            )

        name = info.get("name", "Unknown")
        key = info.get("private_key", "")

        try:
            KeyPair.from_b64(key)
        except ValueError:
            return self.async_show_form(
                step_id="dev_static",
                data_schema=DATA_SCHEME_DEV_STATIC,
                errors={"base": "invalid_dev_key"},
            )

        data = EntryDataStaticDevice(
            type="device_static",
            name=name,
            private_key=key,
        )

        return self.async_create_entry(
            title=f"Device (Static): {name}",
            data=data,
        )

    async def async_step_dev_rolling(self, info: RollingDeviceInput | None = None) -> FlowResult:
        _LOGGER.debug("%s Step: dev_rolling - %s", self.__class__.__name__, info)

        if not info:
            return self.async_show_form(
                step_id="dev_rolling",
                data_schema=DATA_SCHEME_DEV_ROLLING,
                errors={"base": "invalid_dev"},
            )

        name = info.get("name", "Unknown")
        plist = info.get("plist", "")

        try:
            plist_io = io.BytesIO(bytes(plist, "utf-8"))
            FindMyAccessory.from_plist(plist_io)
        except ValueError:
            return self.async_show_form(
                step_id="dev_rolling",
                data_schema=DATA_SCHEME_DEV_ROLLING,
                errors={"base": "invalid_dev_key"},
            )

        data = EntryDataStaticDevice(
            type="device_rolling",
            name=name,
            plist=plist,
        )

        return self.async_create_entry(
            title=f"Device (Rolling): {name}",
            data=data,
        )
