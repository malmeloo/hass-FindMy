"""Integration config flow."""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, TypedDict, Callable

import voluptuous as vol
from homeassistant import config_entries

from findmy.reports import AsyncAppleAccount, LoginState, RemoteAnisetteProvider
from findmy.reports.twofactor import SmsSecondFactorMethod, AsyncSecondFactorMethod
from findmy.util.errors import InvalidCredentialsError, UnhandledProtocolError

from .const import DEFAULT_ANISETTE_URL, DOMAIN
import re

if TYPE_CHECKING:
    from typing import Any

    from homeassistant.data_entry_flow import FlowResult

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA_LOGIN = vol.Schema({
    vol.Required("anisette_url", default=DEFAULT_ANISETTE_URL): str,
    vol.Required("email"): str,
    vol.Required("password"): str,
})

MFA_MENU_CALLBACK_FMT = re.compile(r"^async_step_2fa_request_(\d+)$")


class LoginFlowInput(TypedDict):
    """Input to the login step."""

    anisette_url: str
    email: str
    password: str


class InitialSetupConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for initial setup."""

    VERSION, MINOR_VERSION = 1, 1

    def __init__(self, *args, **kwargs) -> None:
        """Initialize."""
        super().__init__(*args, **kwargs)

        self._account: AsyncAppleAccount | None = None

        self._error: Exception | None = None
        self._2fa_methods: list[AsyncSecondFactorMethod] = []

    def __getattr__(self, item: str) -> Callable:
        """Catch menu callbacks from the 2FA selection menu."""
        matches = MFA_MENU_CALLBACK_FMT.fullmatch(item)
        if not matches:
            raise AttributeError

        step_info = {"method_id": int(matches.group(1))}
        return lambda data: self.async_step_2fa_request({**(data or {}), **step_info})

    async def async_step_user(self, info: dict[str, Any] | None = None) -> FlowResult:
        _LOGGER.debug("%s Step: user - %s", self.__class__.__name__, info)

        return self.async_show_form(
            step_id="login",
            data_schema=DATA_SCHEMA_LOGIN
        )

    async def async_step_login(self, info: LoginFlowInput) -> FlowResult:
        _LOGGER.debug(
            "%s Step: login - %s",
            self.__class__.__name__,
            {**info, "password": "**REDACTED**"}
        )

        if info is None:
            logging.warning("Login step called without info data")
            return self.async_show_form(
                step_id="login",
                data_schema=DATA_SCHEMA_LOGIN
            )

        await self.async_set_unique_id(info["email"].lower())
        self._abort_if_unique_id_configured()

        _LOGGER.info("Log into Apple account: %s", info["email"])

        anisette = RemoteAnisetteProvider(info["anisette_url"])
        self._account = AsyncAppleAccount(anisette)

        # Attempt login
        try:
            await self._account.login(info["email"], info["password"])
        except InvalidCredentialsError:
            return self.async_show_form(
                step_id="login",
                data_schema=DATA_SCHEMA_LOGIN,
                errors={"base": "invalid_auth"}
            )
        except UnhandledProtocolError:
            _LOGGER.exception("Unhandled protocol exception during login")
            return self.async_abort(reason="protocol_error")

        _LOGGER.debug("State after login: %s", self._account.login_state)

        if self._account.login_state == LoginState.REQUIRE_2FA:
            return await self.async_step_2fa_prompt()
        return await self.async_step_done()

    async def async_step_2fa_prompt(self, info: dict | None = None) -> FlowResult:
        _LOGGER.debug("%s Step: 2fa_prompt - %s", self.__class__.__name__, info)

        if self._account is None or self._account.login_state != LoginState.REQUIRE_2FA:
            _LOGGER.error("2FA step called but account configured incorrectly")
            return self.async_abort(reason="unknown_error")

        self._2fa_methods = await self._account.get_2fa_methods()

        menu_options: dict[str, str] = {}
        for method in self._2fa_methods:
            if isinstance(method, SmsSecondFactorMethod):
                menu_options[f"2fa_request_{len(menu_options)}"] = f"SMS - {method.phone_number}"
            else:
                logging.warning("Unknown 2FA method: %s", method)
                continue

        if not menu_options:
            return self.async_show_form(
                step_id="login",
                data_schema=DATA_SCHEMA_LOGIN,
                errors={"base": "2fa_unavailable"}
            )

        return self.async_show_menu(
            step_id="2fa_request",
            menu_options=menu_options
        )

    async def async_step_2fa_request(self, info: dict | None) -> FlowResult:
        _LOGGER.debug("%s Step: 2fa_request - %s", self.__class__.__name__, info)

        if info is None:
            _LOGGER.error("2FA requested but no method ID")
            return self.async_abort(reason="unknown_error")

        try:
            method_id = info.get("method_id")
            method = self._2fa_methods[method_id]
        except KeyError:
            _LOGGER.exception("Unable to look up method ID")
            return self.async_abort(reason="unknown_error")

        await method.request()

        return await self.async_step_done()

    async def async_step_done(self, info: dict | None = None) -> FlowResult:
        _LOGGER.debug("%s Step: done - %s", self.__class__.__name__, info)

        return self.async_abort()
