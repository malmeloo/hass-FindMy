# pyright: reportImportCycles=false

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, final, override

from homeassistant.config_entries import SOURCE_REAUTH
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from findmy import (
    FindMyAccessory,
    FixedRollingKeyPairAccessory,
    InvalidStateError,
    KeyPair,
    LocationReport,
    LoginState,
    UnauthorizedError,
)

from ._entity import account_name
from .const import signal_account_fetch

if TYPE_CHECKING:
    from asyncio import TimerHandle

    from homeassistant.core import HomeAssistant

    from findmy.reports import AsyncAppleAccount

    from .storage import RuntimeStorage

_LOGGER = logging.getLogger(__name__)

FindMyDevice = KeyPair | FindMyAccessory | FixedRollingKeyPairAccessory
type FindMyLocationData = dict[FindMyDevice, LocationReport | None]


class CoordinatorFetchStatus(Enum):
    """The result of a fetch attempt."""

    SUCCESS = "success"
    ERROR = "error"
    ONGOING = "ongoing"


class CoordinatorLogEvent(Enum):
    """Events that can be logged by the coordinator."""

    FETCH_START = "fetch_start"
    FETCH_ERROR = "fetch_error"
    FETCH_SUCCESS = "fetch_success"


@dataclass(frozen=True)
class CoordinatorLogEntry:
    """A log entry for a coordinator update."""

    timestamp: datetime
    account: AsyncAppleAccount
    event: CoordinatorLogEvent


@final
class FindMyCoordinator(DataUpdateCoordinator[FindMyLocationData | None]):
    # minimum time (in seconds) between location fetches on an account.
    _MIN_ACCOUNT_UPDATE_DELAY = 15 * 60

    def __init__(self, hass: HomeAssistant, storage: RuntimeStorage) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="Location Reports",
            update_interval=None,
            always_update=False,
        )

        self._storage = storage

        self._cur_acc_index = 0
        self._logs: list[CoordinatorLogEntry] = []
        self._refresh_handle: TimerHandle | None = None

    def _start_reauth(self, account: AsyncAppleAccount) -> None:
        """Prompt for re-authentication of the config entry that owns ``account``.

        All entries share this coordinator, so it is not bound to a config entry
        and Home Assistant cannot map ``ConfigEntryAuthFailed`` to one by itself.
        """
        entry_id = self._storage.entry_id_for(account)
        entry = self.hass.config_entries.async_get_entry(entry_id) if entry_id else None
        if entry is None:
            _LOGGER.error(
                "Cannot map account %s to a config entry; no re-auth prompt shown",
                account_name(account),
            )
            return

        if any(entry.async_get_active_flows(self.hass, {SOURCE_REAUTH})):
            return

        _LOGGER.warning(
            "Account %s needs re-authentication; requesting it for entry %s",
            account_name(account),
            entry.entry_id,
        )
        entry.async_start_reauth(self.hass)

    def schedule_refresh(self, delay_seconds: float = 10.0) -> None:
        """Schedule a refresh after a quiet period."""
        if self._refresh_handle is not None:
            self._refresh_handle.cancel()

        def _request_refresh() -> None:
            self._refresh_handle = None
            _ = self.hass.async_create_task(
                self.async_request_refresh(),
                name="findmy delayed startup refresh",
            )

        self._refresh_handle = self.hass.loop.call_later(delay_seconds, _request_refresh)

    def get_account(self) -> AsyncAppleAccount | None:
        """Return the next account to fetch with.

        Accounts that are no longer logged in are skipped: they keep their entry
        loaded until the re-auth flow reloads it, and fetching with them would
        only fail again.
        """
        accounts = self._storage.accounts
        for _ in range(len(accounts)):
            account = accounts[self._cur_acc_index % len(accounts)]
            self._cur_acc_index += 1

            if account.login_state == LoginState.LOGGED_IN:
                return account

            _LOGGER.debug(
                "Skipping account %s (state: %s)",
                account_name(account),
                account.login_state,
            )
            self._start_reauth(account)

        return None

    async def reload(self) -> None:
        """Updates coordinator intervals. Must be called after adding or removing a new account."""
        accounts = self._storage.accounts
        if not accounts:
            _LOGGER.debug("Coordinator: disabling updates due to missing account")
            self.update_interval = None
            return

        cur_interval = self.update_interval.total_seconds() if self.update_interval else None
        interval = self._MIN_ACCOUNT_UPDATE_DELAY // len(accounts)
        if cur_interval == interval:
            return

        _LOGGER.debug(
            "Coordinator: Updating interval: %i",
            self._MIN_ACCOUNT_UPDATE_DELAY // len(accounts),
        )
        self.update_interval = timedelta(seconds=self._MIN_ACCOUNT_UPDATE_DELAY // len(accounts))

    def get_account_last_fetch(self, account: AsyncAppleAccount) -> datetime | None:
        """Returns the last time a fetch was attempted for the given account."""
        for log in reversed(self._logs):
            if log.account != account:
                continue

            if log.event in (
                CoordinatorLogEvent.FETCH_SUCCESS,
                CoordinatorLogEvent.FETCH_ERROR,
            ):
                return log.timestamp
        return None

    def get_account_next_fetch(self, account: AsyncAppleAccount) -> datetime | None:
        """Returns the next time a fetch will be attempted for the given account."""
        last_fetch = self.get_account_last_fetch(account)
        if last_fetch is None:
            return None
        return last_fetch + timedelta(
            seconds=self._MIN_ACCOUNT_UPDATE_DELAY * len(self._storage.accounts)
        )

    def get_account_last_fetch_result(
        self, account: AsyncAppleAccount
    ) -> CoordinatorFetchStatus | None:
        """Returns the result of the last fetch for the given account."""
        for log in reversed(self._logs):
            if log.account != account:
                continue

            match log.event:
                case CoordinatorLogEvent.FETCH_START:
                    return CoordinatorFetchStatus.ONGOING
                case CoordinatorLogEvent.FETCH_SUCCESS:
                    return CoordinatorFetchStatus.SUCCESS
                case CoordinatorLogEvent.FETCH_ERROR:
                    return CoordinatorFetchStatus.ERROR

        return None

    def get_account_last_fetch_duration(self, account: AsyncAppleAccount) -> timedelta | None:
        """Returns the duration of the last fetch for the given account."""
        end_time: datetime | None = None
        for log in reversed(self._logs):
            if log.account != account:
                continue

            match log.event:
                case CoordinatorLogEvent.FETCH_SUCCESS | CoordinatorLogEvent.FETCH_ERROR:
                    end_time = log.timestamp
                case CoordinatorLogEvent.FETCH_START:
                    if end_time is not None:
                        return end_time - log.timestamp

                    # still ongoing
                    return None

        return None

    @property
    def devices(self) -> list[FindMyDevice]:
        """Returns a list of all devices that have been registered with the coordinator."""
        return list({ctx for ctx in self.async_contexts() if isinstance(ctx, FindMyDevice)})  # pyright: ignore[reportAny]

    def _log(self, account: AsyncAppleAccount, event: CoordinatorLogEvent) -> None:
        self._logs.append(
            CoordinatorLogEntry(timestamp=datetime.now(tz=UTC), account=account, event=event)
        )
        async_dispatcher_send(self.hass, signal_account_fetch(account_name(account)))

    @override
    async def _async_update_data(self) -> FindMyLocationData:
        if not self._storage.accounts:
            _LOGGER.debug("Skipping data update due to missing accounts")
            return {}

        account = self.get_account()
        if account is None:
            msg = "All accounts require re-authentication"
            raise UpdateFailed(msg)
        _LOGGER.debug("Using lookup account: %s", account)

        self._log(account, CoordinatorLogEvent.FETCH_START)

        devices: list[FindMyDevice] = self.devices
        _LOGGER.debug("Fetching reports for devices: %s", devices)
        success = False
        try:
            success = True

            device_reports = await account.fetch_location(devices)
        except UnauthorizedError as err:
            success = False

            _LOGGER.exception("Unauthorized... :c")

            self._start_reauth(account)

            msg = "Account requires re-authentication"
            raise UpdateFailed(msg) from err
        except InvalidStateError as err:
            success = False

            # Apple invalidates sessions periodically; the account then sits in
            # REQUIRE_2FA and every fetch raises InvalidStateError. Prompt for
            # re-auth on the owning entry. UpdateFailed (not ConfigEntryAuthFailed)
            # keeps the shared coordinator scheduled for the remaining accounts.
            _LOGGER.warning(
                "Account is no longer logged in (state: %s); re-authentication required",
                getattr(account, "login_state", "unknown"),
            )

            self._start_reauth(account)

            msg = "Account requires re-authentication"
            raise UpdateFailed(msg) from err
        finally:
            self._log(
                account,
                (CoordinatorLogEvent.FETCH_SUCCESS if success else CoordinatorLogEvent.FETCH_ERROR),
            )

        data: FindMyLocationData = (self.data or {}).copy()
        for device, report in device_reports.items():
            _LOGGER.debug("Got reports for device: %s - %s", device, report)
            if not isinstance(device, FindMyDevice):
                _LOGGER.warning("Device not supported yet: %s", device)
                continue

            if report:
                data[device] = report

        return data
