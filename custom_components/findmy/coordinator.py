from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

import async_timeout
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from findmy.errors import UnauthorizedError
from findmy.keys import KeyPair
from findmy.accessory import FindMyAccessory
from findmy.reports.reports import LocationReport

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from findmy.reports import AsyncAppleAccount

    from .storage import RuntimeStorage

_LOGGER = logging.getLogger(__name__)

FindMyDevice = KeyPair | FindMyAccessory
type FindMyLocationData = dict[FindMyDevice, LocationReport | None]


class FindMyCoordinator(DataUpdateCoordinator[FindMyLocationData]):
    # minimum time (in seconds) between location fetches on an account.
    _MIN_ACCOUNT_UPDATE_DELAY = 30 * 60

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

    def get_account(self) -> AsyncAppleAccount | None:
        accounts = self._storage.accounts
        if not accounts:
            return None

        account = accounts[self._cur_acc_index % len(accounts)]
        self._cur_acc_index += 1
        return account

    async def reload(self) -> None:
        """Updates coordinator intervals. Must be called after adding or removing a new account."""
        accounts = self._storage.accounts
        if not accounts:
            _LOGGER.debug("Coordinator: disabling updates due to missing account")
            self.update_interval = None
            return

        _LOGGER.debug(
            "Coordinator: Updating interval: %i",
            self._MIN_ACCOUNT_UPDATE_DELAY // len(accounts),
        )
        self.update_interval = timedelta(seconds=self._MIN_ACCOUNT_UPDATE_DELAY // len(accounts))

    async def _async_update_data(self) -> FindMyLocationData:
        account = self.get_account()
        if account is None:
            _LOGGER.debug("Skipping data update due to missing accounts")
            return {}
        _LOGGER.debug("Using lookup account: %s", account.account_name)

        devices: list[FindMyDevice] = list(self.async_contexts())
        _LOGGER.debug("Fetching reports for devices: %s", devices)
        try:
            async with async_timeout.timeout(10):
                device_locations = await account.fetch_last_reports(devices)
        except UnauthorizedError as err:
            _LOGGER.exception("Unauthorized... :c")
            raise ConfigEntryAuthFailed from err

        data: FindMyLocationData = (self.data or {}).copy()
        for device, locations in device_locations.items():
            _LOGGER.debug("Got reports for device: %s - %s", device, len(locations))
            if not isinstance(device, FindMyDevice):
                _LOGGER.warning("Device not supported yet: %s", device)
                continue

            if not locations:
                continue
            # gets most recent location
            data[device] = max(locations)

        return data
