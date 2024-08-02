from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

import async_timeout
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from findmy.errors import UnauthorizedError
from findmy.keys import KeyPair
from findmy.reports.reports import LocationReport

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from findmy.reports import AsyncAppleAccount

_LOGGER = logging.getLogger(__name__)

type FindMyDevice = KeyPair
type FindMyLocationData = dict[FindMyDevice, LocationReport | None]


class FindMyCoordinator(DataUpdateCoordinator[FindMyLocationData]):
    def __init__(self, hass: HomeAssistant, account: AsyncAppleAccount) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"Location Reports ({account.account_name})",
            update_interval=timedelta(minutes=15),
            always_update=False,
        )

        self._account: AsyncAppleAccount = account

    async def _async_update_data(self) -> FindMyLocationData:
        data: FindMyLocationData = {}

        try:
            async with async_timeout.timeout(10):
                listening_devs: list[FindMyDevice] = list(self.async_contexts())
                device_locations = await self._account.fetch_last_reports(listening_devs)
        except UnauthorizedError as err:
            _LOGGER.exception("Unauthorized... :c")
            raise ConfigEntryAuthFailed from err

        for device, locations in device_locations.items():
            if not isinstance(device, KeyPair):
                _LOGGER.warning("Device type not supported yet: %s", type(device))
                continue

            if not locations:
                data[device] = None
                continue
            # gets most recent location
            data[device] = max(locations)

        return data
