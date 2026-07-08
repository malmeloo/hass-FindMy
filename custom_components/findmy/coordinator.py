# pyright: reportImportCycles=false

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, final, override

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from findmy import FindMyAccessory, KeyPair, LocationReport, UnauthorizedError

from .openhaystack import OpenHaystackAccessory

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from findmy.reports import AsyncAppleAccount

    from .storage import RuntimeStorage

_LOGGER = logging.getLogger(__name__)

FindMyDevice = KeyPair | FindMyAccessory | OpenHaystackAccessory
type FindMyLocationData = dict[FindMyDevice, LocationReport | None]


@final
class FindMyCoordinator(DataUpdateCoordinator[FindMyLocationData]):
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

    @override
    async def _async_update_data(self) -> FindMyLocationData:
        account = self.get_account()
        if account is None:
            _LOGGER.debug("Skipping data update due to missing accounts")
            return {}
        _LOGGER.debug("Using lookup account: %s", account)

        contexts: list[FindMyDevice] = list(self.async_contexts())

        # Flatten OpenHaystackAccessory wrappers into their constituent KeyPairs
        # so the FindMy library's fetch_location gets a flat list.  We remember
        # which KeyPair belongs to which wrapper so we can aggregate results.
        flat: list[KeyPair | FindMyAccessory] = []
        owner_of: dict[KeyPair, OpenHaystackAccessory] = {}
        for ctx in contexts:
            if isinstance(ctx, OpenHaystackAccessory):
                for kp in ctx.keypairs:
                    flat.append(kp)
                    owner_of[kp] = ctx
            else:
                flat.append(ctx)

        _LOGGER.debug(
            "Fetching reports for %d contexts (flattened to %d keys)",
            len(contexts), len(flat),
        )
        try:
            device_reports = await account.fetch_location(flat)
        except UnauthorizedError as err:
            _LOGGER.exception("Unauthorized... :c")
            raise ConfigEntryAuthFailed from err

        data: FindMyLocationData = (self.data or {}).copy()
        for device, report in device_reports.items():
            _LOGGER.debug("Got report for %s: %s", device, report)

            # Route the report back to an OpenHaystack wrapper if applicable
            if isinstance(device, KeyPair) and device in owner_of:
                wrapper = owner_of[device]
                existing = data.get(wrapper)
                if report and (existing is None or report.timestamp > existing.timestamp):
                    data[wrapper] = report
                continue

            if not isinstance(device, (KeyPair, FindMyAccessory)):
                _LOGGER.warning("Device not supported yet: %s", device)
                continue

            if report:
                data[device] = report

        return data
