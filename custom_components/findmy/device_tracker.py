from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Mapping

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from findmy.keys import KeyPair

from .const import DOMAIN
from .coordinator import FindMyCoordinator, FindMyDevice

if TYPE_CHECKING:
    from datetime import datetime

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from findmy.reports import AsyncAppleAccount
    from findmy.reports.reports import LocationReport

_LOGGER = logging.getLogger(__name__)

# <-- ADD YOUR PRIVATE KEYS HERE! -->
_KEYS = [
    "",
]
_DEVICES = [KeyPair.from_b64(key) for key in _KEYS]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    _LOGGER.debug("Setting up device tracker entry: %s", entry.entry_id)

    account: AsyncAppleAccount = hass.data[DOMAIN][entry.entry_id]
    coordinator = FindMyCoordinator(hass, account)

    async_add_entities(FindMyDeviceTracker(coordinator, dev) for dev in _DEVICES)

    await coordinator.async_config_entry_first_refresh()

    return True


class FindMyDeviceTracker(CoordinatorEntity[FindMyCoordinator], TrackerEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator: FindMyCoordinator, device: FindMyDevice) -> None:
        super().__init__(coordinator, context=device)

        self._coordinator = coordinator
        self._device: FindMyDevice = device

        self._last_location: LocationReport | None = None

    @property
    def findmy_device(self) -> FindMyDevice:
        return self._device

    @property
    def unique_id(self) -> str | None:
        return self._device.hashed_adv_key_b64

    @property
    def name(self) -> str:
        return "FindMy Tracker"

    @property
    def source_type(self) -> SourceType:
        return SourceType.GPS

    @property
    def latitude(self) -> float | None:
        if self._last_location is None:
            return None
        return self._last_location.latitude

    @property
    def longitude(self) -> float | None:
        if self._last_location is None:
            return None
        return self._last_location.longitude

    @property
    def detected_at(self) -> datetime | None:
        if self._last_location is None:
            return None
        return self._last_location.timestamp

    @property
    def published_at(self) -> datetime | None:
        if self._last_location is None:
            return None
        return self._last_location.published_at

    @property
    def description(self) -> str | None:
        if self._last_location is None:
            return None
        return self._last_location.description

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={
                (DOMAIN, self.unique_id),
            },
            name=self.name,
        )

    @property
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        return {
            "detected_at": self.detected_at,
            "published_at": self.published_at,
            "description": self.description,
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._last_location = self._coordinator.data.get(self._device)
        _LOGGER.debug("Updated data from coordinator: %s", self._last_location)

        self.async_write_ha_state()
