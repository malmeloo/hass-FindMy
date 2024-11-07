from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Mapping

from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.components.device_tracker.const import SourceType
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import RuntimeStorage
from .const import DOMAIN
from .coordinator import FindMyCoordinator, FindMyDevice

if TYPE_CHECKING:
    from datetime import datetime

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from findmy.reports.reports import LocationReport

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    _LOGGER.debug("Setting up device tracker entry: %s", entry.entry_id)

    item = RuntimeStorage.get(hass).get_entry(entry)
    if not isinstance(item, FindMyDevice):
        msg = "Cannot setup device tracker entity for non-device!"
        raise ConfigEntryNotReady(msg)

    storage = RuntimeStorage.get(hass)
    async_add_entities((FindMyDeviceTracker(storage.coordinator, item),))

    return True


class FindMyDeviceTracker(  # pyright: ignore [reportIncompatibleVariableOverride]
    CoordinatorEntity[FindMyCoordinator],
    TrackerEntity,
):
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
    def unique_id(self) -> str:  # pyright: ignore [reportIncompatibleVariableOverride]
        return self._device.hashed_adv_key_b64

    @property
    def name(self) -> str:  # pyright: ignore [reportIncompatibleVariableOverride]
        return self._device.name or "Unknown"

    @property
    def source_type(self) -> SourceType:
        return SourceType.GPS

    @property
    def latitude(self) -> float | None:  # pyright: ignore [reportIncompatibleVariableOverride]
        if self._last_location is None:
            return None
        return self._last_location.latitude

    @property
    def longitude(self) -> float | None:  # pyright: ignore [reportIncompatibleVariableOverride]
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
    def status(self) -> int | None:
        if self._last_location is None:
            return None
        return self._last_location.status

    @property
    def description(self) -> str | None:
        if self._last_location is None:
            return None
        return self._last_location.description

    @property
    def device_info(self) -> DeviceInfo:  # pyright: ignore [reportIncompatibleVariableOverride]
        return DeviceInfo(
            identifiers={
                (DOMAIN, self.unique_id),
            },
            name=self.name,
        )

    @property
    def extra_state_attributes(  # pyright: ignore [reportIncompatibleVariableOverride]
        self,
    ) -> Mapping[str, Any] | None:
        return {
            "detected_at": self.detected_at,
            "published_at": self.published_at,
            "description": self.description,
            "status": self.status,
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._last_location = (self._coordinator.data or {}).get(self._device)
        _LOGGER.debug("Updated data from coordinator: %s", self._last_location)

        self.async_write_ha_state()
