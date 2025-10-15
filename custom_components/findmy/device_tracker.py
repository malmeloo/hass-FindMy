from __future__ import annotations

import logging
from functools import cached_property
from typing import TYPE_CHECKING, final, override

from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.components.device_tracker.const import SourceType
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import generate_entity_id
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from findmy import FindMyAccessory, KeyPair

from .const import DOMAIN
from .coordinator import FindMyCoordinator, FindMyDevice
from .storage import RuntimeStorage

if TYPE_CHECKING:
    from collections.abc import Mapping
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


@final
class FindMyDeviceTracker(  # pyright: ignore [reportUninitializedInstanceVariable, reportIncompatibleVariableOverride]
    CoordinatorEntity[FindMyCoordinator],
    TrackerEntity,
):
    _attr_has_entity_name = True
    _attr_name = None

    _attr_should_poll = False

    def __init__(self, coordinator: FindMyCoordinator, device: FindMyDevice) -> None:
        super().__init__(coordinator, context=device)

        self._coordinator = coordinator
        self._device: FindMyDevice = device

        self._last_location: LocationReport | None = None

        # Define entity id
        # Set here instead of in a property because it needs a setter, so this is more convenient.
        self.entity_id = generate_entity_id(
            "device_tracker.findmy_{}",
            self.given_name,
            hass=self._coordinator.hass,
        )

    @property
    def findmy_device(self) -> FindMyDevice:
        return self._device

    @property
    def given_name(self) -> str:
        return self._device.name or "Unknown"

    @property
    @override
    def unique_id(self) -> str:  # pyright: ignore [reportIncompatibleVariableOverride]
        if isinstance(self._device, KeyPair):
            return self._device.hashed_adv_key_b64

        assert isinstance(self._device, FindMyAccessory)

        identifier = self._device.identifier
        if identifier is None:
            msg = "Device has no identifier"
            raise ValueError(msg)
        return identifier

    @property
    @override
    def source_type(self) -> SourceType:
        return SourceType.GPS

    @cached_property
    @override
    def latitude(self) -> float | None:
        if self._last_location is None:
            return None
        return self._last_location.latitude

    @cached_property
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
    def status(self) -> int | None:
        if self._last_location is None:
            return None
        return self._last_location.status

    @cached_property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={
                (DOMAIN, self.unique_id),
            },
            name=self.given_name,
        )

    @cached_property
    def extra_state_attributes(
        self,
    ) -> Mapping[str, int | datetime | None] | None:
        return {
            "detected_at": self.detected_at,
            "status": self.status,
        }

    @callback
    @override
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._last_location = (self._coordinator.data or {}).get(self._device)
        _LOGGER.debug("Updated data from coordinator: %s", self._last_location)

        self.async_write_ha_state()
