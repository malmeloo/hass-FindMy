"""FindMy binary_sensor platform: battery-low flag and local presence."""

from __future__ import annotations

import logging
from functools import cached_property
from typing import TYPE_CHECKING, override

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from findmy import FindMyAccessory

from ._entity import battery_bits, build_device_info, device_unique_id, latest_status
from .const import signal_local_observation
from .coordinator import FindMyCoordinator, FindMyDevice
from .presence import FindMyPresenceBinarySensor
from .storage import RuntimeStorage

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.device_registry import DeviceInfo
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    _LOGGER.debug("Setting up binary_sensor entry: %s", entry.entry_id)

    item = RuntimeStorage.get(hass).get_entry(entry)
    if not isinstance(item, FindMyDevice):
        msg = "Cannot setup binary_sensor entities for non-device!"
        raise ConfigEntryNotReady(msg)

    storage = RuntimeStorage.get(hass)
    entities: list[BinarySensorEntity] = [
        FindMyBatteryLowBinarySensor(storage.coordinator, item, entry.entry_id),
    ]
    if isinstance(item, FindMyAccessory):
        # Only accessories with derived rolling keys are matched against local advertisements.
        entities.append(FindMyPresenceBinarySensor(item, entry.entry_id))
    async_add_entities(entities)

    return True


class FindMyBatteryLowBinarySensor(
    BinarySensorEntity,
):
    _attr_has_entity_name: bool = True
    _attr_should_poll: bool = False
    _attr_name: str | None = "Battery low"
    _attr_device_class: BinarySensorDeviceClass | None = BinarySensorDeviceClass.BATTERY

    def __init__(
        self,
        coordinator: FindMyCoordinator,
        device: FindMyDevice,
        entry_id: str,
    ) -> None:
        super().__init__()
        self._coordinator: FindMyCoordinator = coordinator
        self._device: FindMyDevice = device
        self._entry_id: str = entry_id
        self._cached: bool | None = None
        self._attr_available: bool = coordinator.last_update_success

    @override
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            self._coordinator.async_add_listener(
                self._handle_coordinator_update,
                self._device,
            )
        )
        # The status byte also arrives in local advertisements, without any location report.
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_local_observation(device_unique_id(self._device)),
                self._handle_local_observation,
            ),
        )

    @callback
    def _handle_local_observation(self, *_args: object) -> None:
        value = self._compute()
        if value != self._cached:
            self._cached = value
            self.async_write_ha_state()

    async def async_update(self) -> None:
        await self._coordinator.async_request_refresh()

    @cached_property
    @override
    def unique_id(self) -> str:
        return f"{device_unique_id(self._device)}_battery_low"

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        return build_device_info(self._device)

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_available = self._coordinator.last_update_success
        self._cached = self._compute()
        self.async_write_ha_state()

    def _compute(self) -> bool | None:
        bits = battery_bits(latest_status(self.hass, self._coordinator, self._device))
        if bits is None:
            return None
        # low = 0b10, critical = 0b11 => bit 1 set
        return bits >= 0b10  # noqa: PLR2004

    @property
    @override
    def is_on(self) -> bool | None:  # pyright: ignore[reportIncompatibleVariableOverride]
        val = self._cached
        if val is None:
            val = self._compute()
        return val
