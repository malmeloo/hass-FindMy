"""FindMy sensor platform: lat/lon (recorded to HASS history) + battery
level / percent / voltage sensors derived from the Apple Find My status
byte the tag advertises."""

from __future__ import annotations

import logging
from functools import cached_property
from typing import TYPE_CHECKING, override

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryNotReady

from ._entity import (
    battery_label,
    battery_percent,
    battery_voltage_mv,
    build_device_info,
    device_unique_id,
    latest_report,
    status_counter,
)
from .coordinator import FindMyCoordinator, FindMyDevice
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
    _LOGGER.debug("Setting up sensor entry: %s", entry.entry_id)

    item = RuntimeStorage.get(hass).get_entry(entry)
    if not isinstance(item, FindMyDevice):
        msg = "Cannot setup sensor entities for non-device!"
        raise ConfigEntryNotReady(msg)

    storage = RuntimeStorage.get(hass)
    async_add_entities(
        (
            FindMyLatitudeSensor(storage.coordinator, item, entry.entry_id),
            FindMyLongitudeSensor(storage.coordinator, item, entry.entry_id),
            FindMyPositionSensor(storage.coordinator, item, entry.entry_id),
            FindMyBatteryLevelSensor(storage.coordinator, item, entry.entry_id),
            FindMyBatteryPercentSensor(storage.coordinator, item, entry.entry_id),
            FindMyBatteryVoltageSensor(storage.coordinator, item, entry.entry_id),
            FindMyStatusCounterSensor(storage.coordinator, item, entry.entry_id),
        ),
    )

    return True


class _FindMyBaseSensor[T](
    SensorEntity,
):
    _attr_has_entity_name: bool = True
    _attr_should_poll: bool = False
    _suffix: str = ""

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
        self._cached_value: T | None = None
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

    async def async_update(self) -> None:
        await self._coordinator.async_request_refresh()

    @cached_property
    @override
    def unique_id(self) -> str:
        return f"{device_unique_id(self._device)}_{self._suffix}"

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        return build_device_info(self._device)

    @cached_property
    @override
    def available(self) -> bool:
        return self._attr_available

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_available = self._coordinator.last_update_success
        self._cached_value = self._compute_value()
        self.async_write_ha_state()

    def _compute_value(self) -> T | None:
        return None


class FindMyLatitudeSensor(_FindMyBaseSensor[float]):
    _attr_name: str | None = "Latitude"
    _attr_native_unit_of_measurement: str | None = "°"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision: int | None = 6
    _suffix: str = "latitude"

    @override
    def _compute_value(self) -> float | None:
        report = latest_report(self._coordinator, self._device)
        return report.latitude if report else None

    @cached_property
    @override
    def native_value(self) -> float | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyLongitudeSensor(_FindMyBaseSensor[float]):
    _attr_name: str | None = "Longitude"
    _attr_native_unit_of_measurement: str | None = "°"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision: int | None = 6
    _suffix: str = "longitude"

    @override
    def _compute_value(self) -> float | None:
        report = latest_report(self._coordinator, self._device)
        return report.longitude if report else None

    @cached_property
    @override
    def native_value(self) -> float | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyPositionSensor(_FindMyBaseSensor[str]):
    """Convenience sensor combining lat + lon in a single 'lat,lon' string.
    Not graphable, but handy for template concatenation, notifications and
    passing to external map tools."""

    _attr_name: str | None = "Position"
    _suffix: str = "position"

    @override
    def _compute_value(self) -> str | None:
        report = latest_report(self._coordinator, self._device)
        if report is None:
            return None
        return f"{report.latitude:.6f},{report.longitude:.6f}"

    @cached_property
    @override
    def native_value(self) -> str | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyBatteryLevelSensor(_FindMyBaseSensor[str]):
    _attr_name: str | None = "Battery level"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.ENUM
    _attr_options: list[str] | None = ["ok", "medium", "low", "critical"]  # noqa: RUF012
    _suffix: str = "battery_level"

    @override
    def _compute_value(self) -> str | None:
        report = latest_report(self._coordinator, self._device)
        return battery_label(report.status if report else None)

    @cached_property
    @override
    def native_value(self) -> str | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyBatteryPercentSensor(_FindMyBaseSensor[int]):
    _attr_name: str | None = "Battery"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement: str | None = "%"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _suffix: str = "battery_percent"

    @override
    def _compute_value(self) -> int | None:
        report = latest_report(self._coordinator, self._device)
        return battery_percent(report.status if report else None)

    @cached_property
    @override
    def native_value(self) -> int | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyBatteryVoltageSensor(_FindMyBaseSensor[int]):
    _attr_name: str | None = "Battery voltage"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.VOLTAGE
    _attr_native_unit_of_measurement: str | None = "mV"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default: bool = False  # estimate only, opt-in
    _suffix: str = "battery_voltage"

    @override
    def _compute_value(self) -> int | None:
        report = latest_report(self._coordinator, self._device)
        return battery_voltage_mv(report.status if report else None)

    @cached_property
    @override
    def native_value(self) -> int | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyStatusCounterSensor(_FindMyBaseSensor[int]):
    _attr_name: str | None = "Status counter"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default: bool = False  # diagnostic, opt-in
    _suffix: str = "status_counter"

    @override
    def _compute_value(self) -> int | None:
        report = latest_report(self._coordinator, self._device)
        return status_counter(report.status if report else None)

    @cached_property
    @override
    def native_value(self) -> int | None:
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val
