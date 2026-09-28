"""FindMy sensor platform: lat/lon (recorded to HASS history) + battery
level / percent / voltage sensors derived from the Apple Find My status
byte the tag advertises."""

from __future__ import annotations

import logging
from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, override

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import generate_entity_id

from findmy import AsyncAppleAccount, FindMyAccessory

from ._entity import (
    account_entity_id,
    account_name,
    account_unique_id,
    battery_label,
    battery_percent,
    battery_voltage_mv,
    build_device_info,
    device_unique_id,
    latest_report,
    latest_status,
    status_counter,
)
from .const import DOMAIN, signal_account_fetch, signal_local_observation
from .coordinator import CoordinatorFetchStatus, FindMyCoordinator, FindMyDevice
from .presence import FindMySignalStrengthSensor
from .storage import RuntimeStorage

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    _LOGGER.debug("Setting up sensor entry: %s", entry.entry_id)

    storage = RuntimeStorage.get(hass)
    item = storage.get_entry(entry)

    entities: list[SensorEntity] = []

    if isinstance(item, FindMyDevice):
        entities.extend(
            (
                FindMyLatitudeSensor(storage.coordinator, item, entry.entry_id),
                FindMyLongitudeSensor(storage.coordinator, item, entry.entry_id),
                FindMyPositionSensor(storage.coordinator, item, entry.entry_id),
                FindMyBatteryLevelSensor(storage.coordinator, item, entry.entry_id),
                FindMyBatteryPercentSensor(storage.coordinator, item, entry.entry_id),
                FindMyBatteryVoltageSensor(storage.coordinator, item, entry.entry_id),
                FindMyStatusCounterSensor(storage.coordinator, item, entry.entry_id),
            )
        )

    if isinstance(item, FindMyAccessory):
        # Only accessories with derived rolling keys are matched against local advertisements.
        entities.extend((FindMySignalStrengthSensor(item),))

    if isinstance(item, AsyncAppleAccount):
        # account status sensors
        entities.extend(
            (
                FindMyAccountStateSensor(storage.coordinator, item, entry.entry_id),
                FindMyAccountLastFetchSensor(storage.coordinator, item, entry.entry_id),
                FindMyAccountLastFetchResultSensor(storage.coordinator, item, entry.entry_id),
                FindMyAccountLastFetchDurationSensor(storage.coordinator, item, entry.entry_id),
                FindMyAccountNextFetchSensor(storage.coordinator, item, entry.entry_id),
            )
        )

    async_add_entities(entities)

    return True


####################
#  Device Sensors  #
####################


class _FindMyDeviceBaseSensor[T](
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
        value = self._compute_value()
        if value != self._cached_value:
            self._cached_value = value
            self.async_write_ha_state()

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

    @property
    @override
    def native_value(self) -> T | None:  # pyright: ignore[reportIncompatibleVariableOverride]
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyLatitudeSensor(_FindMyDeviceBaseSensor[float]):
    _attr_name: str | None = "Latitude"
    _attr_native_unit_of_measurement: str | None = "°"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision: int | None = 6
    _suffix: str = "latitude"

    @override
    def _compute_value(self) -> float | None:
        report = latest_report(self._coordinator, self._device)
        return report.latitude if report else None


class FindMyLongitudeSensor(_FindMyDeviceBaseSensor[float]):
    _attr_name: str | None = "Longitude"
    _attr_native_unit_of_measurement: str | None = "°"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision: int | None = 6
    _suffix: str = "longitude"

    @override
    def _compute_value(self) -> float | None:
        report = latest_report(self._coordinator, self._device)
        return report.longitude if report else None


class FindMyPositionSensor(_FindMyDeviceBaseSensor[str]):
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


class FindMyBatteryLevelSensor(_FindMyDeviceBaseSensor[str]):
    _attr_name: str | None = "Battery level"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.ENUM
    _attr_options: list[str] | None = ["ok", "medium", "low", "critical"]  # noqa: RUF012
    _suffix: str = "battery_level"

    @override
    def _compute_value(self) -> str | None:
        return battery_label(latest_status(self.hass, self._coordinator, self._device))


class FindMyBatteryPercentSensor(_FindMyDeviceBaseSensor[int]):
    _attr_name: str | None = "Battery"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement: str | None = "%"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _suffix: str = "battery_percent"

    @override
    def _compute_value(self) -> int | None:
        return battery_percent(latest_status(self.hass, self._coordinator, self._device))


class FindMyBatteryVoltageSensor(_FindMyDeviceBaseSensor[int]):
    _attr_name: str | None = "Battery voltage"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.VOLTAGE
    _attr_native_unit_of_measurement: str | None = "mV"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default: bool = False  # estimate only, opt-in
    _suffix: str = "battery_voltage"

    @override
    def _compute_value(self) -> int | None:
        return battery_voltage_mv(latest_status(self.hass, self._coordinator, self._device))


class FindMyStatusCounterSensor(_FindMyDeviceBaseSensor[int]):
    _attr_name: str | None = "Status counter"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default: bool = False  # diagnostic, opt-in
    _suffix: str = "status_counter"

    @override
    def _compute_value(self) -> int | None:
        return status_counter(latest_status(self.hass, self._coordinator, self._device))


#####################
#  Account Sensors  #
#####################


class _FindMyAccountBaseSensor[T](
    SensorEntity,
):
    _attr_has_entity_name: bool = False
    _attr_should_poll: bool = False
    _attr_available: bool = True
    _suffix: str = ""

    def __init__(
        self,
        coordinator: FindMyCoordinator,
        account: AsyncAppleAccount,
        entry_id: str,
    ) -> None:
        self._coordinator: FindMyCoordinator = coordinator
        self._account: AsyncAppleAccount = account
        self._entry_id: str = entry_id

        self._cached_value: T | None = None
        # Use generate_entity_id to properly slugify and validate the entity_id
        self.entity_id: str = generate_entity_id(
            "sensor.apple_account_{}",
            f"{account_entity_id(self._account)}_{self._suffix}",
            hass=coordinator.hass,
        )

    @override
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()

        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_account_fetch(account_name(self._account)),
                self._handle_fetch_update,
            )
        )

    async def async_update(self) -> None:
        await self._coordinator.async_request_refresh()

    @cached_property
    @override
    def unique_id(self) -> str:
        return f"apple_account_{account_unique_id(self._account)}_{self._suffix}"

    @cached_property
    @override
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, account_entity_id(self._account))},
            name=account_name(self._account),
        )

    @callback
    def _handle_fetch_update(self, *_args: object) -> None:
        value = self._compute_value()
        if value != self._cached_value:
            self._cached_value = value
            self.async_write_ha_state()

    def _compute_value(self) -> T | None:
        return None

    @property
    @override
    def native_value(self) -> T | None:  # pyright: ignore[reportIncompatibleVariableOverride]
        val = self._cached_value
        if val is None:
            val = self._compute_value()
        return val


class FindMyAccountStateSensor(_FindMyAccountBaseSensor[str]):
    _attr_name: str | None = "State"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.ENUM
    _suffix: str = "state"

    @override
    def _compute_value(self) -> str | None:
        state = self._coordinator.get_account_last_fetch_result(self._account)

        if state == CoordinatorFetchStatus.ONGOING:
            return "fetching"

        return "idle"


class FindMyAccountLastFetchSensor(_FindMyAccountBaseSensor[datetime]):
    _attr_name: str | None = "Last fetch"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.TIMESTAMP
    _suffix: str = "last_fetch"

    @override
    def _compute_value(self) -> datetime | None:
        return self._coordinator.get_account_last_fetch(self._account)


class FindMyAccountNextFetchSensor(_FindMyAccountBaseSensor[datetime]):
    _attr_name: str | None = "Next fetch"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.TIMESTAMP
    _suffix: str = "next_fetch"

    @override
    def _compute_value(self) -> datetime | None:
        return self._coordinator.get_account_next_fetch(self._account)


class FindMyAccountLastFetchResultSensor(_FindMyAccountBaseSensor[str]):
    _attr_name: str | None = "Last fetch result"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.ENUM
    _suffix: str = "last_fetch_result"

    @override
    def _compute_value(self) -> str | None:
        res = self._coordinator.get_account_last_fetch_result(self._account)
        if res == CoordinatorFetchStatus.ONGOING:
            return "ongoing"
        if res == CoordinatorFetchStatus.SUCCESS:
            return "success"
        if res == CoordinatorFetchStatus.ERROR:
            return "error"

        return None


class FindMyAccountLastFetchDurationSensor(_FindMyAccountBaseSensor[float]):
    _attr_name: str | None = "Last fetch duration"
    _attr_device_class: SensorDeviceClass | None = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement: str | None = "s"
    _attr_state_class: SensorStateClass | None = SensorStateClass.MEASUREMENT
    _suffix: str = "last_fetch_duration"

    @override
    def _compute_value(self) -> float | None:
        dur = self._coordinator.get_account_last_fetch_duration(self._account)
        if dur is None:
            return None

        return dur.total_seconds()
