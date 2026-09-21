"""Presence and signal strength of rolling-key accessories heard over local Bluetooth.

The entities are added by the binary_sensor and sensor platforms.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, final, override

from homeassistant.components import bluetooth
from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import SIGNAL_STRENGTH_DECIBELS_MILLIWATT, STATE_ON, EntityCategory
from homeassistant.core import callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect, async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.restore_state import RestoreEntity

from ._entity import build_device_info, device_unique_id
from .const import (
    CONF_AWAY_TIMEOUT,
    DEFAULT_AWAY_TIMEOUT_MINUTES,
    signal_local_observation,
    signal_local_rssi,
)
from .storage import RuntimeStorage

if TYPE_CHECKING:
    from findmy import FindMyAccessory

    from .local_bluetooth import LocalObservation

_LOGGER = logging.getLogger(__name__)

# How often the Bluetooth history is checked for newer advertisements.
_REFRESH_INTERVAL = timedelta(seconds=30)
# Attribute-only updates are rate-limited so that recorder is not written every refresh.
_ATTRIBUTE_UPDATE_DELAY = timedelta(minutes=5)
# The signal strength sensor follows changes of at least this many dB right away and smaller
# ones with the attribute updates, so that the recorder is not written every refresh.
_RSSI_UPDATE_THRESHOLD = 3
_MAX_RECORDED_GAP = timedelta(hours=2)


@final
class FindMyPresenceBinarySensor(BinarySensorEntity, RestoreEntity):
    """Home while the accessory is heard by Home Assistant Bluetooth, with an away timeout.

    Home Assistant only runs advertisement callbacks when the payload changes, which for an
    accessory happens once per key rotation (15 minutes). The callback therefore only tells
    the current rolling address; how recently that address was heard is read from the
    Bluetooth history, which is updated for every advertisement.
    """

    # No entity name: like the device tracker, the sensor represents the accessory itself and is
    # listed under the accessory's name instead of a generic "Present".
    _attr_has_entity_name = True
    _attr_name = None
    _attr_device_class = BinarySensorDeviceClass.PRESENCE
    _attr_should_poll = False
    _unrecorded_attributes = frozenset(
        {"last_seen", "rssi", "source", "mac_address", "local_state", "max_gap"},
    )

    def __init__(self, device: FindMyAccessory, entry_id: str) -> None:
        self._device = device
        self._entry_id = entry_id

        self._identifier: str = device_unique_id(device)

        self._attr_unique_id = f"{self._identifier}_present"
        self._attr_device_info = build_device_info(device)
        self._attr_is_on = False

        self._mac_address: str | None = None
        # Time of the tracker observation that provided the current rolling address.
        self._observed_at: datetime | None = None
        self._last_seen: datetime | None = None
        self._rssi: int | None = None
        self._source: str | None = None
        self._local_state: str | None = None
        self._battery: str | None = None
        # Longest silence between two advertisements heard since startup, in seconds.
        self._max_gap: float = 0.0
        # False until an advertisement is heard in this run; the restored last_seen is a guess.
        self._gap_tracking = False
        self._last_write: datetime | None = None

    @property
    def _away_timeout(self) -> timedelta:
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        minutes = DEFAULT_AWAY_TIMEOUT_MINUTES
        if entry is not None:
            minutes = entry.options.get(CONF_AWAY_TIMEOUT, DEFAULT_AWAY_TIMEOUT_MINUTES)
        return timedelta(minutes=minutes)

    @override
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()

        now = datetime.now(tz=UTC)
        last_state = await self.async_get_last_state()
        if last_state is not None and last_state.state == STATE_ON:
            # Assume the accessory is still here until the away timeout passes without it.
            self._attr_is_on = True
            self._last_seen = now

        stored = RuntimeStorage.get(self.hass).local_observations.get(self._identifier)
        if stored is not None:
            self._handle_observation(*stored)

        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_local_observation(self._identifier),
                self._handle_observation,
            ),
        )
        self.async_on_remove(
            async_track_time_interval(self.hass, self._async_refresh, _REFRESH_INTERVAL),
        )

    @callback
    def _handle_observation(self, observation: LocalObservation, source: str | None) -> None:
        """Take over a new rolling address matched by the device tracker."""
        if self._observed_at is not None and observation.detected_at < self._observed_at:
            return
        self._observed_at = observation.detected_at
        self._mac_address = observation.mac_address
        self._local_state = observation.state
        if observation.battery_level is not None:
            # DULT advertisements carry no battery level; keep the last Offline Finding one.
            self._battery = observation.battery_level
        self._mark_seen(observation.detected_at, observation.rssi, source)
        self._update_state(force_write=True)

    @callback
    def _async_refresh(self, _now: datetime | None = None) -> None:
        if self._mac_address is not None:
            service_info = bluetooth.async_last_service_info(
                self.hass,
                self._mac_address,
                connectable=False,
            )
            if service_info is not None:
                age = max(0.0, bluetooth.MONOTONIC_TIME() - service_info.time)
                heard_at = datetime.now(tz=UTC) - timedelta(seconds=age)
                self._mark_seen(heard_at, service_info.rssi, service_info.source)
        self._update_state(force_write=False)

    @callback
    def _mark_seen(self, heard_at: datetime, rssi: int | None, source: str | None) -> None:
        if self._last_seen is not None:
            if heard_at <= self._last_seen:
                return
            gap = heard_at - self._last_seen
            # Gaps are recorded regardless of the away timeout so they can be used to tune it;
            # silences longer than _MAX_RECORDED_GAP are treated as the accessory having left.
            if self._gap_tracking and gap <= _MAX_RECORDED_GAP:
                self._max_gap = max(self._max_gap, gap.total_seconds())
        self._gap_tracking = True
        self._last_seen = heard_at
        self._rssi = rssi
        self._source = source

    @callback
    def _update_state(self, *, force_write: bool) -> None:
        now = datetime.now(tz=UTC)
        is_on = self._last_seen is not None and now - self._last_seen <= self._away_timeout

        state_changed = is_on != self._attr_is_on
        self._attr_is_on = is_on

        # An accessory that is away has no signal strength.
        storage = RuntimeStorage.get(self.hass)
        rssi = self._rssi if is_on else None
        if storage.local_rssi.get(self._identifier) != rssi:
            storage.local_rssi[self._identifier] = rssi
            async_dispatcher_send(self.hass, signal_local_rssi(self._identifier))

        attributes_due = (
            self._last_write is None or now - self._last_write >= _ATTRIBUTE_UPDATE_DELAY
        )
        if state_changed or force_write or attributes_due:
            self._last_write = now
            self.async_write_ha_state()

    @property
    @override
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "last_seen": self._last_seen,
            "rssi": self._rssi,
            "source": self._source,
            "mac_address": self._mac_address,
            "local_state": self._local_state,
            "battery": self._battery,
            "max_gap": round(self._max_gap),
            "away_timeout": int(self._away_timeout.total_seconds() // 60),
        }


@final
class FindMySignalStrengthSensor(SensorEntity):
    """Signal strength of the accessory's last local advertisement, fed by the presence sensor."""

    _attr_has_entity_name = True
    _attr_name = "Signal strength"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_should_poll = False

    def __init__(self, device: FindMyAccessory) -> None:
        self._identifier: str = device_unique_id(device)
        self._attr_unique_id = f"{self._identifier}_signal_strength"
        self._attr_device_info = build_device_info(device)
        self._attr_native_value = None
        self._last_write: datetime | None = None

    @override
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._attr_native_value = RuntimeStorage.get(self.hass).local_rssi.get(self._identifier)
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_local_rssi(self._identifier),
                self._handle_rssi,
            ),
        )

    @callback
    def _handle_rssi(self) -> None:
        rssi = RuntimeStorage.get(self.hass).local_rssi.get(self._identifier)
        previous = self._attr_native_value
        now = datetime.now(tz=UTC)
        due = self._last_write is None or now - self._last_write >= _ATTRIBUTE_UPDATE_DELAY
        changed = (
            rssi is None or previous is None or abs(rssi - int(previous)) >= _RSSI_UPDATE_THRESHOLD  # pyright: ignore[reportArgumentType]
        )
        if rssi == previous or not (changed or due):
            return
        self._attr_native_value = rssi
        self._last_write = now
        self.async_write_ha_state()
