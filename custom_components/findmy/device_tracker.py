from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from functools import cached_property
from time import monotonic
from typing import TYPE_CHECKING, final, override

from homeassistant.components import bluetooth
from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.components.device_tracker.const import SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import generate_entity_id
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from findmy import FindMyAccessory, KeyPair

from .config_flow import DeviceEntryData
from .const import DOMAIN
from .coordinator import FindMyCoordinator, FindMyDevice
from .local_bluetooth import (
    APPLE_COMPANY_ID,
    CandidateKeyLookup,
    LocalObservation,
    build_candidate_key_lookup_from_json,
    match_local_advertisement,
)
from .storage import RuntimeStorage

if TYPE_CHECKING:
    from collections.abc import Mapping

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from findmy import LocationReport

    from .config_flow import DeviceEntryData

_LOGGER = logging.getLogger(__name__)

_LOCAL_KEY_REFRESH_INTERVAL = timedelta(minutes=15)
_LOCAL_STATE_UPDATE_DELAY = 60
_LOCAL_ALIGNMENT_UPDATE_DELAY = 60
_LOCAL_ALIGNMENT_SAVE_DELAY = 15 * 60


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
    async_add_entities((FindMyDeviceTracker(storage.coordinator, item, entry.entry_id),))

    return True


@final
class FindMyDeviceTracker(  # pyright: ignore [reportUninitializedInstanceVariable, reportIncompatibleVariableOverride]
    CoordinatorEntity[FindMyCoordinator],
    TrackerEntity,
):
    _attr_has_entity_name = True
    _attr_name = None

    _attr_should_poll = False

    def __init__(self, coordinator: FindMyCoordinator, device: FindMyDevice, entry_id: str) -> None:
        super().__init__(coordinator, context=device)

        self._coordinator: FindMyCoordinator = coordinator
        self._device: FindMyDevice = device
        self._entry_id: str = entry_id

        self._last_location: LocationReport | None = None
        self._local_observation: LocalObservation | None = None
        self._local_source: str | None = None
        self._local_candidates: CandidateKeyLookup = {}
        self._local_candidate_count = 0
        self._local_refresh_lock = asyncio.Lock()
        self._local_refresh_tasks: set[asyncio.Task[None]] = set()
        self._local_active = False
        self._last_local_state_update = 0.0
        self._last_alignment_update = 0.0
        self._last_alignment_save = 0.0

        # Define entity id
        # Set here instead of in a property because it needs a setter, so this is more convenient.
        self.entity_id = generate_entity_id(
            "device_tracker.findmy_{}",
            self.given_name,
            hass=self._coordinator.hass,
        )

    @override
    async def async_added_to_hass(self) -> None:
        """Start local Bluetooth matching for rolling-key accessories."""
        await super().async_added_to_hass()

        if not isinstance(self._device, FindMyAccessory):
            return

        self._local_active = True
        # Nearby/separated advertisements and Bluetooth proxies do not always
        # classify the AirTag's connectability consistently, so listen for both.
        for connectable in (False, True):
            self.async_on_remove(
                bluetooth.async_register_callback(
                    self.hass,
                    self._async_track_service_info,
                    bluetooth.BluetoothCallbackMatcher(
                        connectable=connectable,
                        manufacturer_id=APPLE_COMPANY_ID,
                    ),
                    bluetooth.BluetoothScanningMode.PASSIVE,
                ),
            )
        self.async_on_remove(
            async_track_time_interval(
                self.hass,
                self._async_refresh_local_candidates,
                _LOCAL_KEY_REFRESH_INTERVAL,
            ),
        )
        self.async_on_remove(self._cancel_local_refresh_tasks)

        self._schedule_local_candidate_refresh("initial")

    @override
    async def async_will_remove_from_hass(self) -> None:
        """Stop publishing results while background work is winding down."""
        self._local_active = False
        await super().async_will_remove_from_hass()

    @callback
    def _cancel_local_refresh_tasks(self) -> None:
        """Cancel outstanding candidate generation tasks."""
        for task in self._local_refresh_tasks:
            _ = task.cancel()
        self._local_refresh_tasks.clear()

    @callback
    def _schedule_local_candidate_refresh(self, reason: str) -> None:
        """Schedule candidate generation and retain the task until completion."""
        task = self.hass.async_create_task(
            self._async_refresh_local_candidates(),
            f"findmy local key cache ({reason}): {self.unique_id}",
        )
        self._local_refresh_tasks.add(task)
        task.add_done_callback(self._local_refresh_tasks.discard)

    async def _async_refresh_local_candidates(self, _now: datetime | None = None) -> None:
        """Generate rolling-key candidates outside Home Assistant's event loop."""
        if not isinstance(self._device, FindMyAccessory):
            return

        async with self._local_refresh_lock:
            observed_at = datetime.now(tz=UTC)
            accessory_data = self._device.to_json()
            candidates = await self.hass.async_add_executor_job(
                build_candidate_key_lookup_from_json,
                accessory_data,
                observed_at,
            )

            if not self._local_active:
                return

            self._local_candidates = candidates
            self._local_candidate_count = sum(len(keys) for keys in candidates.values())
            _LOGGER.debug(
                "Prepared %i local rolling-key candidates for %s",
                self._local_candidate_count,
                self.given_name,
            )
            self.async_write_ha_state()

    @callback
    def _async_track_service_info(
        self,
        service_info: bluetooth.BluetoothServiceInfoBleak,
        _change: bluetooth.BluetoothChange,
    ) -> None:
        """Match an Apple advertisement against the pre-generated key cache."""
        if not isinstance(self._device, FindMyAccessory):
            return

        apple_data = service_info.manufacturer_data.get(APPLE_COMPANY_ID)
        if apple_data is None or not self._local_candidates:
            return

        observation = match_local_advertisement(
            service_info.address,
            apple_data,
            datetime.now(tz=UTC),
            service_info.rssi,
            self._local_candidates,
        )
        if observation is None:
            return

        previous = self._local_observation
        self._local_observation = observation
        self._local_source = service_info.source

        now_mono = monotonic()
        current_index = self._device._alignment_index  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        index_changed = observation.can_align and observation.key_index != current_index
        if observation.can_align and (
            index_changed or now_mono - self._last_alignment_update >= _LOCAL_ALIGNMENT_UPDATE_DELAY
        ):
            self._device.update_alignment(observation.detected_at, observation.key_index)
            self._last_alignment_update = now_mono

        if observation.can_align and (
            index_changed or now_mono - self._last_alignment_save >= _LOCAL_ALIGNMENT_SAVE_DELAY
        ):
            self._update_entry()
            self._last_alignment_save = now_mono

        identity_changed = (
            previous is None
            or previous.mac_address != observation.mac_address
            or previous.state != observation.state
        )
        if (
            identity_changed
            or now_mono - self._last_local_state_update >= _LOCAL_STATE_UPDATE_DELAY
        ):
            self._last_local_state_update = now_mono
            self.async_write_ha_state()

        if index_changed:
            self._schedule_local_candidate_refresh("realignment")

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

    @property
    @override
    def latitude(self) -> float | None:  # pyright: ignore[reportIncompatibleVariableOverride]
        if self._last_location is None:
            return None
        return self._last_location.latitude

    @property
    @override
    def longitude(self) -> float | None:  # pyright: ignore[reportIncompatibleVariableOverride]
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

    @property
    def mac_address(self) -> str | None:
        if isinstance(self._device, KeyPair):
            return self._device.mac_address
        if self._local_observation is not None:
            return self._local_observation.mac_address
        return None

    @cached_property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={
                (DOMAIN, self.unique_id),
            },
            name=self.given_name,
        )

    @property
    @override
    def extra_state_attributes(  # pyright: ignore[reportIncompatibleVariableOverride]
        self,
    ) -> Mapping[str, int | str | datetime | None] | None:
        attrs = {
            "detected_at": self.detected_at,
            "status": self.status,
            "mac_address": self.mac_address,
        }

        if isinstance(self._device, FindMyAccessory):
            # TODO(malmeloo): make properties public in FindMy.py  # noqa: FIX002, TD003
            attrs["alignment_index"] = self._device._alignment_index  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            attrs["alignment_date"] = self._device._alignment_date  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            attrs["local_key_candidates"] = self._local_candidate_count
            attrs["local_detected_at"] = (
                self._local_observation.detected_at if self._local_observation is not None else None
            )
            attrs["local_rssi"] = (
                self._local_observation.rssi if self._local_observation is not None else None
            )
            attrs["local_source"] = self._local_source
            attrs["local_state"] = (
                self._local_observation.state if self._local_observation is not None else None
            )
            attrs["local_battery"] = (
                self._local_observation.battery_level
                if self._local_observation is not None
                else None
            )

        return attrs

    def _update_entry(self) -> None:
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if entry is None:
            _LOGGER.error("Config entry for device tracker disappeared")
            return

        if isinstance(self._device, KeyPair):
            data: DeviceEntryData = {
                "type": "device_static",
                "data": self._device.to_json(),
            }
        elif isinstance(self._device, FindMyAccessory):  # pyright: ignore[reportUnnecessaryIsInstance]
            data = {
                "type": "device_rolling",
                "data": self._device.to_json(),
            }
        else:
            _LOGGER.error("Unknown device type for entry update: %s", type(self._device))
            return

        _ = self.hass.config_entries.async_update_entry(entry, data=data)

    @callback
    @override
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._last_location = (self._coordinator.data or {}).get(self._device)
        _LOGGER.debug("Updated data from coordinator: %s", self._last_location)

        self.async_write_ha_state()

        self._update_entry()
