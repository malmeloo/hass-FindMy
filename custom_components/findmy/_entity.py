"""Shared helpers for FindMy entities (device_tracker + sensor + binary_sensor).

Keeps device grouping / unique-ID logic in one place so all platforms
attach to the same HASS "device" and remain in sync when the coordinator
updates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from findmy import FindMyAccessory, KeyPair
from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN

if TYPE_CHECKING:
    from findmy import LocationReport

    from .coordinator import FindMyCoordinator, FindMyDevice


def device_unique_id(device: FindMyDevice) -> str:
    """Stable identifier used both for the device registry and for the primary
    device_tracker's unique_id. All companion entities derive from this."""
    if isinstance(device, KeyPair):
        return device.hashed_adv_key_b64

    assert isinstance(device, FindMyAccessory)
    identifier = device.identifier
    if identifier is None:
        msg = "Device has no identifier"
        raise ValueError(msg)
    return identifier


def device_name(device: FindMyDevice) -> str:
    return device.name or "Unknown"


def build_device_info(device: FindMyDevice) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, device_unique_id(device))},
        name=device_name(device),
    )


def latest_report(
    coordinator: FindMyCoordinator,
    device: FindMyDevice,
) -> LocationReport | None:
    if coordinator.data is None:
        return None
    return coordinator.data.get(device)


# --- Battery bits (Apple Find My payload byte 6, bits 6-7) ----------------
# Encoded by the OpenHaystack firmware convention:
#   0b00 = OK        (>80 %)
#   0b01 = medium    (50-80 %)
#   0b10 = low       (30-50 %)
#   0b11 = critical  (<30 %)
# Real AirTags encode the same 2-bit region with the same semantics.

BATTERY_LABELS = {
    0b00: "ok",
    0b01: "medium",
    0b10: "low",
    0b11: "critical",
}

# Rough percentage centres for each level. Not accurate; the tag only
# transmits 2 bits. Use these for the sensor value or leave the raw label.
BATTERY_PERCENTS = {
    0b00: 90,
    0b01: 65,
    0b10: 40,
    0b11: 15,
}

# CR2032 voltage curve mapped to the 4 levels. Also a rough estimate.
BATTERY_VOLTAGES_MV = {
    0b00: 3000,
    0b01: 2800,
    0b10: 2600,
    0b11: 2400,
}


def battery_bits(status: int | None) -> int | None:
    if status is None:
        return None
    return (status >> 6) & 0b11


def battery_label(status: int | None) -> str | None:
    bits = battery_bits(status)
    return BATTERY_LABELS.get(bits) if bits is not None else None


def battery_percent(status: int | None) -> int | None:
    bits = battery_bits(status)
    return BATTERY_PERCENTS.get(bits) if bits is not None else None


def battery_voltage_mv(status: int | None) -> int | None:
    bits = battery_bits(status)
    return BATTERY_VOLTAGES_MV.get(bits) if bits is not None else None


def status_counter(status: int | None) -> int | None:
    if status is None:
        return None
    return status & 0b00111111
