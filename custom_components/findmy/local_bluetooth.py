"""Efficient matching of local Find My Bluetooth advertisements."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from findmy import (
    FindMyAccessory,
    KeyPairType,
    NearbyOfflineFindingDevice,
    OfflineFindingDevice,
    SeparatedOfflineFindingDevice,
)

if TYPE_CHECKING:
    from findmy import FindMyAccessoryMapping

APPLE_COMPANY_ID = 0x004C
KEY_WINDOW = timedelta(hours=12)


@dataclass(frozen=True, slots=True)
class CandidateKey:
    """A generated rolling key and its accessory index."""

    index: int
    adv_key: bytes
    can_align: bool


type CandidateKeyLookup = Mapping[bytes, tuple[CandidateKey, ...]]


@dataclass(frozen=True, slots=True)
class LocalObservation:
    """A verified local observation of a rolling-key accessory."""

    mac_address: str
    detected_at: datetime
    rssi: int | None
    state: str
    battery_level: str
    status: int
    key_index: int
    can_align: bool


def build_candidate_key_lookup(
    accessory: FindMyAccessory,
    observed_at: datetime,
) -> dict[bytes, tuple[CandidateKey, ...]]:
    """Build a lookup keyed by the six public-key bytes visible nearby."""
    candidates: defaultdict[bytes, list[CandidateKey]] = defaultdict(list)

    for index, key in accessory.keys_between(
        observed_at - KEY_WINDOW,
        observed_at + KEY_WINDOW,
    ):
        adv_key = key.adv_key_bytes
        candidates[adv_key[:6]].append(
            CandidateKey(
                index=index,
                adv_key=adv_key,
                can_align=key.key_type == KeyPairType.PRIMARY,
            ),
        )

    return {partial_key: tuple(keys) for partial_key, keys in candidates.items()}


def build_candidate_key_lookup_from_json(
    accessory_data: FindMyAccessoryMapping,
    observed_at: datetime,
) -> dict[bytes, tuple[CandidateKey, ...]]:
    """Build candidates from a snapshot to avoid mutating the live key generators."""
    return build_candidate_key_lookup(FindMyAccessory.from_json(accessory_data), observed_at)


def extract_offline_finding_payload(apple_data: bytes) -> bytes | None:
    """Extract one complete nearby or separated Offline Finding section."""
    for offset in range(max(0, len(apple_data) - 1)):
        if apple_data[offset] != OfflineFindingDevice.OF_TYPE:
            continue

        payload_length = apple_data[offset + 1]
        if payload_length not in (
            NearbyOfflineFindingDevice.OF_PAYLOAD_LEN,
            SeparatedOfflineFindingDevice.OF_PAYLOAD_LEN,
        ):
            continue

        section_end = offset + OfflineFindingDevice.OF_HEADER_SIZE + payload_length
        if section_end <= len(apple_data):
            return apple_data[offset:section_end]

    return None


def match_local_advertisement(
    address: str,
    apple_data: bytes,
    detected_at: datetime,
    rssi: int | None,
    candidates: CandidateKeyLookup,
) -> LocalObservation | None:
    """Return an observation only when an advertisement matches a candidate key."""
    payload = extract_offline_finding_payload(apple_data)
    if payload is None:
        return None

    try:
        device = OfflineFindingDevice.from_ble_payload(
            address,
            payload,
            detected_at,
            rssi,
        )
    except (IndexError, ValueError):
        return None

    if isinstance(device, NearbyOfflineFindingDevice):
        partial_key = device.partial_adv_key
        full_key = None
        state = "nearby"
    elif isinstance(device, SeparatedOfflineFindingDevice):
        partial_key = device.adv_key_bytes[:6]
        full_key = device.adv_key_bytes
        state = "separated"
    else:
        return None

    for candidate in candidates.get(partial_key, ()):
        if full_key is not None and candidate.adv_key != full_key:
            continue

        return LocalObservation(
            mac_address=device.mac_address,
            detected_at=device.detected_at,
            rssi=device.rssi,
            state=state,
            battery_level=device.battery_level,
            status=device.status,
            key_index=candidate.index,
            can_align=candidate.can_align,
        )

    return None
