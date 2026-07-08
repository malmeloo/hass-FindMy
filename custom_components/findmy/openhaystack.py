# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

"""OpenHaystack rotating-key accessory - wraps N KeyPairs as a single trackable device."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, TypedDict

from findmy import KeyPair

if TYPE_CHECKING:
    from typing import Any

    from findmy import LocationReport


class OpenHaystackAccessoryMapping(TypedDict):
    """Serialized shape for HASS config entry storage."""

    name: str
    private_keys: list[str]


class OpenHaystackAccessory:
    """A single logical tag whose firmware rotates through a fixed set of pre-generated keys.

    The findmy.py library treats each key as an independent `KeyPair`. We collect
    them under one name, ask Apple for reports on every key, and surface the
    freshest report as the tag's current position.

    JSON import formats supported:
      - `devices.json` from OpenHaystack / Macless-Haystack / this repo's
        `generate_keys.py`. Each device entry has `privateKey` (leader) plus
        `additionalKeys` (list of base64 privkeys).
    """

    def __init__(self, name: str, keypairs: list[KeyPair]) -> None:
        if not keypairs:
            msg = "OpenHaystackAccessory needs at least one KeyPair"
            raise ValueError(msg)
        self.name: str = name
        self._keypairs: list[KeyPair] = keypairs
        for kp in self._keypairs:
            kp.name = name  # so aggregated reports still surface a friendly name

    @property
    def keypairs(self) -> list[KeyPair]:
        return self._keypairs

    @property
    def identifier(self) -> str:
        """Stable unique ID = hash of the leader adv key."""
        return self._keypairs[0].hashed_adv_key_b64

    def pick_latest(self, reports: dict[KeyPair, LocationReport | None]) -> LocationReport | None:
        """Return the most-recent report across any of our keys, or None."""
        best: LocationReport | None = None
        for kp in self._keypairs:
            report = reports.get(kp)
            if report is None:
                continue
            if best is None or report.timestamp > best.timestamp:
                best = report
        return best

    def to_json(self) -> OpenHaystackAccessoryMapping:
        return {
            "name": self.name,
            "private_keys": [kp.private_key_b64 for kp in self._keypairs],
        }

    @classmethod
    def from_json(cls, data: OpenHaystackAccessoryMapping) -> OpenHaystackAccessory:
        keypairs = [KeyPair.from_b64(k) for k in data["private_keys"]]
        return cls(data.get("name", "Unknown"), keypairs)

    @classmethod
    def from_openhaystack_file(cls, file_path: str) -> list[OpenHaystackAccessory]:
        """Load one or more accessories from an OpenHaystack `devices.json`."""
        with open(file_path, encoding="utf-8") as f:
            raw: Any = json.load(f)  # noqa: ANN401
        return cls.from_openhaystack_data(raw)

    @classmethod
    def from_openhaystack_data(cls, raw: Any) -> list[OpenHaystackAccessory]:  # noqa: ANN401
        """Parse the already-decoded devices.json structure."""
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            msg = "Unexpected devices.json shape (expected list or dict)"
            raise ValueError(msg)

        result: list[OpenHaystackAccessory] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                msg = f"Entry {i} is not a dict"
                raise ValueError(msg)
            name = item.get("name") or f"Device {i + 1}"
            leader = item.get("privateKey")
            if not leader:
                msg = f"Entry {i} has no 'privateKey'"
                raise ValueError(msg)
            extras = item.get("additionalKeys") or []
            if not isinstance(extras, list):
                msg = f"Entry {i} 'additionalKeys' is not a list"
                raise ValueError(msg)

            all_keys: list[str] = [leader, *extras]
            keypairs = [KeyPair.from_b64(k) for k in all_keys]
            result.append(cls(name, keypairs))
        return result
