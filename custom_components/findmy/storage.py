# pyright: reportImportCycles=false

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, cast

from findmy import AsyncAppleAccount, FindMyAccessory, FixedRollingKeyPairAccessory, KeyPair

from .const import DOMAIN
from .coordinator import FindMyCoordinator, FindMyDevice

if TYPE_CHECKING:
    from datetime import datetime

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

    from .config_flow import EntryData
    from .local_bluetooth import LocalObservation

type StorageItem = AsyncAppleAccount | FindMyDevice

_LOGGER = logging.getLogger(__name__)


class RuntimeStorage:
    def __init__(self, hass: HomeAssistant) -> None:
        self._entries: dict[str, StorageItem] = {}
        # Latest local Bluetooth match per accessory unique id, with the scanner source.
        self.local_observations: dict[str, tuple[LocalObservation, str | None]] = {}
        # Latest Offline Finding status byte heard locally per accessory, with its time.
        # DULT advertisements carry no status byte and never end up here.
        self.local_status: dict[str, tuple[int, datetime]] = {}
        # Signal strength of accessories that are currently heard locally.
