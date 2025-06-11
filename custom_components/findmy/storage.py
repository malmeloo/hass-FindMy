from __future__ import annotations
import io
import logging
from typing import TYPE_CHECKING, cast

from custom_components.findmy.coordinator import FindMyCoordinator, FindMyDevice
from findmy.accessory import KeyPair, FindMyAccessory
from findmy.reports import AsyncAppleAccount, RemoteAnisetteProvider

from .config_flow import EntryData
from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

type StorageItem = AsyncAppleAccount | FindMyDevice

_LOGGER = logging.getLogger(__name__)


class RuntimeStorage:
    def __init__(self, hass: HomeAssistant) -> None:
        self._entries: dict[str, StorageItem] = {}

        self._hass: HomeAssistant = hass
        self._coordinator = FindMyCoordinator(self._hass, self)

    @classmethod
    def attach(cls, hass: HomeAssistant) -> RuntimeStorage:
        if hass.data.get(DOMAIN, None) is not None:
            msg = "Already attached!"
            raise RuntimeError(msg)

        storage = cls(hass)
        hass.data[DOMAIN] = storage

        return storage

    def detach(self, hass: HomeAssistant) -> None:
        if hass.data.get(DOMAIN, None) != self:
            msg = "Not attached!"
            raise RuntimeError(msg)

        del hass.data[DOMAIN]

    @classmethod
    def get(cls, hass: HomeAssistant) -> RuntimeStorage:
        if hass.data.get(DOMAIN, None) is None:
            msg = "No storage attached!"
            raise RuntimeError(msg)

        return hass.data[DOMAIN]

    @property
    def coordinator(self) -> FindMyCoordinator:
        return self._coordinator

    @property
    def accounts(self) -> list[AsyncAppleAccount]:
        return [item for item in self._entries.values() if isinstance(item, AsyncAppleAccount)]

    @property
    def static_tags(self) -> list[AsyncAppleAccount]:
        return [item for item in self._entries.values() if isinstance(item, AsyncAppleAccount)]

    def get_entry(self, entry: ConfigEntry[EntryData]) -> StorageItem:
        return self._entries[entry.entry_id]

    async def add_entry(self, entry: ConfigEntry[EntryData]) -> StorageItem:
        data = cast(EntryData, entry.data)

        if data["type"] == "account":
            anisette = RemoteAnisetteProvider(data["anisette_url"])
            account = AsyncAppleAccount(anisette=anisette)
            account.from_json(data["account_data"])

            _LOGGER.debug("Storing entry %s as account: %s", entry.entry_id, account.account_name)

            self._entries[entry.entry_id] = account
            return account

        if data["type"] == "device_static":
            key = KeyPair.from_b64(data["private_key"])
            key.name = data["name"]

            _LOGGER.debug("Storing entry %s as static tag: %s", entry.entry_id, data["name"])

            self._entries[entry.entry_id] = key
            return key

        if data["type"] == "device_rolling":
            plist_io = io.BytesIO(bytes(data["plist"], "utf-8"))
            accessory = FindMyAccessory.from_plist(plist_io)
            accessory.name = data["name"]

            _LOGGER.debug("Storing entry %s as rolling tag: %s", entry.entry_id, data["name"])

            self._entries[entry.entry_id] = accessory
            return accessory

        msg = f"Could not match entry {data['type']} with StorageItem!"
        raise ValueError(msg)

    async def del_entry(self, entry: ConfigEntry[EntryData]) -> StorageItem:
        item = self._entries.pop(entry.entry_id)

        if isinstance(item, AsyncAppleAccount):
            await item.close()

        return item
