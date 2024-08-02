"""A custom integration for Home Assistant to track your Find My-enabled devices."""

import logging
from typing import cast

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from findmy.reports import AsyncAppleAccount, RemoteAnisetteProvider

from .config_flow import EntryData
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.DEVICE_TRACKER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry[EntryData]) -> bool:
    _LOGGER.debug("Setting up FindMy entry: %s", entry.entry_id)

    data = cast(EntryData, entry.data)
    anisette = RemoteAnisetteProvider(data["anisette_url"])
    account = AsyncAppleAccount(anisette)
    account.restore(data["account_data"])

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = account

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry[EntryData]) -> bool:
    _LOGGER.debug("Unloading FindMy entry: %s", entry.entry_id)

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        account: AsyncAppleAccount = hass.data[DOMAIN].pop(entry.entry_id)
        await account.close()

    return unload_ok
