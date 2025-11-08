"""A custom integration for Home Assistant to track your Find My-enabled devices."""

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .config_flow import EntryData
from .coordinator import FindMyDevice
from .storage import RuntimeStorage

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.DEVICE_TRACKER]


async def async_setup(hass: HomeAssistant, _config: ConfigEntry) -> bool:
    _ = RuntimeStorage.attach(hass)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry[EntryData]) -> bool:
    _LOGGER.debug("Setting up FindMy entry: %s", entry.entry_id)

    storage = RuntimeStorage.get(hass)

    item = await storage.add_entry(entry)
    if isinstance(item, FindMyDevice):
        # only initialize device tracker entities for actual devices
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    await storage.coordinator.reload()
    await storage.coordinator.async_refresh()

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry[EntryData]) -> bool:
    _LOGGER.debug("Unloading FindMy entry: %s", entry.entry_id)

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    _ = await RuntimeStorage.get(hass).del_entry(entry)

    return True
