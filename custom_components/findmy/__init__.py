"""A custom integration for Home Assistant to track your Find My-enabled devices."""

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .config_flow import EntryData
from .const import CONFIG_FLOW_VERSION_MAJOR, CONFIG_FLOW_VERSION_MINOR
from .coordinator import FindMyDevice
from .storage import RuntimeStorage

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.DEVICE_TRACKER]


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate old config entry to the current format."""
    if config_entry.version >= CONFIG_FLOW_VERSION_MAJOR:
        return True

    _LOGGER.info(
        "Migrating configuration from version %s.%s to version %s.%s",
        config_entry.version,
        config_entry.minor_version,
        CONFIG_FLOW_VERSION_MAJOR,
        CONFIG_FLOW_VERSION_MINOR,
    )

    if config_entry.version == 1 and config_entry.data.get("type") == "device_rolling":
        new_data = {**config_entry.data}
        _LOGGER.info(
            "Migrating entry %s from 'device_rolling' to 'device_rolling_pre_generated'",
            config_entry.entry_id,
        )
        new_data["type"] = "device_rolling_pre_generated"

        _ = hass.config_entries.async_update_entry(
            config_entry,
            data=new_data,
            version=CONFIG_FLOW_VERSION_MAJOR,
            minor_version=CONFIG_FLOW_VERSION_MINOR,
        )

    _LOGGER.info(
        "Migration to configuration version %s.%s successful",
        config_entry.version,
        config_entry.minor_version,
    )

    return True


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
