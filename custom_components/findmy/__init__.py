"""A custom integration for Home Assistant to track your Find My-enabled devices."""

import logging
from typing import TYPE_CHECKING

from homeassistant.const import Platform

from findmy import AsyncAppleAccount

from .const import CONFIG_FLOW_VERSION_MAJOR, CONFIG_FLOW_VERSION_MINOR
from .coordinator import FindMyDevice
from .services import async_register as _async_register_services
from .storage import RuntimeStorage

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

    from .config_flow import EntryData

_LOGGER = logging.getLogger(__name__)

ACCOUNT_PLATFORMS = [
    Platform.SENSOR,
]
DEVICE_PLATFORMS = [
    Platform.DEVICE_TRACKER,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
]


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
            "Migrating entry %s from 'device_rolling' to 'device_rolling_derived'",
            config_entry.entry_id,
        )
        new_data["type"] = "device_rolling_derived"

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
    _async_register_services(hass)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry[EntryData]) -> bool:
    _LOGGER.debug("Setting up FindMy entry: %s", entry.entry_id)

    storage = RuntimeStorage.get(hass)

    item = await storage.add_entry(entry)

    if isinstance(item, AsyncAppleAccount):
        await hass.config_entries.async_forward_entry_setups(entry, ACCOUNT_PLATFORMS)
    elif isinstance(item, FindMyDevice):  # pyright: ignore[reportUnnecessaryIsInstance]
        # only initialize device tracker entities for actual devices
        await hass.config_entries.async_forward_entry_setups(entry, DEVICE_PLATFORMS)
    else:
        _LOGGER.warning(
            "Could not determine platforms to load for entry %s; no entities will be created",
            entry.entry_id,
        )

    await storage.coordinator.reload()
    # All entries share one coordinator. Delay the first refresh so multiple setup calls can
    # settle, then coalesce them into one refresh instead of a startup storm.
    storage.coordinator.schedule_refresh()

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry[EntryData]) -> bool:
    _LOGGER.debug("Unloading FindMy entry: %s", entry.entry_id)

    try:
        item = await RuntimeStorage.get(hass).del_entry(entry)
    except KeyError:
        _LOGGER.warning(
            "Entry %s not found in storage during unload",
            entry.entry_id,
        )
        return False

    if isinstance(item, AsyncAppleAccount):
        _ = await hass.config_entries.async_unload_platforms(entry, ACCOUNT_PLATFORMS)
    elif isinstance(item, FindMyDevice):  # pyright: ignore[reportUnnecessaryIsInstance]
        _ = await hass.config_entries.async_unload_platforms(entry, DEVICE_PLATFORMS)
    else:
        _LOGGER.warning(
            "Could not determine platforms to unload for entry %s",
            entry.entry_id,
        )
        return False

    return True
