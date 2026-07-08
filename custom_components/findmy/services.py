"""FindMy service registrations - bulk management helpers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast

import voluptuous as vol
from homeassistant.core import ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

SERVICE_DELETE_DEVICES = "delete_devices"

DELETE_SCHEMA = vol.Schema(
    {
        vol.Optional("filter", default="all"): vol.In(
            ["all", "static", "rolling"],
        ),
    },
)


async def _async_delete_devices(call: ServiceCall) -> None:
    """Remove multiple FindMy device config entries in one go.

    Never touches account entries.  The `filter` field decides which device
    subset to remove:
      - "all" (default): every FindMy device entry
      - "openhaystack": only device_openhaystack entries
      - "static":       only device_static entries
      - "rolling":      only device_rolling entries
    """
    hass = call.hass
    filter_type = cast("str", call.data.get("filter", "all"))

    entries = hass.config_entries.async_entries(DOMAIN)
    removed: list[str] = []
    for entry in entries:
        data = entry.data or {}
        entry_type = data.get("type") if isinstance(data, dict) else None
        if not isinstance(entry_type, str) or not entry_type.startswith("device_"):
            continue

        if filter_type != "all":
            if entry_type != f"device_{filter_type}":
                continue

        _LOGGER.info("delete_devices: removing entry %s (%s)", entry.title, entry.entry_id)
        removed.append(entry.entry_id)
        await hass.config_entries.async_remove(entry.entry_id)

    _LOGGER.info(
        "delete_devices: removed %d entries (filter=%s)",
        len(removed),
        filter_type,
    )

    # Surface something visible in the service call response so the user can
    # see how many entries were affected.
    if not removed:
        raise HomeAssistantError(
            f"No matching device entries to delete (filter={filter_type})",
        )


def async_register(hass: HomeAssistant) -> None:
    """Register all services once - idempotent."""
    if hass.services.has_service(DOMAIN, SERVICE_DELETE_DEVICES):
        return

    hass.services.async_register(
        DOMAIN,
        SERVICE_DELETE_DEVICES,
        _async_delete_devices,
        schema=DELETE_SCHEMA,
    )
