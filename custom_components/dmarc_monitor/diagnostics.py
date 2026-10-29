"""Diagnostics data — everything except the API key."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_API_KEY, INTEGRATION_VERSION
from .coordinator import DmarcMonitorConfigEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: DmarcMonitorConfigEntry
) -> dict[str, Any]:
    return {
        "version": INTEGRATION_VERSION,
        "data": async_redact_data(dict(entry.data), {CONF_API_KEY}),
        "options": dict(entry.options),
        **entry.runtime_data.diagnostics(),
    }
