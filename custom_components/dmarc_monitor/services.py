"""Service: fetch the reports now instead of at the next interval."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, callback

from .const import DOMAIN

SERVICE_REFRESH = "refresh"


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    async def async_refresh(call: ServiceCall) -> None:
        for entry in hass.config_entries.async_entries(DOMAIN):
            if entry.state is ConfigEntryState.LOADED:
                await entry.runtime_data.async_refresh()

    hass.services.async_register(DOMAIN, SERVICE_REFRESH, async_refresh)
