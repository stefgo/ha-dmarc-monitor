"""DMARC Monitor: watches the DMARC and TLS reports Stalwart received."""

from __future__ import annotations

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_API_KEY,
    CONF_URL,
    CONF_VERIFY_SSL,
    DOMAIN,
    ISSUE_DELIVERY_FAILED,
)
from .coordinator import DmarcMonitorConfigEntry, DmarcMonitorCoordinator
from .services import async_setup_services
from .stalwart import StalwartClient

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.BUTTON, Platform.SENSOR]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


def build_client(hass: HomeAssistant, data: dict) -> StalwartClient:
    """A client from entry data — also used by the config flow."""
    return StalwartClient(
        async_get_clientsession(hass, verify_ssl=data.get(CONF_VERIFY_SSL, True)),
        data[CONF_URL],
        data[CONF_API_KEY],
    )


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the services once per Home Assistant run."""
    async_setup_services(hass)
    return True


async def async_setup_entry(
    hass: HomeAssistant, entry: DmarcMonitorConfigEntry
) -> bool:
    """Set up one monitored domain."""
    coordinator = DmarcMonitorCoordinator(
        hass, entry, build_client(hass, dict(entry.data))
    )
    await coordinator.async_load()
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: DmarcMonitorConfigEntry
) -> bool:
    """Unload the platforms."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(
    hass: HomeAssistant, entry: DmarcMonitorConfigEntry
) -> None:
    """Drop the delivery issue of a removed domain."""
    ir.async_delete_issue(hass, DOMAIN, f"{ISSUE_DELIVERY_FAILED}_{entry.entry_id}")


async def _async_update_listener(
    hass: HomeAssistant, entry: DmarcMonitorConfigEntry
) -> None:
    """Options feed the rules and the interval — rebuild with them."""
    await hass.config_entries.async_reload(entry.entry_id)
