"""Fetches the reports of one domain now, like the service ``refresh``."""

from __future__ import annotations

from homeassistant.components.button import (
    ENTITY_ID_FORMAT,
    ButtonEntity,
    ButtonEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import DmarcMonitorConfigEntry
from .entity import DmarcMonitorEntity, apply_default_entity_ids

REFRESH = ButtonEntityDescription(
    key="refresh",
    translation_key="refresh",
    icon="mdi:refresh",
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: DmarcMonitorConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    entities = [RefreshButton(entry.runtime_data, entry, REFRESH)]
    apply_default_entity_ids(entities, ENTITY_ID_FORMAT)
    async_add_entities(entities)


class RefreshButton(DmarcMonitorEntity, ButtonEntity):
    """Stays available when the API fails — that is when it is needed."""

    @property
    def available(self) -> bool:
        return True

    async def async_press(self) -> None:
        await self.coordinator.async_refresh()
