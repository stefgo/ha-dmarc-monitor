"""On while a problem of level WARNING or ERROR is open."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    ENTITY_ID_FORMAT,
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import DmarcMonitorConfigEntry
from .entity import DmarcMonitorEntity, apply_default_entity_ids
from .messages import problem_title

MAIL_PROBLEM = BinarySensorEntityDescription(
    key="mail_problem",
    translation_key="mail_problem",
    device_class=BinarySensorDeviceClass.PROBLEM,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: DmarcMonitorConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    entities = [MailProblemSensor(entry.runtime_data, entry, MAIL_PROBLEM)]
    apply_default_entity_ids(entities, ENTITY_ID_FORMAT)
    async_add_entities(entities)


class MailProblemSensor(DmarcMonitorEntity, BinarySensorEntity):
    @property
    def is_on(self) -> bool:
        return self.coordinator.data.has_problem

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        domain = self.coordinator.rules.domain
        language = self.hass.config.language
        return {
            "problems": [
                {
                    "rule": p.rule,
                    "level": p.level,
                    "title": problem_title(p.as_dict(), domain, language),
                    "since": p.opened_at.isoformat(),
                    "last_seen": p.last_seen.isoformat(),
                    "count": p.count,
                    "reporters": p.reporters,
                }
                for p in self.coordinator.data.open_problems
            ]
        }
