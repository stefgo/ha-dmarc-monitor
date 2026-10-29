"""Common base of the entities: one device per monitored domain."""

from __future__ import annotations

from collections.abc import Iterable

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from .const import CONF_DOMAIN, CONF_URL, DOMAIN, INTEGRATION_VERSION
from .coordinator import DmarcMonitorConfigEntry, DmarcMonitorCoordinator


class DmarcMonitorEntity(CoordinatorEntity[DmarcMonitorCoordinator]):
    """Binds an entity to the device of its domain.

    The object ID is derived from the domain, not left to Home Assistant: HA
    would build it from the translated entity name in the system language, so
    the same entity would get a different ID on a German instance.
    """

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DmarcMonitorCoordinator,
        entry: DmarcMonitorConfigEntry,
        description: EntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        domain = entry.data[CONF_DOMAIN]
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self.default_object_id = f"{slugify(domain)}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=domain,
            manufacturer="DMARC Monitor",
            model="Mail domain",
            sw_version=INTEGRATION_VERSION,
            entry_type=DeviceEntryType.SERVICE,
            configuration_url=entry.data.get(CONF_URL),
        )


def apply_default_entity_ids(
    entities: Iterable[DmarcMonitorEntity], entity_id_format: str
) -> None:
    """Pre-set entity IDs; the registry keeps IDs it already knows."""
    for entity in entities:
        entity.entity_id = entity_id_format.format(entity.default_object_id)
