"""Statistics of the last seven days and the state of the API."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    ENTITY_ID_FORMAT,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import (
    API_AUTH_FAILED,
    API_CANNOT_CONNECT,
    API_OK,
    DmarcMonitorConfigEntry,
    MonitorData,
)
from .entity import DmarcMonitorEntity, apply_default_entity_ids


@dataclass(frozen=True, kw_only=True)
class DmarcSensorDescription(SensorEntityDescription):
    value_fn: Callable[[MonitorData], float | int | datetime | None]
    attrs_fn: Callable[[MonitorData], dict[str, Any]] | None = None


SENSORS: tuple[DmarcSensorDescription, ...] = (
    DmarcSensorDescription(
        key="dmarc_pass_rate",
        translation_key="dmarc_pass_rate",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda d: d.stats.pass_rate,
        attrs_fn=lambda d: {"passed": d.stats.passed, "failed": d.stats.failed},
    ),
    DmarcSensorDescription(
        key="dmarc_messages",
        translation_key="dmarc_messages",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.stats.messages,
        attrs_fn=lambda d: {
            "passed": d.stats.passed,
            "failed": d.stats.failed,
            "reports": d.stats.dmarc_reports,
            "by_reporter": {
                name: asdict(values) for name, values in d.stats.by_reporter.items()
            },
        },
    ),
    DmarcSensorDescription(
        key="tls_failed_sessions",
        translation_key="tls_failed_sessions",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.stats.tls_failed,
        attrs_fn=lambda d: {
            "successful": d.stats.tls_successful,
            "reports": d.stats.tls_reports,
        },
    ),
    DmarcSensorDescription(
        key="last_report",
        translation_key="last_report",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda d: d.stats.last_report_at,
        attrs_fn=lambda d: {
            "reporter": d.stats.last_report_from,
            "kind": d.stats.last_report_kind,
        },
    ),
)

API_STATUS = SensorEntityDescription(
    key="api_status",
    translation_key="api_status",
    device_class=SensorDeviceClass.ENUM,
    options=[API_OK, API_AUTH_FAILED, API_CANNOT_CONNECT],
    entity_category=EntityCategory.DIAGNOSTIC,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: DmarcMonitorConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[DmarcMonitorEntity] = [
        DmarcSensor(coordinator, entry, description) for description in SENSORS
    ]
    entities.append(ApiStatusSensor(coordinator, entry, API_STATUS))
    apply_default_entity_ids(entities, ENTITY_ID_FORMAT)
    async_add_entities(entities)


class DmarcSensor(DmarcMonitorEntity, SensorEntity):
    entity_description: DmarcSensorDescription

    @property
    def native_value(self) -> float | int | datetime | None:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator.data)


class ApiStatusSensor(DmarcMonitorEntity, SensorEntity):
    """Stays available when the API fails — that is what it reports."""

    @property
    def available(self) -> bool:
        return True

    @property
    def native_value(self) -> str:
        return self.coordinator.api_status

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"detail": self.coordinator.api_detail}
