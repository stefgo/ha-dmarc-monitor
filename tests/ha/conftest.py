"""Fixtures for the tests that need a real Home Assistant.

Stalwart is replaced by ``FakeStalwart``, which serves the recorded objects in
``tests/fixtures``; Log Notifier by a recording ``lognotifier.send`` service.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ServiceValidationError
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.dmarc_monitor.const import (
    CONF_API_KEY,
    CONF_CHANNEL,
    CONF_DOMAIN,
    CONF_OWN_IPS,
    CONF_URL,
    CONF_VERIFY_SSL,
    DOMAIN,
    OBJECT_DMARC,
    OBJECT_TLS,
)
from custom_components.dmarc_monitor.stalwart import StalwartAuthError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NOW = "2026-10-29T01:00:00+00:00"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def add(entries: dict[str, Any], item: Any) -> None:
    """Append to a list the way Stalwart sends it: an object keyed by index."""
    entries[str(len(entries))] = item


class FakeStalwart:
    """Stands in for StalwartClient; the objects can be changed per test."""

    def __init__(self) -> None:
        self.objects: dict[str, dict[str, dict[str, Any]]] = {
            OBJECT_DMARC: {
                o["id"]: o for o in (load("dmarc_google"), load("dmarc_mimecast"))
            },
            OBJECT_TLS: {o["id"]: o for o in (load("tls_google"),)},
        }
        self.reject = False
        self.fetched: list[str] = []

    def __call__(self, *_args: Any, **_kwargs: Any) -> FakeStalwart:
        return self

    def add(self, object_type: str, obj: dict[str, Any]) -> None:
        self.objects[object_type][obj["id"]] = obj

    async def query_ids(self, object_type: str) -> list[str]:
        if self.reject:
            raise StalwartAuthError("API key rejected (401)")
        return list(self.objects[object_type])

    async def get(self, object_type: str, ids: list[str]) -> list[dict[str, Any]]:
        self.fetched.extend(ids)
        return [copy.deepcopy(self.objects[object_type][i]) for i in ids]

    async def async_validate(self, _types: Any) -> None:
        if self.reject:
            raise StalwartAuthError("API key rejected (401)")


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    return enable_custom_integrations


@pytest.fixture(autouse=True)
def frozen_time(freezer):
    freezer.move_to(NOW)
    return freezer


@pytest.fixture(autouse=True)
def no_dns():
    """No real lookups: reverse DNS and the server's own address."""
    with (
        patch(
            "custom_components.dmarc_monitor.coordinator.socket.gethostbyaddr",
            side_effect=OSError,
        ),
        patch(
            "custom_components.dmarc_monitor.config_flow.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("192.0.2.10", 0))],
        ),
    ):
        yield


@pytest.fixture
def stalwart() -> FakeStalwart:
    fake = FakeStalwart()
    with patch("custom_components.dmarc_monitor.StalwartClient", fake):
        yield fake


class LogNotifier:
    """A recording lognotifier.send service."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.channels = {"alarm"}

    async def handle(self, call: ServiceCall) -> None:
        if call.data["channel_id"] not in self.channels:
            raise ServiceValidationError(f"Unknown channel: {call.data['channel_id']}")
        self.calls.append(dict(call.data))


@pytest.fixture
def lognotifier(hass: HomeAssistant) -> LogNotifier:
    service = LogNotifier()
    hass.services.async_register("lognotifier", "send", service.handle)
    return service


@pytest.fixture
def config_entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="example.org",
        unique_id="example.org",
        data={
            CONF_URL: "https://mail.example.org",
            CONF_API_KEY: "secret-key",
            CONF_VERIFY_SSL: True,
            CONF_DOMAIN: "example.org",
        },
        options={CONF_OWN_IPS: ["192.0.2.10"], CONF_CHANNEL: "alarm"},
    )
    entry.add_to_hass(hass)
    return entry


@pytest.fixture
async def setup_entry(hass, config_entry, stalwart, lognotifier) -> MockConfigEntry:
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    return config_entry
