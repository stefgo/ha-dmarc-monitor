"""Diagnostics never carry the API key."""

from __future__ import annotations

import json

from homeassistant.core import HomeAssistant

from custom_components.dmarc_monitor.diagnostics import (
    async_get_config_entry_diagnostics,
)


async def test_diagnostics_redact_the_key(hass: HomeAssistant, setup_entry):
    data = await async_get_config_entry_diagnostics(hass, setup_entry)
    assert "secret-key" not in json.dumps(data, default=str)
    assert data["reports"]["dmarc"] == 2
    assert data["api_status"] == "ok"
