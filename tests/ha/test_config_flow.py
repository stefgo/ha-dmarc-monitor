"""Config flow, reauth and options."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.dmarc_monitor.const import (
    CONF_API_KEY,
    CONF_CHANNEL,
    CONF_DKIM_EXCEPTIONS,
    CONF_DOMAIN,
    CONF_EXPECTED_P,
    CONF_EXPECTED_SP,
    CONF_OWN_IPS,
    CONF_URL,
    CONF_VERIFY_SSL,
    CONF_WATCHED_REPORTERS,
    DOMAIN,
)

SERVER = {
    CONF_URL: "https://mail.example.org/",
    CONF_API_KEY: "secret-key",
    CONF_VERIFY_SSL: True,
}


def suggested(result, key):
    for field in result["data_schema"].schema:
        if field == key:
            return (field.description or {}).get("suggested_value")
    raise KeyError(key)


async def test_full_flow_suggests_values_from_the_reports(
    hass: HomeAssistant, stalwart
):
    MockConfigEntry(
        domain="lognotifier",
        options={"channels": {"alarm": {"name": "Alarm"}, "ops": {"name": "Ops"}}},
    ).add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SERVER)

    assert result["step_id"] == "domain"
    assert suggested(result, CONF_DOMAIN) == "example.org"
    assert suggested(result, CONF_OWN_IPS) == "192.0.2.10"
    assert suggested(result, CONF_CHANNEL) == "alarm"
    assert suggested(result, CONF_EXPECTED_P) == "reject"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_DOMAIN: "Example.org",
            CONF_OWN_IPS: "192.0.2.10, 2001:db8::/64",
            CONF_CHANNEL: "alarm",
            CONF_EXPECTED_P: "reject",
            CONF_EXPECTED_SP: "reject",
        },
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "example.org"
    assert result["data"][CONF_URL] == "https://mail.example.org"
    assert result["options"][CONF_OWN_IPS] == ["192.0.2.10", "2001:db8::/64"]
    assert result["options"][CONF_DKIM_EXCEPTIONS] == ["google.com *ed25519*"]


async def test_rejected_key_is_reported(hass: HomeAssistant, stalwart):
    stalwart.reject = True
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SERVER)
    assert result["errors"] == {"base": "invalid_auth"}


async def test_invalid_ips_are_refused(hass: HomeAssistant, stalwart):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SERVER)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_DOMAIN: "example.org",
            CONF_OWN_IPS: "mail.example.org",
            CONF_CHANNEL: "alarm",
            CONF_EXPECTED_P: "reject",
            CONF_EXPECTED_SP: "reject",
        },
    )
    assert result["errors"] == {CONF_OWN_IPS: "invalid_ips"}


async def test_reauth_replaces_the_key(hass: HomeAssistant, setup_entry, stalwart):
    result = await setup_entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_API_KEY: "new-key"}
    )
    await hass.async_block_till_done()
    assert result["reason"] == "reauth_successful"
    assert setup_entry.data[CONF_API_KEY] == "new-key"


async def test_options_can_clear_the_lists(hass: HomeAssistant, setup_entry):
    result = await hass.config_entries.options.async_init(setup_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            CONF_OWN_IPS: "192.0.2.10",
            CONF_CHANNEL: "alarm",
            CONF_EXPECTED_P: "reject",
            CONF_EXPECTED_SP: "reject",
            "scan_interval": 30,
            "foreign_min_count": 1,
            "missing_days": 3,
            "resolve_days": 3,
            "notify_no_tls_policy": False,
        },
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert setup_entry.options[CONF_DKIM_EXCEPTIONS] == []
    assert setup_entry.options[CONF_WATCHED_REPORTERS] == []
    assert setup_entry.runtime_data.update_interval.total_seconds() == 1800
