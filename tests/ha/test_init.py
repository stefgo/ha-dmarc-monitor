"""Setup, entities and the delivery to Log Notifier."""

from __future__ import annotations

import copy

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from custom_components.dmarc_monitor.const import DOMAIN, OBJECT_DMARC, OBJECT_TLS

from .conftest import add, load


def spoofed_report():
    report = load("dmarc_google")
    report["id"] = "d3"
    report["report"]["reportId"] = "spoof"
    add(
        report["report"]["records"],
        {
            "sourceIp": "198.51.100.7",
            "count": 4,
            "evaluatedDisposition": "reject",
            "evaluatedDkim": "fail",
            "evaluatedSpf": "fail",
            "headerFrom": "example.org",
            "envelopeFrom": "",
        },
    )
    return report


async def test_sample_reports_give_clean_entities(hass: HomeAssistant, setup_entry):
    assert setup_entry.state is ConfigEntryState.LOADED

    assert hass.states.get("binary_sensor.example_org_mail_problem").state == "off"
    assert hass.states.get("sensor.example_org_dmarc_pass_rate").state == "100.0"
    assert hass.states.get("sensor.example_org_dmarc_messages").state == "3"
    assert hass.states.get("sensor.example_org_tls_failed_sessions").state == "0"
    assert hass.states.get("sensor.example_org_api_status").state == "ok"
    last = hass.states.get("sensor.example_org_last_report")
    assert last.state == "2026-10-28T23:35:02+00:00"


async def test_only_the_tls_hint_is_posted(
    hass: HomeAssistant, setup_entry, lognotifier
):
    (call,) = lognotifier.calls
    assert call["channel_id"] == "alarm"
    assert call["level"] == "INFO"
    assert call["tags"] == ["tls-rpt", "T2"]


async def test_spoofing_is_posted_once_and_turns_the_sensor_on(
    hass: HomeAssistant, setup_entry, stalwart, lognotifier
):
    stalwart.add(OBJECT_DMARC, spoofed_report())
    coordinator = setup_entry.runtime_data
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    state = hass.states.get("binary_sensor.example_org_mail_problem")
    assert state.state == "on"
    assert state.attributes["problems"][0]["rule"] == "D2"
    warnings = [c for c in lognotifier.calls if c["level"] == "WARNING"]
    assert len(warnings) == 1
    assert "198.51.100.7" in warnings[0]["content"]

    await coordinator.async_refresh()
    assert len([c for c in lognotifier.calls if c["level"] == "WARNING"]) == 1


async def test_only_new_reports_are_fetched(hass: HomeAssistant, setup_entry, stalwart):
    stalwart.fetched.clear()
    stalwart.add(OBJECT_DMARC, spoofed_report())
    await setup_entry.runtime_data.async_refresh()
    assert stalwart.fetched == ["d3"]


async def test_unknown_channel_raises_an_issue_and_keeps_the_message(
    hass: HomeAssistant, config_entry, stalwart, lognotifier
):
    lognotifier.channels = set()
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    issue_id = f"delivery_failed_{config_entry.entry_id}"
    assert ir.async_get(hass).async_get_issue(DOMAIN, issue_id)
    assert len(config_entry.runtime_data.tracker.outbox) == 1

    lognotifier.channels = {"alarm"}
    await config_entry.runtime_data.async_refresh()
    assert len(lognotifier.calls) == 1
    assert not ir.async_get(hass).async_get_issue(DOMAIN, issue_id)


async def test_rejected_key_starts_reauth(hass: HomeAssistant, config_entry, stalwart):
    stalwart.reject = True
    assert not await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert [f["context"]["source"] for f in flows] == ["reauth"]


async def test_reports_of_other_domains_are_ignored(
    hass: HomeAssistant, config_entry, stalwart, lognotifier
):
    other = copy.deepcopy(stalwart.objects[OBJECT_TLS]["t1"])
    other["id"] = "t2"
    other["report"]["policies"]["0"]["policyDomain"] = "other.test"
    other["report"]["policies"]["0"]["totalFailedSessions"] = 9
    stalwart.add(OBJECT_TLS, other)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("sensor.example_org_tls_failed_sessions").state == "0"


async def test_refresh_service(hass: HomeAssistant, setup_entry, stalwart):
    stalwart.fetched.clear()
    stalwart.add(OBJECT_DMARC, spoofed_report())
    await hass.services.async_call(DOMAIN, "refresh", blocking=True)
    assert stalwart.fetched == ["d3"]


async def test_unload(hass: HomeAssistant, setup_entry):
    assert await hass.config_entries.async_unload(setup_entry.entry_id)
    assert setup_entry.state is ConfigEntryState.NOT_LOADED
