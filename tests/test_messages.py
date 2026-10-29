"""The Log Notifier payloads."""

from __future__ import annotations

import importlib

from conftest import PACKAGE

messages = importlib.import_module(f"{PACKAGE}.messages")
tracker = importlib.import_module(f"{PACKAGE}.tracker")


def problem(**overrides):
    data = {
        "key": "D2:198.51.100.7",
        "rule": "D2",
        "level": "WARNING",
        "kind": "dmarc",
        "count": 4,
        "first_seen": "2026-10-26T00:00:00+00:00",
        "last_seen": "2026-10-26T23:59:59+00:00",
        "params": {"ip": "198.51.100.7", "host": "bad.example.net"},
        "reporters": ["google.com"],
    }
    data.update(overrides)
    return data


def test_opened_message():
    note = tracker.Notification("opened", problem())
    data = messages.build_message(note, "example.org", "alarm", "en")

    assert data["channel_id"] == "alarm"
    assert data["level"] == "WARNING"
    assert data["title"] == "Foreign sender uses example.org"
    assert "**4**" in data["content"]
    assert data["source"] == "dmarc-monitor"
    assert data["tags"] == ["dmarc", "D2"]
    rows = data["blocks"][0]["rows"]
    assert rows[1] == [
        {"label": "Source", "value": "198.51.100.7"},
        {"label": "Host", "value": "bad.example.net"},
    ]
    assert rows[-1][0]["format"] == "datetime"


def test_resolved_message_is_info_and_german():
    note = tracker.Notification("resolved", problem())
    data = messages.build_message(note, "example.org", "alarm", "de-DE")

    assert data["level"] == "INFO"
    assert data["title"] == "Behoben: Fremder Absender nutzt example.org"


def test_every_rule_renders_without_missing_placeholders():
    cases = [
        ("D1", {"ip": "192.0.2.10"}),
        ("D3", {"mechanism": "dkim", "selector": "s1", "result": "fail"}),
        ("D3", {"mechanism": "dkim-missing", "ip": "192.0.2.10"}),
        ("D3", {"mechanism": "spf", "result": "softfail", "spf_domain": "example.org"}),
        ("D4", {"field": "p", "found": "none", "expected": "reject"}),
        ("T1", {"result_type": "certificate-expired", "mx_host": "mx.example.org"}),
        ("T2", {}),
        ("R1", {"reporter": "google.com", "days": 3, "last_received": None}),
    ]
    for language in ("en", "de"):
        for rule, params in cases:
            note = tracker.Notification("opened", problem(rule=rule, params=params))
            data = messages.build_message(note, "example.org", "alarm", language)
            assert "{" not in data["title"] + data["content"], (rule, language)
