"""Stalwart objects → data model."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime

import pytest
from conftest import PACKAGE, fixture

parse = importlib.import_module(f"{PACKAGE}.parse")


def test_google_dmarc_report():
    report = parse.parse_dmarc_report(fixture("dmarc_google"))

    assert report.id == "d1"
    assert report.reporter == "google.com"
    assert report.begin == datetime(2026, 10, 26, tzinfo=UTC)
    assert report.policy.p == "reject"
    assert report.policy.testing is False
    (record,) = report.records
    assert record.source_ip == "192.0.2.10"
    assert record.dmarc_pass
    assert [r.result for r in record.dkim_results] == ["fail", "pass"]
    assert record.spf_results[0].scope == "mailfrom"


def test_tls_report_maps_policy_type():
    report = parse.parse_tls_report(fixture("tls_google"))

    assert report.reporter == "google inc."
    (policy,) = report.policies
    assert policy.policy_type == "nopolicyfound"
    assert (policy.successful, policy.failed) == (1, 0)


def test_tls_failure_names_follow_rfc_8460():
    obj = fixture("tls_google")
    obj["report"]["policies"][0].update(
        totalFailedSessions=3,
        failureDetails=[
            {
                "resultType": "certificateExpired",
                "failedSessionCount": 3,
                "receivingMxHostname": "mail.example.org",
            }
        ],
    )
    (failure,) = parse.parse_tls_report(obj).policies[0].failures

    assert failure.result_type == "certificate-expired"
    assert failure.mx_host == "mail.example.org"


@pytest.mark.parametrize(
    "value", ["2026-10-27T00:00:00Z", "2026-10-27T01:00:00+01:00", 1793059200]
)
def test_dates_in_any_common_form(value):
    assert parse.parse_datetime(value) == datetime(2026, 10, 27, tzinfo=UTC)


def test_a_report_without_dates_is_refused():
    obj = fixture("dmarc_google")
    del obj["report"]["dateRangeStart"]
    with pytest.raises(parse.ParseError):
        parse.parse_dmarc_report(obj)


def test_missing_optional_fields_cost_nothing():
    obj = fixture("dmarc_google")
    record = obj["report"]["records"][0]
    for key in ("dkimResults", "spfResults", "count"):
        del record[key]
    (parsed,) = parse.parse_dmarc_report(obj).records
    assert parsed.count == 0
    assert parsed.dkim_results == ()
