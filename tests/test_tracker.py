"""Opening, keeping and resolving problems across evaluations."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta

from conftest import PACKAGE

models = importlib.import_module(f"{PACKAGE}.models")
tracker_mod = importlib.import_module(f"{PACKAGE}.tracker")

DAY = timedelta(days=1)
T0 = datetime(2026, 10, 27, tzinfo=UTC)


def finding(key="D2:198.51.100.7", rule="D2", level="WARNING", kind="dmarc", seen=T0):
    return models.Finding(
        key=key,
        rule=rule,
        level=level,
        kind=kind,
        first_seen=seen - DAY,
        last_seen=seen,
        count=1,
        params={"ip": "198.51.100.7"},
        reporters={"google.com"},
    )


def tracker():
    return tracker_mod.ProblemTracker(resolve_after=3 * DAY)


def events(items):
    return [(n.event, n.problem["key"]) for n in items]


def test_a_problem_is_reported_once():
    t = tracker()
    assert events(t.update([finding()], {"dmarc": T0}, T0 + DAY)) == [
        ("opened", "D2:198.51.100.7")
    ]
    assert t.update([finding()], {"dmarc": T0}, T0 + DAY) == []
    assert t.has_problem


def test_resolved_only_with_newer_reports():
    t = tracker()
    t.update([finding()], {"dmarc": T0}, T0)
    # Four days later, but no report since: no evidence, stays open.
    assert t.update([finding()], {"dmarc": T0}, T0 + 4 * DAY) == []
    # A newer report without the problem resolves it.
    result = t.update([finding()], {"dmarc": T0 + 3 * DAY}, T0 + 4 * DAY)
    assert events(result) == [("resolved", "D2:198.51.100.7")]
    assert not t.has_problem


def test_a_recurring_problem_is_reported_again():
    t = tracker()
    t.update([finding()], {"dmarc": T0}, T0)
    t.update([], {"dmarc": T0 + 4 * DAY}, T0 + 4 * DAY)
    again = finding(seen=T0 + 6 * DAY)
    assert events(t.update([again], {"dmarc": T0 + 6 * DAY}, T0 + 6 * DAY)) == [
        ("opened", "D2:198.51.100.7")
    ]


def test_old_findings_are_not_reported_on_first_start():
    t = tracker()
    assert t.update([finding(seen=T0 - 10 * DAY)], {"dmarc": T0}, T0) == []


def test_t2_is_reported_exactly_once():
    t = tracker()
    hint = finding(key="T2", rule="T2", level="INFO", kind="tls")
    assert events(t.update([hint], {"tls": T0}, T0)) == [("opened", "T2")]
    t.update([], {"tls": T0 + 5 * DAY}, T0 + 5 * DAY)
    later = finding(key="T2", rule="T2", level="INFO", kind="tls", seen=T0 + 9 * DAY)
    assert t.update([later], {"tls": T0 + 9 * DAY}, T0 + 9 * DAY) == []
    assert not t.open_problems()


def test_r1_resolves_as_soon_as_reports_return():
    t = tracker()
    quiet = finding(key="R1:google.com", rule="R1", level="INFO", kind="status")
    t.update([quiet], {}, T0)
    assert not t.has_problem  # INFO is a hint
    assert events(t.update([], {}, T0 + DAY)) == [("resolved", "R1:google.com")]


def test_state_survives_a_restart():
    t = tracker()
    t.update([finding()], {"dmarc": T0}, T0)
    restored = tracker()
    restored.load(t.as_dict())
    assert restored.update([finding()], {"dmarc": T0}, T0) == []
    assert len(restored.outbox) == 1
