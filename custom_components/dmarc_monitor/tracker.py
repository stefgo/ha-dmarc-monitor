"""Problem tracker: turns repeated evaluations into opened and resolved events.

The rules look at all stored reports on every cycle and find the same problem
again and again. The tracker remembers what was already reported, so Log
Notifier gets one message when a problem appears and one when it is gone —
across restarts, because its state is persisted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .const import PROBLEM_LEVELS, RULE_REPORTS_MISSING, RULE_TLS_NO_POLICY
from .models import Finding
from .parse import parse_datetime

STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"
# Reported once and then never again (T2: a hint, not a problem).
STATUS_SILENCED = "silenced"

EVENT_OPENED = "opened"
EVENT_RESOLVED = "resolved"

# Resolved problems are kept a while so that diagnostics can show them; after
# that the key may come back as a new problem anyway.
KEEP_RESOLVED = timedelta(days=60)
# Undelivered messages pile up while Log Notifier is missing; the oldest go.
MAX_OUTBOX = 100

ONCE_RULES = frozenset({RULE_TLS_NO_POLICY})
# Rules whose finding describes the present, not a report period: they are
# active exactly as long as the evaluation yields them.
CURRENT_RULES = frozenset({RULE_REPORTS_MISSING})


@dataclass(slots=True)
class Problem:
    key: str
    rule: str
    level: str
    kind: str
    status: str
    first_seen: datetime
    last_seen: datetime
    opened_at: datetime
    count: int = 0
    params: dict[str, Any] = field(default_factory=dict)
    reporters: list[str] = field(default_factory=list)
    resolved_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "rule": self.rule,
            "level": self.level,
            "kind": self.kind,
            "status": self.status,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "opened_at": self.opened_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "count": self.count,
            "params": dict(self.params),
            "reporters": list(self.reporters),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Problem | None:
        first = parse_datetime(data.get("first_seen"))
        last = parse_datetime(data.get("last_seen"))
        opened = parse_datetime(data.get("opened_at"))
        if not (first and last and opened and data.get("key")):
            return None
        return cls(
            key=str(data["key"]),
            rule=str(data.get("rule", "")),
            level=str(data.get("level", "")),
            kind=str(data.get("kind", "")),
            status=str(data.get("status", STATUS_OPEN)),
            first_seen=first,
            last_seen=last,
            opened_at=opened,
            resolved_at=parse_datetime(data.get("resolved_at")),
            count=int(data.get("count", 0)),
            params=dict(data.get("params") or {}),
            reporters=[str(r) for r in data.get("reporters") or []],
        )


@dataclass(slots=True)
class Notification:
    """One message for Log Notifier: a problem appeared or went away."""

    event: str
    problem: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"event": self.event, "problem": self.problem}


class ProblemTracker:
    """Open, update and resolve problems from successive evaluations."""

    def __init__(self, resolve_after: timedelta) -> None:
        self.resolve_after = resolve_after
        self.problems: dict[str, Problem] = {}
        self.outbox: list[Notification] = []

    # --- Persistence ----------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        return {
            "problems": [p.as_dict() for p in self.problems.values()],
            "outbox": [n.as_dict() for n in self.outbox],
        }

    def load(self, data: dict[str, Any] | None) -> None:
        if not data:
            return
        for raw in data.get("problems") or []:
            if isinstance(raw, dict) and (problem := Problem.from_dict(raw)):
                self.problems[problem.key] = problem
        self.outbox = [
            Notification(str(raw["event"]), dict(raw["problem"]))
            for raw in data.get("outbox") or []
            if isinstance(raw, dict) and "event" in raw and "problem" in raw
        ]

    # --- Evaluation -----------------------------------------------------------

    def _active(self, finding: Finding, now: datetime) -> bool:
        if finding.rule in CURRENT_RULES:
            return True
        return finding.last_seen >= now - self.resolve_after

    def update(
        self,
        findings: Iterable[Finding],
        latest_end: dict[str, datetime],
        now: datetime,
    ) -> list[Notification]:
        """Apply one evaluation; returns the new notifications.

        A finding is active while it occurred within ``resolve_after``. An open
        problem is resolved once it is no longer active *and* a newer report of
        the same kind exists — without new reports there is no evidence that
        the problem went away, only that nobody reported anything.
        """
        events: list[Notification] = []
        active_keys: set[str] = set()
        for finding in findings:
            if not self._active(finding, now):
                continue
            active_keys.add(finding.key)
            problem = self.problems.get(finding.key)
            if problem is not None and problem.status in (STATUS_OPEN, STATUS_SILENCED):
                problem.last_seen = max(problem.last_seen, finding.last_seen)
                problem.count = finding.count
                problem.params = {**problem.params, **finding.params}
                problem.reporters = sorted(set(problem.reporters) | finding.reporters)
                continue
            problem = Problem(
                key=finding.key,
                rule=finding.rule,
                level=finding.level,
                kind=finding.kind,
                status=STATUS_SILENCED if finding.rule in ONCE_RULES else STATUS_OPEN,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                opened_at=now,
                count=finding.count,
                params=dict(finding.params),
                reporters=sorted(finding.reporters),
            )
            self.problems[finding.key] = problem
            events.append(Notification(EVENT_OPENED, problem.as_dict()))

        for problem in self.problems.values():
            if problem.status != STATUS_OPEN or problem.key in active_keys:
                continue
            if problem.rule not in CURRENT_RULES:
                newest = latest_end.get(problem.kind)
                if newest is None or newest <= problem.last_seen:
                    continue
            problem.status = STATUS_RESOLVED
            problem.resolved_at = now
            events.append(Notification(EVENT_RESOLVED, problem.as_dict()))

        self.problems = {
            key: p
            for key, p in self.problems.items()
            if p.status != STATUS_RESOLVED
            or (p.resolved_at is not None and now - p.resolved_at < KEEP_RESOLVED)
        }
        self.outbox.extend(events)
        del self.outbox[:-MAX_OUTBOX]
        return events

    # --- Views ----------------------------------------------------------------

    def open_problems(self) -> list[Problem]:
        """Open problems, most severe first."""
        order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        return sorted(
            (p for p in self.problems.values() if p.status == STATUS_OPEN),
            key=lambda p: (order.get(p.level, 9), p.key),
        )

    @property
    def has_problem(self) -> bool:
        return any(p.level in PROBLEM_LEVELS for p in self.open_problems())
