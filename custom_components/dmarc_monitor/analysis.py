"""The rules: from stored reports to findings and statistics.

``evaluate`` is a pure function of the reports, the configuration and the
current time. It knows nothing about what was reported before — that is the
tracker's job — so the same input always yields the same findings.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Any

from .const import (
    DEFAULT_DKIM_EXCEPTIONS,
    DEFAULT_FOREIGN_MIN_COUNT,
    DEFAULT_MISSING_DAYS,
    DEFAULT_POLICY,
    DEFAULT_WATCHED_REPORTERS,
    LEVEL_ERROR,
    LEVEL_INFO,
    LEVEL_WARNING,
    RULE_FOREIGN_DMARC_FAIL,
    RULE_OWN_DMARC_FAIL,
    RULE_OWN_PARTIAL_FAIL,
    RULE_POLICY_MISMATCH,
    RULE_REPORTS_MISSING,
    RULE_TLS_FAILURE,
    RULE_TLS_NO_POLICY,
    STATS_DAYS,
)
from .models import (
    DmarcRecord,
    DmarcReport,
    Finding,
    TlsReport,
    email_domain,
    in_domain,
)

KIND_DMARC = "dmarc"
KIND_TLS = "tls"
# R1 is about the absence of reports, not about their content.
KIND_STATUS = "status"

# A source sent mail on behalf of the domain through a forwarder or a list —
# the reporter says so itself. DMARC fails there because the forwarder changed
# the message, not because someone forges the domain.
FORWARDING_OVERRIDES = frozenset(
    {"forwarded", "trustedforwarder", "mailinglist", "localpolicy"}
)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class DkimException:
    """A DKIM signature a reporter is known not to verify.

    Both parts are shell patterns: ``google.com *ed25519*``.
    """

    reporter: str
    selector: str

    def matches(self, report: DmarcReport, selector: str) -> bool:
        return reporter_matches(self.reporter, report.reporter, report.email) and (
            fnmatchcase(selector.lower(), self.selector.lower())
        )


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Everything the rules need to know about the monitored domain."""

    domain: str
    own_networks: tuple[Network, ...] = ()
    expected_p: str = DEFAULT_POLICY
    expected_sp: str = DEFAULT_POLICY
    dkim_exceptions: tuple[DkimException, ...] = ()
    foreign_min_count: int = DEFAULT_FOREIGN_MIN_COUNT
    watched_reporters: tuple[str, ...] = DEFAULT_WATCHED_REPORTERS
    missing_days: int = DEFAULT_MISSING_DAYS
    notify_no_tls_policy: bool = True

    def is_own(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self.own_networks)


@dataclass(slots=True)
class ReporterStats:
    messages: int = 0
    passed: int = 0
    failed: int = 0


@dataclass(slots=True)
class Stats:
    """The numbers behind the sensors, over the last ``STATS_DAYS`` days."""

    messages: int = 0
    passed: int = 0
    failed: int = 0
    by_reporter: dict[str, ReporterStats] = field(default_factory=dict)
    tls_successful: int = 0
    tls_failed: int = 0
    dmarc_reports: int = 0
    tls_reports: int = 0
    last_report_at: datetime | None = None
    last_report_from: str | None = None
    last_report_kind: str | None = None

    @property
    def pass_rate(self) -> float | None:
        if not self.messages:
            return None
        return round(100 * self.passed / self.messages, 1)


@dataclass(slots=True)
class Evaluation:
    findings: list[Finding]
    stats: Stats
    #: End of the newest report period per kind — the evidence a problem
    #: needs before it may count as resolved.
    latest_end: dict[str, datetime]
    #: Reports for other domains: counted for the diagnostics, ignored otherwise.
    foreign_domain_reports: int = 0


def parse_networks(values: Iterable[str]) -> tuple[Network, ...]:
    """Addresses or CIDR ranges → networks; unparseable entries raise."""
    networks: list[Network] = []
    for value in values:
        text = value.strip()
        if text:
            networks.append(ipaddress.ip_network(text, strict=False))
    return tuple(networks)


def parse_dkim_exceptions(lines: Iterable[str]) -> tuple[DkimException, ...]:
    """``reporter selector`` per line; a line with one word means any selector."""
    exceptions: list[DkimException] = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0].startswith("#"):
            continue
        exceptions.append(DkimException(parts[0], parts[1] if len(parts) > 1 else "*"))
    return tuple(exceptions)


def reporter_matches(pattern: str, org_name: str, email: str = "") -> bool:
    """Does a reporter pattern name this reporter?

    Reporters identify themselves inconsistently — Google writes ``google.com``
    as its organisation, Mimecast its brand name — so the pattern is tried
    against the organisation and against the domain of the sender address.
    """
    pattern = pattern.strip().lower()
    org = org_name.strip().lower()
    sender = email_domain(email)
    return (
        fnmatchcase(org, pattern)
        or (bool(sender) and fnmatchcase(sender, pattern))
        or (bool(sender) and sender.endswith(f".{pattern}"))
    )


DEFAULT_EXCEPTIONS = parse_dkim_exceptions(DEFAULT_DKIM_EXCEPTIONS)


class _Collector:
    """Merges the occurrences of a finding across reports."""

    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}

    def add(
        self,
        key: str,
        rule: str,
        level: str,
        kind: str,
        begin: datetime,
        end: datetime,
        seen_by: str,
        count: int,
        **params: Any,
    ) -> None:
        finding = self.findings.get(key)
        if finding is None:
            self.findings[key] = Finding(
                key=key,
                rule=rule,
                level=level,
                kind=kind,
                first_seen=begin,
                last_seen=end,
                count=count,
                params=dict(params),
                reporters={seen_by},
            )
            return
        finding.first_seen = min(finding.first_seen, begin)
        finding.last_seen = max(finding.last_seen, end)
        finding.count += count
        finding.reporters.add(seen_by)


def _own_partial_failures(
    collect: _Collector, report: DmarcReport, record: DmarcRecord, cfg: RuleConfig
) -> None:
    """D3: one mechanism fails for our own server, DMARC still passes."""
    signatures = [r for r in record.dkim_results if in_domain(r.domain, cfg.domain)]
    if not signatures:
        collect.add(
            f"{RULE_OWN_PARTIAL_FAIL}:dkim-missing:{report.reporter}",
            RULE_OWN_PARTIAL_FAIL,
            LEVEL_WARNING,
            KIND_DMARC,
            report.begin,
            report.end,
            report.reporter,
            record.count,
            mechanism="dkim-missing",
            ip=record.source_ip,
        )
    for signature in signatures:
        if signature.result == "pass":
            continue
        if any(
            rule.matches(report, signature.selector) for rule in cfg.dkim_exceptions
        ):
            continue
        collect.add(
            f"{RULE_OWN_PARTIAL_FAIL}:dkim:{report.reporter}:{signature.selector}",
            RULE_OWN_PARTIAL_FAIL,
            LEVEL_WARNING,
            KIND_DMARC,
            report.begin,
            report.end,
            report.reporter,
            record.count,
            mechanism="dkim",
            selector=signature.selector,
            result=signature.result,
            ip=record.source_ip,
        )
    for check in record.spf_results:
        if check.result == "pass" or not in_domain(check.domain, cfg.domain):
            continue
        # DMARC aligns on MAIL FROM only. A missing SPF record for the HELO
        # name is common and harmless.
        if check.scope == "helo":
            continue
        collect.add(
            f"{RULE_OWN_PARTIAL_FAIL}:spf:{report.reporter}:{record.source_ip}",
            RULE_OWN_PARTIAL_FAIL,
            LEVEL_WARNING,
            KIND_DMARC,
            report.begin,
            report.end,
            report.reporter,
            record.count,
            mechanism="spf",
            result=check.result,
            spf_domain=check.domain,
            ip=record.source_ip,
        )


def _dmarc_findings(collect: _Collector, report: DmarcReport, cfg: RuleConfig) -> None:
    policy = report.policy
    # D4: the record the reporter saw differs from the one we publish. An
    # unspecified subdomain policy inherits p.
    effective_sp = policy.sp if policy.sp not in ("", "unspecified") else policy.p
    for name, found, expected in (
        ("p", policy.p, cfg.expected_p),
        ("sp", effective_sp, cfg.expected_sp),
    ):
        if found and found != expected:
            collect.add(
                f"{RULE_POLICY_MISMATCH}:{name}:{found}",
                RULE_POLICY_MISMATCH,
                LEVEL_ERROR,
                KIND_DMARC,
                report.begin,
                report.end,
                report.reporter,
                1,
                field=name,
                found=found,
                expected=expected,
            )
    if policy.testing:
        collect.add(
            f"{RULE_POLICY_MISMATCH}:t:y",
            RULE_POLICY_MISMATCH,
            LEVEL_ERROR,
            KIND_DMARC,
            report.begin,
            report.end,
            report.reporter,
            1,
            field="t",
            found="y",
            expected="n",
        )

    for record in report.records:
        if record.count <= 0:
            continue
        own = cfg.is_own(record.source_ip)
        if own and not record.dmarc_pass:
            collect.add(
                f"{RULE_OWN_DMARC_FAIL}:{record.source_ip}",
                RULE_OWN_DMARC_FAIL,
                LEVEL_ERROR,
                KIND_DMARC,
                report.begin,
                report.end,
                report.reporter,
                record.count,
                ip=record.source_ip,
                dkim=record.dkim,
                spf=record.spf,
            )
        elif own:
            _own_partial_failures(collect, report, record, cfg)
        elif not record.dmarc_pass and not (
            FORWARDING_OVERRIDES.intersection(record.overrides)
        ):
            collect.add(
                f"{RULE_FOREIGN_DMARC_FAIL}:{record.source_ip}",
                RULE_FOREIGN_DMARC_FAIL,
                LEVEL_WARNING,
                KIND_DMARC,
                report.begin,
                report.end,
                report.reporter,
                record.count,
                ip=record.source_ip,
                header_from=record.header_from,
                disposition=record.disposition,
            )


def _tls_findings(collect: _Collector, report: TlsReport, cfg: RuleConfig) -> None:
    for policy in report.policies:
        if not in_domain(policy.policy_domain, cfg.domain):
            continue
        if policy.policy_type == "nopolicyfound" and cfg.notify_no_tls_policy:
            collect.add(
                RULE_TLS_NO_POLICY,
                RULE_TLS_NO_POLICY,
                LEVEL_INFO,
                KIND_TLS,
                report.begin,
                report.end,
                report.reporter,
                policy.successful + policy.failed,
            )
        if policy.failed <= 0:
            continue
        listed = [f for f in policy.failures if f.count > 0]
        for failure in listed:
            collect.add(
                f"{RULE_TLS_FAILURE}:{failure.result_type}:{failure.mx_host or '-'}",
                RULE_TLS_FAILURE,
                LEVEL_ERROR,
                KIND_TLS,
                report.begin,
                report.end,
                report.reporter,
                failure.count,
                result_type=failure.result_type,
                mx_host=failure.mx_host,
                receiving_ip=failure.receiving_ip,
                reason=failure.reason,
            )
        unlisted = policy.failed - sum(f.count for f in listed)
        if unlisted > 0:
            collect.add(
                f"{RULE_TLS_FAILURE}:unknown:-",
                RULE_TLS_FAILURE,
                LEVEL_ERROR,
                KIND_TLS,
                report.begin,
                report.end,
                report.reporter,
                unlisted,
                result_type="unknown",
            )


def _missing_reports(
    collect: _Collector,
    reports: Sequence[DmarcReport],
    cfg: RuleConfig,
    now: datetime,
) -> None:
    """R1: a watched reporter has gone quiet."""
    limit = timedelta(days=cfg.missing_days)
    for pattern in cfg.watched_reporters:
        received = [
            r.received_at
            for r in reports
            if reporter_matches(pattern, r.org_name, r.email)
        ]
        last = max(received, default=None)
        if last is not None and now - last <= limit:
            continue
        collect.add(
            f"{RULE_REPORTS_MISSING}:{pattern}",
            RULE_REPORTS_MISSING,
            LEVEL_INFO,
            KIND_STATUS,
            last or now,
            now,
            pattern,
            0,
            reporter=pattern,
            last_received=last.isoformat() if last else None,
            days=cfg.missing_days,
        )


def _stats(
    dmarc: Sequence[DmarcReport],
    tls: Sequence[TlsReport],
    cfg: RuleConfig,
    now: datetime,
) -> Stats:
    stats = Stats()
    since = now - timedelta(days=STATS_DAYS)
    for report in dmarc:
        if report.end < since:
            continue
        stats.dmarc_reports += 1
        bucket = stats.by_reporter.setdefault(report.reporter, ReporterStats())
        for record in report.records:
            passed = record.count if record.dmarc_pass else 0
            stats.messages += record.count
            stats.passed += passed
            stats.failed += record.count - passed
            bucket.messages += record.count
            bucket.passed += passed
            bucket.failed += record.count - passed
    for tls_report in tls:
        if tls_report.end < since:
            continue
        stats.tls_reports += 1
        for policy in tls_report.policies:
            if in_domain(policy.policy_domain, cfg.domain):
                stats.tls_successful += policy.successful
                stats.tls_failed += policy.failed
    latest: tuple[datetime, str, str] | None = None
    for report in dmarc:
        if latest is None or report.received_at > latest[0]:
            latest = (report.received_at, report.org_name, KIND_DMARC)
    for tls_report in tls:
        if latest is None or tls_report.received_at > latest[0]:
            latest = (tls_report.received_at, tls_report.org_name, KIND_TLS)
    if latest:
        stats.last_report_at, stats.last_report_from, stats.last_report_kind = latest
    return stats


def evaluate(
    dmarc: Sequence[DmarcReport],
    tls: Sequence[TlsReport],
    cfg: RuleConfig,
    now: datetime,
) -> Evaluation:
    """Apply every rule to the reports of the monitored domain."""
    own_dmarc = [r for r in dmarc if r.policy.domain == cfg.domain]
    own_tls = [
        r
        for r in tls
        if any(in_domain(p.policy_domain, cfg.domain) for p in r.policies)
    ]
    collect = _Collector()
    for report in own_dmarc:
        _dmarc_findings(collect, report, cfg)
    for tls_report in own_tls:
        _tls_findings(collect, tls_report, cfg)
    _missing_reports(collect, own_dmarc, cfg, now)

    findings = [
        f
        for f in collect.findings.values()
        if f.rule != RULE_FOREIGN_DMARC_FAIL or f.count >= cfg.foreign_min_count
    ]
    latest_end: dict[str, datetime] = {}
    if own_dmarc:
        latest_end[KIND_DMARC] = max(r.end for r in own_dmarc)
    if own_tls:
        latest_end[KIND_TLS] = max(r.end for r in own_tls)
    return Evaluation(
        findings=sorted(findings, key=lambda f: f.key),
        stats=_stats(own_dmarc, own_tls, cfg, now),
        latest_end=latest_end,
        foreign_domain_reports=(len(dmarc) - len(own_dmarc))
        + (len(tls) - len(own_tls)),
    )
