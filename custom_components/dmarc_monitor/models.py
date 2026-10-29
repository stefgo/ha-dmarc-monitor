"""Data model: received reports and the problems derived from them.

No Home Assistant imports here — the parser, the rules and the tracker are
tested with nothing but pytest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class DkimResult:
    """One DKIM signature as the reporter evaluated it."""

    domain: str
    selector: str
    result: str


@dataclass(frozen=True, slots=True)
class SpfResult:
    """One SPF check as the reporter evaluated it."""

    domain: str
    scope: str
    result: str


@dataclass(frozen=True, slots=True)
class DmarcRecord:
    """One row of an aggregate report: a source IP and what happened to it."""

    source_ip: str | None
    count: int
    disposition: str
    # The DMARC verdict per mechanism: "pass" only if aligned *and* passed.
    dkim: str
    spf: str
    header_from: str
    dkim_results: tuple[DkimResult, ...] = ()
    spf_results: tuple[SpfResult, ...] = ()
    overrides: tuple[str, ...] = ()

    @property
    def dmarc_pass(self) -> bool:
        """DMARC passes when at least one mechanism passed aligned."""
        return self.dkim == "pass" or self.spf == "pass"


@dataclass(frozen=True, slots=True)
class PublishedPolicy:
    """The DMARC record the reporter found in DNS."""

    domain: str
    p: str
    sp: str
    testing: bool


@dataclass(frozen=True, slots=True)
class DmarcReport:
    """A DMARC aggregate report as Stalwart stored it."""

    id: str
    org_name: str
    email: str
    report_id: str
    begin: datetime
    end: datetime
    received_at: datetime
    policy: PublishedPolicy
    records: tuple[DmarcRecord, ...] = ()

    @property
    def reporter(self) -> str:
        """Short name of the reporter — the organisation, lower case."""
        return self.org_name.strip().lower() or email_domain(self.email)


@dataclass(frozen=True, slots=True)
class TlsFailure:
    """Failed sessions of one kind towards one MX."""

    result_type: str
    count: int
    mx_host: str | None = None
    sending_ip: str | None = None
    receiving_ip: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class TlsPolicyResult:
    """Sessions under one policy (MTA-STS, DANE or none at all)."""

    policy_type: str
    policy_domain: str
    successful: int
    failed: int
    mx_hosts: tuple[str, ...] = ()
    failures: tuple[TlsFailure, ...] = ()


@dataclass(frozen=True, slots=True)
class TlsReport:
    """An SMTP TLS report (RFC 8460) as Stalwart stored it."""

    id: str
    org_name: str
    report_id: str
    begin: datetime
    end: datetime
    received_at: datetime
    policies: tuple[TlsPolicyResult, ...] = ()

    @property
    def reporter(self) -> str:
        """Short name of the reporter, lower case."""
        return self.org_name.strip().lower()


@dataclass(slots=True)
class Finding:
    """A problem one evaluation found in the stored reports.

    ``key`` identifies the problem across evaluations — the same failing
    source on the next day is the same problem, not a new one. ``last_seen`` is
    the end of the newest report period it occurred in.
    """

    key: str
    rule: str
    level: str
    kind: str
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    params: dict[str, Any] = field(default_factory=dict)
    reporters: set[str] = field(default_factory=set)


def email_domain(address: str) -> str:
    """Domain part of an address, lower case; empty if there is none."""
    return address.rpartition("@")[2].strip().lower()


def in_domain(name: str, domain: str) -> bool:
    """Is ``name`` the domain itself or one of its subdomains?

    Relaxed alignment, which is what the policies here use, compares the
    organisational domain; a subdomain of the monitored domain belongs to it.
    """
    name = name.strip().rstrip(".").lower()
    domain = domain.strip().rstrip(".").lower()
    return name == domain or name.endswith(f".{domain}")
