"""Turn Stalwart's JMAP objects into the data model.

Stalwart has already decompressed, parsed and validated the reports; what
arrives here is JSON. The parser is still lenient: a reporter that leaves a
field out, or a Stalwart version that spells an enum differently, must cost one
field, not the whole report.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .models import (
    DkimResult,
    DmarcRecord,
    DmarcReport,
    PublishedPolicy,
    SpfResult,
    TlsFailure,
    TlsPolicyResult,
    TlsReport,
)

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Stalwart spells TLS result types in camel case; RFC 8460 — and every
# reporter's documentation — uses the kebab-case names. Messages show those.
TLS_RESULT_NAMES = {
    "starttlsnotsupported": "starttls-not-supported",
    "certificatehostmismatch": "certificate-host-mismatch",
    "certificateexpired": "certificate-expired",
    "certificatenottrusted": "certificate-not-trusted",
    "validationfailure": "validation-failure",
    "tlsainvalid": "tlsa-invalid",
    "dnssecinvalid": "dnssec-invalid",
    "danerequired": "dane-required",
    "stspolicyfetcherror": "sts-policy-fetch-error",
    "stspolicyinvalid": "sts-policy-invalid",
    "stswebpkiinvalid": "sts-webpki-invalid",
    "other": "other",
}


class ParseError(ValueError):
    """An object is unusable — the required core fields are missing."""


def norm(value: Any) -> str:
    """Comparable form of an enum value: lower case, letters and digits only.

    ``noPolicyFound``, ``no-policy-found`` and ``NO_POLICY_FOUND`` all become
    ``nopolicyfound``.
    """
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def parse_datetime(value: Any) -> datetime | None:
    """ISO 8601 string or Unix seconds → aware UTC datetime."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _list(value: Any) -> list[Any]:
    """A JSON list, which Stalwart sends as an object keyed by index.

    ``{"0": a, "1": b}`` becomes ``[a, b]``, in index order; a plain array is
    taken as it is.
    """
    if isinstance(value, list):
        return value
    if isinstance(value, Mapping):
        return [value[key] for key in sorted(value, key=_index)]
    return []


def _index(key: Any) -> tuple[int, str]:
    """Sort key: numeric index first ("2" before "10"), anything else after."""
    text = str(key)
    return (int(text), "") if text.isdigit() else (sys.maxsize, text)


def _address(value: Any) -> str:
    """An ``EmailAddress`` may arrive as a string or as ``{name, email}``."""
    if isinstance(value, Mapping):
        return _text(value.get("email")) or _text(value.get("address"))
    return _text(value)


def _required_datetime(data: Mapping[str, Any], *keys: str) -> datetime:
    """The first of ``keys`` that holds a date."""
    for key in keys:
        parsed = parse_datetime(data.get(key))
        if parsed is not None:
            return parsed
    raise ParseError(f"{' / '.join(keys)} is missing or not a date")


def _dmarc_record(data: Mapping[str, Any]) -> DmarcRecord:
    return DmarcRecord(
        source_ip=_text(data.get("sourceIp")) or None,
        count=_int(data.get("count")),
        disposition=norm(data.get("evaluatedDisposition")),
        dkim=norm(data.get("evaluatedDkim")),
        spf=norm(data.get("evaluatedSpf")),
        header_from=_text(data.get("headerFrom")).lower(),
        dkim_results=tuple(
            DkimResult(
                domain=_text(item.get("domain")).lower(),
                selector=_text(item.get("selector")),
                result=norm(item.get("result")),
            )
            for item in _list(data.get("dkimResults"))
            if isinstance(item, Mapping)
        ),
        spf_results=tuple(
            SpfResult(
                domain=_text(item.get("domain")).lower(),
                scope=norm(item.get("scope")),
                result=norm(item.get("result")),
            )
            for item in _list(data.get("spfResults"))
            if isinstance(item, Mapping)
        ),
        overrides=tuple(
            norm(item.get("overrideType"))
            for item in _list(data.get("policyOverrideReasons"))
            if isinstance(item, Mapping)
        ),
    )


def parse_dmarc_report(obj: Mapping[str, Any]) -> DmarcReport:
    """A ``DmarcExternalReport`` object → :class:`DmarcReport`."""
    report = obj.get("report")
    if not isinstance(report, Mapping):
        raise ParseError("report is missing")
    domain = _text(report.get("policyDomain")).lower()
    if not domain:
        raise ParseError("policyDomain is missing")
    # Stalwart names the start of a DMARC period dateRangeBegin, of a TLS
    # period dateRangeStart.
    begin = _required_datetime(report, "dateRangeBegin", "dateRangeStart")
    end = _required_datetime(report, "dateRangeEnd")
    return DmarcReport(
        id=str(obj.get("id", "")),
        org_name=_text(report.get("orgName")),
        email=_address(report.get("email")) or _address(obj.get("from")),
        report_id=_text(report.get("reportId")),
        begin=begin,
        end=end,
        received_at=parse_datetime(obj.get("receivedAt")) or end,
        policy=PublishedPolicy(
            domain=domain,
            p=norm(report.get("policyDisposition")),
            sp=norm(report.get("policySubdomainDisposition")),
            testing=report.get("policyTestingMode") is True,
        ),
        records=tuple(
            _dmarc_record(item)
            for item in _list(report.get("records"))
            if isinstance(item, Mapping)
        ),
    )


def _tls_policy(data: Mapping[str, Any]) -> TlsPolicyResult:
    return TlsPolicyResult(
        policy_type=norm(data.get("policyType")),
        policy_domain=_text(data.get("policyDomain")).lower(),
        successful=_int(data.get("totalSuccessfulSessions")),
        failed=_int(data.get("totalFailedSessions")),
        mx_hosts=tuple(
            _text(host) for host in _list(data.get("mxHosts")) if _text(host)
        ),
        failures=tuple(
            TlsFailure(
                result_type=TLS_RESULT_NAMES.get(
                    norm(item.get("resultType")), _text(item.get("resultType"))
                )
                or "other",
                count=_int(item.get("failedSessionCount")),
                mx_host=_text(item.get("receivingMxHostname")) or None,
                sending_ip=_text(item.get("sendingMtaIp")) or None,
                receiving_ip=_text(item.get("receivingIp")) or None,
                reason=_text(item.get("failureReasonCode"))
                or _text(item.get("additionalInformation"))
                or None,
            )
            for item in _list(data.get("failureDetails"))
            if isinstance(item, Mapping)
        ),
    )


def parse_tls_report(obj: Mapping[str, Any]) -> TlsReport:
    """A ``TlsExternalReport`` object → :class:`TlsReport`."""
    report = obj.get("report")
    if not isinstance(report, Mapping):
        raise ParseError("report is missing")
    begin = _required_datetime(report, "dateRangeStart")
    end = _required_datetime(report, "dateRangeEnd")
    return TlsReport(
        id=str(obj.get("id", "")),
        org_name=_text(report.get("organizationName"))
        or _address(obj.get("from")).rpartition("@")[2],
        report_id=_text(report.get("reportId")),
        begin=begin,
        end=end,
        received_at=parse_datetime(obj.get("receivedAt")) or end,
        policies=tuple(
            _tls_policy(item)
            for item in _list(report.get("policies"))
            if isinstance(item, Mapping)
        ),
    )
