"""Constants for the DMARC Monitor integration."""

from __future__ import annotations

import json
from pathlib import Path

DOMAIN = "dmarc_monitor"


def _manifest_version() -> str:
    """Read the version from the manifest — the single source of truth."""
    try:
        manifest = json.loads(
            (Path(__file__).parent / "manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return "0.0.0"
    version = manifest.get("version")
    return version if isinstance(version, str) and version else "0.0.0"


INTEGRATION_VERSION = _manifest_version()

# --- Levels -----------------------------------------------------------------
# The names Log Notifier knows. TRACE is never sent from here.
LEVEL_ERROR = "ERROR"
LEVEL_WARNING = "WARNING"
LEVEL_INFO = "INFO"

# Levels that make the problem sensor go on. An INFO is a hint, not a problem.
PROBLEM_LEVELS = frozenset({LEVEL_ERROR, LEVEL_WARNING})

# --- Rules ------------------------------------------------------------------
RULE_OWN_DMARC_FAIL = "D1"
RULE_FOREIGN_DMARC_FAIL = "D2"
RULE_OWN_PARTIAL_FAIL = "D3"
RULE_POLICY_MISMATCH = "D4"
RULE_TLS_FAILURE = "T1"
RULE_TLS_NO_POLICY = "T2"
RULE_REPORTS_MISSING = "R1"

# --- Configuration keys -----------------------------------------------------
CONF_URL = "url"
CONF_API_KEY = "api_key"
CONF_VERIFY_SSL = "verify_ssl"
CONF_DOMAIN = "domain"
CONF_OWN_IPS = "own_ips"
CONF_CHANNEL = "channel"
CONF_EXPECTED_P = "expected_p"
CONF_EXPECTED_SP = "expected_sp"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_DKIM_EXCEPTIONS = "dkim_exceptions"
CONF_FOREIGN_MIN_COUNT = "foreign_min_count"
CONF_WATCHED_REPORTERS = "watched_reporters"
CONF_MISSING_DAYS = "missing_days"
CONF_RESOLVE_DAYS = "resolve_days"
CONF_NOTIFY_NO_TLS_POLICY = "notify_no_tls_policy"

DEFAULT_CHANNEL = "alarm"
DEFAULT_POLICY = "reject"
# Minutes. Reports arrive once a day per reporter, an hour is plenty.
DEFAULT_SCAN_INTERVAL = 60
MIN_SCAN_INTERVAL = 5
MAX_SCAN_INTERVAL = 24 * 60
# Google does not verify Ed25519 signatures (RFC 8463) and reports them as
# "fail". Selectors carry the key type in their name; Stalwart rotates the
# keys, so the date part changes and only a pattern stays valid.
DEFAULT_DKIM_EXCEPTIONS = ("google.com *ed25519*",)
DEFAULT_FOREIGN_MIN_COUNT = 1
DEFAULT_WATCHED_REPORTERS = ("google.com",)
DEFAULT_MISSING_DAYS = 3
DEFAULT_RESOLVE_DAYS = 3
DEFAULT_NOTIFY_NO_TLS_POLICY = True

# Window of the statistics sensors.
STATS_DAYS = 7

POLICY_VALUES = ("none", "quarantine", "reject")

# --- Log Notifier -----------------------------------------------------------
LOGNOTIFIER_DOMAIN = "lognotifier"
LOGNOTIFIER_SERVICE = "send"
NOTIFY_SOURCE = "dmarc-monitor"

# --- Storage, issues --------------------------------------------------------
STORAGE_VERSION = 1
ISSUE_DELIVERY_FAILED = "delivery_failed"

# --- Stalwart ---------------------------------------------------------------
JMAP_CAPABILITY_CORE = "urn:ietf:params:jmap:core"
JMAP_CAPABILITY_STALWART = "urn:stalwart:jmap"
OBJECT_DMARC = "x:DmarcExternalReport"
OBJECT_TLS = "x:TlsExternalReport"
# Ids per /get call. Stalwart keeps reports for 30 days, a few per day.
GET_BATCH_SIZE = 50
QUERY_PAGE_SIZE = 250
REQUEST_TIMEOUT = 30
