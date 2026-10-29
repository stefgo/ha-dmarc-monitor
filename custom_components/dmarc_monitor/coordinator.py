"""Update coordinator: fetch reports, evaluate, track, deliver."""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .analysis import (
    Evaluation,
    RuleConfig,
    Stats,
    evaluate,
    parse_dkim_exceptions,
    parse_networks,
)
from .const import (
    CONF_CHANNEL,
    CONF_DKIM_EXCEPTIONS,
    CONF_DOMAIN,
    CONF_EXPECTED_P,
    CONF_EXPECTED_SP,
    CONF_FOREIGN_MIN_COUNT,
    CONF_MISSING_DAYS,
    CONF_NOTIFY_NO_TLS_POLICY,
    CONF_OWN_IPS,
    CONF_RESOLVE_DAYS,
    CONF_SCAN_INTERVAL,
    CONF_WATCHED_REPORTERS,
    DEFAULT_CHANNEL,
    DEFAULT_DKIM_EXCEPTIONS,
    DEFAULT_FOREIGN_MIN_COUNT,
    DEFAULT_MISSING_DAYS,
    DEFAULT_NOTIFY_NO_TLS_POLICY,
    DEFAULT_POLICY,
    DEFAULT_RESOLVE_DAYS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_WATCHED_REPORTERS,
    DOMAIN,
    ISSUE_DELIVERY_FAILED,
    LOGNOTIFIER_DOMAIN,
    LOGNOTIFIER_SERVICE,
    OBJECT_DMARC,
    OBJECT_TLS,
    STORAGE_VERSION,
)
from .messages import build_message
from .models import DmarcReport, TlsReport
from .parse import ParseError, parse_dmarc_report, parse_tls_report
from .stalwart import StalwartAuthError, StalwartClient, StalwartConnectionError
from .tracker import Notification, Problem, ProblemTracker

_LOGGER = logging.getLogger(__name__)

# A flood of forged reports must not turn into a flood of messages: the rest
# stays in the outbox and goes out in the following cycles.
MAX_DELIVERIES_PER_CYCLE = 10
RDNS_TIMEOUT = 5

API_OK = "ok"
API_AUTH_FAILED = "auth_failed"
API_CANNOT_CONNECT = "cannot_connect"

type DmarcMonitorConfigEntry = ConfigEntry[DmarcMonitorCoordinator]


@dataclass(slots=True)
class MonitorData:
    """What the entities show after one cycle."""

    stats: Stats
    open_problems: list[Problem] = field(default_factory=list)
    has_problem: bool = False
    foreign_domain_reports: int = 0


def rule_config(data: dict[str, Any], options: dict[str, Any]) -> RuleConfig:
    """Entry data and options → the configuration of the rules."""
    return RuleConfig(
        domain=str(data[CONF_DOMAIN]).strip().lower(),
        own_networks=parse_networks(options.get(CONF_OWN_IPS, [])),
        expected_p=options.get(CONF_EXPECTED_P, DEFAULT_POLICY),
        expected_sp=options.get(CONF_EXPECTED_SP, DEFAULT_POLICY),
        dkim_exceptions=parse_dkim_exceptions(
            options.get(CONF_DKIM_EXCEPTIONS, list(DEFAULT_DKIM_EXCEPTIONS))
        ),
        foreign_min_count=int(
            options.get(CONF_FOREIGN_MIN_COUNT, DEFAULT_FOREIGN_MIN_COUNT)
        ),
        watched_reporters=tuple(
            options.get(CONF_WATCHED_REPORTERS, list(DEFAULT_WATCHED_REPORTERS))
        ),
        missing_days=int(options.get(CONF_MISSING_DAYS, DEFAULT_MISSING_DAYS)),
        notify_no_tls_policy=bool(
            options.get(CONF_NOTIFY_NO_TLS_POLICY, DEFAULT_NOTIFY_NO_TLS_POLICY)
        ),
    )


class DmarcMonitorCoordinator(DataUpdateCoordinator[MonitorData]):
    """Reads the reports of one Stalwart server for one domain."""

    config_entry: DmarcMonitorConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: DmarcMonitorConfigEntry,
        client: StalwartClient,
    ) -> None:
        options = entry.options
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {entry.title}",
            update_interval=timedelta(
                minutes=int(options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
            ),
            config_entry=entry,
        )
        self.client = client
        self.rules = rule_config(dict(entry.data), dict(options))
        self.channel: str = options.get(CONF_CHANNEL, DEFAULT_CHANNEL)
        self.tracker = ProblemTracker(
            timedelta(days=int(options.get(CONF_RESOLVE_DAYS, DEFAULT_RESOLVE_DAYS)))
        )
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        # Stored reports never change; they only expire. Cached by Stalwart id,
        # so every cycle fetches just the new ones.
        self._dmarc: dict[str, DmarcReport] = {}
        self._tls: dict[str, TlsReport] = {}
        # Per object type: ids are only unique within one type.
        self._unparseable: dict[str, set[str]] = {
            OBJECT_DMARC: set(),
            OBJECT_TLS: set(),
        }
        self._hostnames: dict[str, str | None] = {}
        self._delivering = asyncio.Lock()
        self.api_status = API_OK
        self.api_detail: str | None = None
        self.last_evaluation: Evaluation | None = None
        self.last_delivery_error: str | None = None

    # --- Lifecycle ------------------------------------------------------------

    async def async_load(self) -> None:
        """Restore the tracker before the first refresh."""
        self.tracker.load(await self._store.async_load())
        # Notifications that waited for Log Notifier go out once HA has
        # started — at that point Log Notifier's service exists, if at all.
        self.config_entry.async_on_unload(
            async_at_started(self.hass, self._async_started)
        )

    async def _async_started(self, _hass: HomeAssistant) -> None:
        await self.async_deliver()

    def _save(self) -> None:
        self._store.async_delay_save(self.tracker.as_dict, 1)

    # --- Fetching -------------------------------------------------------------

    async def _sync(self, object_type: str, cache: dict[str, Any], parser: Any) -> None:
        ids = await self.client.query_ids(object_type)
        current = set(ids)
        for stale in set(cache) - current:
            del cache[stale]
        skipped = self._unparseable[object_type]
        skipped &= current
        new = [i for i in ids if i not in cache and i not in skipped]
        if not new:
            return
        for obj in await self.client.get(object_type, new):
            object_id = str(obj.get("id", ""))
            try:
                cache[object_id] = parser(obj)
            except ParseError as err:
                _LOGGER.debug("Skipping %s %s: %s", object_type, object_id, err)
                skipped.add(object_id)

    async def _hostname(self, ip: str) -> str | None:
        if ip in self._hostnames:
            return self._hostnames[ip]
        try:
            host, _aliases, _addresses = await asyncio.wait_for(
                self.hass.async_add_executor_job(socket.gethostbyaddr, ip),
                RDNS_TIMEOUT,
            )
        except (OSError, TimeoutError):
            host = None
        self._hostnames[ip] = host
        return host

    async def _async_update_data(self) -> MonitorData:
        try:
            await self._sync(OBJECT_DMARC, self._dmarc, parse_dmarc_report)
            await self._sync(OBJECT_TLS, self._tls, parse_tls_report)
        except StalwartAuthError as err:
            self.api_status, self.api_detail = API_AUTH_FAILED, str(err)
            raise ConfigEntryAuthFailed(str(err)) from err
        except StalwartConnectionError as err:
            self.api_status, self.api_detail = API_CANNOT_CONNECT, str(err)
            raise UpdateFailed(str(err)) from err
        self.api_status, self.api_detail = API_OK, None

        now = dt_util.utcnow()
        evaluation = evaluate(
            list(self._dmarc.values()), list(self._tls.values()), self.rules, now
        )
        recent = now - self.tracker.resolve_after
        for finding in evaluation.findings:
            ip = finding.params.get("ip")
            if ip and finding.last_seen >= recent:
                finding.params["host"] = await self._hostname(ip)
        self.last_evaluation = evaluation
        if self.tracker.update(evaluation.findings, evaluation.latest_end, now):
            self._save()
        await self.async_deliver()
        return MonitorData(
            stats=evaluation.stats,
            open_problems=self.tracker.open_problems(),
            has_problem=self.tracker.has_problem,
            foreign_domain_reports=evaluation.foreign_domain_reports,
        )

    # --- Delivery -------------------------------------------------------------

    async def async_deliver(self) -> None:
        """Send waiting notifications to Log Notifier."""
        if self.hass.state is not CoreState.running or not self.tracker.outbox:
            return
        async with self._delivering:
            await self._deliver()

    async def _deliver(self) -> None:
        if not self.hass.services.has_service(LOGNOTIFIER_DOMAIN, LOGNOTIFIER_SERVICE):
            self._delivery_failed("Log Notifier is not installed or not set up")
            return
        sent = 0
        while self.tracker.outbox and sent < MAX_DELIVERIES_PER_CYCLE:
            notification: Notification = self.tracker.outbox[0]
            data = build_message(
                notification,
                self.rules.domain,
                self.channel,
                self.hass.config.language,
            )
            try:
                await self.hass.services.async_call(
                    LOGNOTIFIER_DOMAIN, LOGNOTIFIER_SERVICE, data, blocking=True
                )
            except HomeAssistantError as err:
                self._delivery_failed(str(err))
                break
            self.tracker.outbox.pop(0)
            sent += 1
        if sent:
            self._save()
        if not self.tracker.outbox:
            self.last_delivery_error = None
            ir.async_delete_issue(
                self.hass,
                DOMAIN,
                f"{ISSUE_DELIVERY_FAILED}_{self.config_entry.entry_id}",
            )

    def _delivery_failed(self, reason: str) -> None:
        if reason != self.last_delivery_error:
            _LOGGER.warning(
                "Could not send %d message(s) to Log Notifier channel %s: %s",
                len(self.tracker.outbox),
                self.channel,
                reason,
            )
        self.last_delivery_error = reason
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"{ISSUE_DELIVERY_FAILED}_{self.config_entry.entry_id}",
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_DELIVERY_FAILED,
            translation_placeholders={
                "domain": self.rules.domain,
                "channel": self.channel,
                "reason": reason,
                "count": str(len(self.tracker.outbox)),
            },
        )

    # --- Diagnostics ----------------------------------------------------------

    def diagnostics(self) -> dict[str, Any]:
        evaluation = self.last_evaluation
        return {
            "api_status": self.api_status,
            "api_detail": self.api_detail,
            "reports": {
                "dmarc": len(self._dmarc),
                "tls": len(self._tls),
                "unparseable": {
                    kind: sorted(ids) for kind, ids in self._unparseable.items()
                },
                "other_domains": evaluation.foreign_domain_reports if evaluation else 0,
            },
            "findings": [
                {
                    "key": f.key,
                    "level": f.level,
                    "first_seen": f.first_seen.isoformat(),
                    "last_seen": f.last_seen.isoformat(),
                    "count": f.count,
                }
                for f in (evaluation.findings if evaluation else [])
            ],
            "tracker": self.tracker.as_dict(),
            "channel": self.channel,
            "last_delivery_error": self.last_delivery_error,
        }
