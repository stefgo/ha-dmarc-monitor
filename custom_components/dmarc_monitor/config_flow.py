"""Config, reauth and options flow."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any
from urllib.parse import urlsplit

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from . import build_client
from .analysis import parse_dkim_exceptions, parse_networks
from .const import (
    CONF_API_KEY,
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
    CONF_URL,
    CONF_VERIFY_SSL,
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
    LOGNOTIFIER_DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
    OBJECT_DMARC,
    OBJECT_TLS,
    POLICY_VALUES,
)
from .parse import ParseError, parse_dmarc_report
from .stalwart import StalwartAuthError, StalwartConnectionError

_LOGGER = logging.getLogger(__name__)

# Reports read in the config flow to suggest the domain and its policy.
SAMPLE_REPORTS = 20

SECRET = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
URL = TextSelector(TextSelectorConfig(type=TextSelectorType.URL))
MULTILINE = TextSelector(TextSelectorConfig(multiline=True))
POLICY = SelectSelector(
    SelectSelectorConfig(options=list(POLICY_VALUES), mode=SelectSelectorMode.DROPDOWN)
)


def _days(maximum: int) -> NumberSelector:
    return NumberSelector(
        NumberSelectorConfig(min=1, max=maximum, step=1, mode=NumberSelectorMode.BOX)
    )


def _lines(text: str) -> list[str]:
    """Commas or line breaks — whatever the user typed."""
    return [
        part.strip() for part in text.replace(",", "\n").splitlines() if part.strip()
    ]


def lognotifier_channels(hass: HomeAssistant) -> list[SelectOptionDict]:
    """The channels of Log Notifier, read from its entry."""
    channels: list[SelectOptionDict] = []
    for entry in hass.config_entries.async_entries(LOGNOTIFIER_DOMAIN):
        for channel_id, data in (entry.options.get("channels") or {}).items():
            name = data.get("name") if isinstance(data, dict) else None
            channels.append(
                SelectOptionDict(value=channel_id, label=f"{name or channel_id}")
            )
    return channels


def default_channel(channels: list[SelectOptionDict]) -> str:
    for channel in channels:
        if DEFAULT_CHANNEL in (channel["value"].lower(), channel["label"].lower()):
            return channel["value"]
    return channels[0]["value"] if channels else DEFAULT_CHANNEL


def channel_selector(channels: list[SelectOptionDict]) -> SelectSelector:
    # custom_value: Log Notifier may not be set up yet, or the channel is
    # created afterwards.
    return SelectSelector(
        SelectSelectorConfig(
            options=channels, custom_value=True, mode=SelectSelectorMode.DROPDOWN
        )
    )


async def resolve_host(hass: HomeAssistant, url: str) -> list[str]:
    """Addresses of the server in the URL — usually the outgoing mail server."""
    host = urlsplit(url).hostname
    if not host:
        return []
    try:
        infos = await asyncio.wait_for(
            hass.async_add_executor_job(socket.getaddrinfo, host, None),
            5,
        )
    except (OSError, TimeoutError):
        return []
    return sorted({str(info[4][0]) for info in infos})


def validate_options(
    user_input: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Form → options; text fields become lists."""
    errors: dict[str, str] = {}
    options = dict(user_input)
    options[CONF_OWN_IPS] = _lines(str(user_input.get(CONF_OWN_IPS, "")))
    try:
        parse_networks(options[CONF_OWN_IPS])
    except ValueError:
        errors[CONF_OWN_IPS] = "invalid_ips"
    if CONF_DKIM_EXCEPTIONS in user_input:
        options[CONF_DKIM_EXCEPTIONS] = [
            line.strip()
            for line in str(user_input[CONF_DKIM_EXCEPTIONS]).splitlines()
            if line.strip()
        ]
        parse_dkim_exceptions(options[CONF_DKIM_EXCEPTIONS])
    if CONF_WATCHED_REPORTERS in user_input:
        options[CONF_WATCHED_REPORTERS] = [
            r.lower() for r in _lines(str(user_input[CONF_WATCHED_REPORTERS]))
        ]
    for key in (
        CONF_SCAN_INTERVAL,
        CONF_FOREIGN_MIN_COUNT,
        CONF_MISSING_DAYS,
        CONF_RESOLVE_DAYS,
    ):
        if key in options:
            options[key] = int(options[key])
    return options, errors


class DmarcMonitorConfigFlow(ConfigFlow, domain=DOMAIN):
    """Two steps: the server, then the domain."""

    VERSION = 1

    def __init__(self) -> None:
        self._server: dict[str, Any] = {}
        self._suggested: dict[str, Any] = {}

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return DmarcMonitorOptionsFlow()

    async def _validate(self, data: dict[str, Any]) -> str | None:
        client = build_client(self.hass, data)
        try:
            await client.async_validate([OBJECT_DMARC, OBJECT_TLS])
        except StalwartAuthError as err:
            _LOGGER.debug("API key rejected: %s", err)
            return "invalid_auth"
        except StalwartConnectionError as err:
            _LOGGER.debug("Stalwart unreachable: %s", err)
            return "cannot_connect"
        except Exception:
            _LOGGER.exception("Unexpected error while validating Stalwart")
            return "unknown"
        return None

    async def _suggest(self, data: dict[str, Any]) -> None:
        """Read a few reports for the domain and its policy."""
        client = build_client(self.hass, data)
        try:
            ids = await client.query_ids(OBJECT_DMARC)
            objects = await client.get(OBJECT_DMARC, ids[-SAMPLE_REPORTS:])
        except (StalwartAuthError, StalwartConnectionError):
            return
        reports = []
        for obj in objects:
            try:
                reports.append(parse_dmarc_report(obj))
            except ParseError:
                continue
        if not reports:
            return
        latest = max(reports, key=lambda r: r.received_at)
        self._suggested = {
            CONF_DOMAIN: latest.policy.domain,
            CONF_EXPECTED_P: latest.policy.p
            if latest.policy.p in POLICY_VALUES
            else DEFAULT_POLICY,
            CONF_EXPECTED_SP: latest.policy.sp
            if latest.policy.sp in POLICY_VALUES
            else latest.policy.p
            if latest.policy.p in POLICY_VALUES
            else DEFAULT_POLICY,
        }

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """The Stalwart server and its API key."""
        errors: dict[str, str] = {}
        if user_input is not None:
            user_input[CONF_URL] = user_input[CONF_URL].strip().rstrip("/")
            error = await self._validate(user_input)
            if error is None:
                self._server = user_input
                await self._suggest(user_input)
                return await self.async_step_domain()
            errors["base"] = error

        schema = vol.Schema(
            {
                vol.Required(CONF_URL): URL,
                vol.Required(CONF_API_KEY): SECRET,
                vol.Required(CONF_VERIFY_SSL, default=True): BooleanSelector(),
            }
        )
        suggested = {k: v for k, v in (user_input or {}).items() if k != CONF_API_KEY}
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
            # hassfest rejects URLs inside translation strings.
            description_placeholders={"example_url": "https://mail.example.org"},
        )

    async def async_step_domain(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Which domain, which own servers, which Log Notifier channel."""
        errors: dict[str, str] = {}
        channels = lognotifier_channels(self.hass)
        if user_input is not None:
            domain = user_input[CONF_DOMAIN].strip().rstrip(".").lower()
            options, errors = validate_options(
                {k: v for k, v in user_input.items() if k != CONF_DOMAIN}
            )
            if not domain or "." not in domain:
                errors[CONF_DOMAIN] = "invalid_domain"
            if not errors:
                await self.async_set_unique_id(domain)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=domain,
                    data={**self._server, CONF_DOMAIN: domain},
                    options={
                        CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
                        CONF_DKIM_EXCEPTIONS: list(DEFAULT_DKIM_EXCEPTIONS),
                        CONF_FOREIGN_MIN_COUNT: DEFAULT_FOREIGN_MIN_COUNT,
                        CONF_WATCHED_REPORTERS: list(DEFAULT_WATCHED_REPORTERS),
                        CONF_MISSING_DAYS: DEFAULT_MISSING_DAYS,
                        CONF_RESOLVE_DAYS: DEFAULT_RESOLVE_DAYS,
                        CONF_NOTIFY_NO_TLS_POLICY: DEFAULT_NOTIFY_NO_TLS_POLICY,
                        **options,
                    },
                )

        host = urlsplit(self._server.get(CONF_URL, "")).hostname or ""
        fallback_domain = host.split(".", 1)[1] if host.count(".") >= 2 else host
        suggested = {
            CONF_DOMAIN: self._suggested.get(CONF_DOMAIN, fallback_domain),
            CONF_OWN_IPS: ", ".join(
                await resolve_host(self.hass, self._server.get(CONF_URL, ""))
            ),
            CONF_CHANNEL: default_channel(channels),
            CONF_EXPECTED_P: self._suggested.get(CONF_EXPECTED_P, DEFAULT_POLICY),
            CONF_EXPECTED_SP: self._suggested.get(CONF_EXPECTED_SP, DEFAULT_POLICY),
        }
        if user_input is not None:
            suggested.update(user_input)
        schema = vol.Schema(
            {
                vol.Required(CONF_DOMAIN): TextSelector(),
                vol.Required(CONF_OWN_IPS): TextSelector(),
                vol.Required(CONF_CHANNEL): channel_selector(channels),
                vol.Required(CONF_EXPECTED_P): POLICY,
                vol.Required(CONF_EXPECTED_SP): POLICY,
            }
        )
        return self.async_show_form(
            step_id="domain",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """A new API key for the same server."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            data = {**entry.data, CONF_API_KEY: user_input[CONF_API_KEY]}
            error = await self._validate(data)
            if error is None:
                return self.async_update_reload_and_abort(entry, data=data)
            errors["base"] = error
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_API_KEY): SECRET}),
            errors=errors,
            description_placeholders={
                "domain": entry.title,
                "url": entry.data.get(CONF_URL, ""),
            },
        )


class DmarcMonitorOptionsFlow(OptionsFlow):
    """Every knob of the rules in one form."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            options, errors = validate_options(user_input)
            # A cleared optional field is left out of the form data; it means
            # "none", not "back to the defaults".
            options.setdefault(CONF_DKIM_EXCEPTIONS, [])
            options.setdefault(CONF_WATCHED_REPORTERS, [])
            if not errors:
                return self.async_create_entry(data=options)

        current = self.config_entry.options
        channels = lognotifier_channels(self.hass)
        suggested = {
            CONF_OWN_IPS: ", ".join(current.get(CONF_OWN_IPS, [])),
            CONF_CHANNEL: current.get(CONF_CHANNEL, default_channel(channels)),
            CONF_EXPECTED_P: current.get(CONF_EXPECTED_P, DEFAULT_POLICY),
            CONF_EXPECTED_SP: current.get(CONF_EXPECTED_SP, DEFAULT_POLICY),
            CONF_SCAN_INTERVAL: current.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            CONF_DKIM_EXCEPTIONS: "\n".join(
                current.get(CONF_DKIM_EXCEPTIONS, DEFAULT_DKIM_EXCEPTIONS)
            ),
            CONF_FOREIGN_MIN_COUNT: current.get(
                CONF_FOREIGN_MIN_COUNT, DEFAULT_FOREIGN_MIN_COUNT
            ),
            CONF_WATCHED_REPORTERS: ", ".join(
                current.get(CONF_WATCHED_REPORTERS, DEFAULT_WATCHED_REPORTERS)
            ),
            CONF_MISSING_DAYS: current.get(CONF_MISSING_DAYS, DEFAULT_MISSING_DAYS),
            CONF_RESOLVE_DAYS: current.get(CONF_RESOLVE_DAYS, DEFAULT_RESOLVE_DAYS),
            CONF_NOTIFY_NO_TLS_POLICY: current.get(
                CONF_NOTIFY_NO_TLS_POLICY, DEFAULT_NOTIFY_NO_TLS_POLICY
            ),
        }
        if user_input is not None:
            suggested.update(user_input)
        schema = vol.Schema(
            {
                vol.Required(CONF_OWN_IPS): TextSelector(),
                vol.Required(CONF_CHANNEL): channel_selector(channels),
                vol.Required(CONF_EXPECTED_P): POLICY,
                vol.Required(CONF_EXPECTED_SP): POLICY,
                vol.Required(CONF_SCAN_INTERVAL): NumberSelector(
                    NumberSelectorConfig(
                        min=MIN_SCAN_INTERVAL,
                        max=MAX_SCAN_INTERVAL,
                        step=1,
                        mode=NumberSelectorMode.BOX,
                        unit_of_measurement="min",
                    )
                ),
                vol.Optional(CONF_DKIM_EXCEPTIONS): MULTILINE,
                vol.Required(CONF_FOREIGN_MIN_COUNT): NumberSelector(
                    NumberSelectorConfig(
                        min=1, max=10000, step=1, mode=NumberSelectorMode.BOX
                    )
                ),
                vol.Optional(CONF_WATCHED_REPORTERS): TextSelector(),
                vol.Required(CONF_MISSING_DAYS): _days(30),
                vol.Required(CONF_RESOLVE_DAYS): _days(30),
                vol.Required(CONF_NOTIFY_NO_TLS_POLICY): BooleanSelector(),
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
        )
