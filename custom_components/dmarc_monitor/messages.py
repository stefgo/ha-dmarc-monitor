"""Log Notifier messages for opened and resolved problems.

Home Assistant's translations cover the UI, not the text a service call
carries, so the two languages live here. The language follows the instance
(``hass.config.language``); anything but German gets English.
"""

from __future__ import annotations

from typing import Any

from .const import (
    LEVEL_INFO,
    NOTIFY_SOURCE,
    RULE_FOREIGN_DMARC_FAIL,
    RULE_OWN_DMARC_FAIL,
    RULE_OWN_PARTIAL_FAIL,
    RULE_POLICY_MISMATCH,
    RULE_REPORTS_MISSING,
    RULE_TLS_FAILURE,
    RULE_TLS_NO_POLICY,
)
from .tracker import EVENT_RESOLVED, Notification

TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "D1.title": "DMARC fails for your own mail server",
        "D1.body": (
            "**{count}** message(s) from your server **{ip}** passed neither "
            "DKIM nor SPF aligned. Recipients reject them under your policy. "
            "Check the DKIM keys and the SPF record of {domain}."
        ),
        "D2.title": "Foreign sender uses {domain}",
        "D2.body": (
            "**{count}** message(s) from **{ip}** claimed to come from "
            "{domain} and failed DMARC. Your policy tells recipients to "
            "reject them. If this source is one of yours, add its address "
            "under the integration's options."
        ),
        "D3.dkim.title": "DKIM signature {selector} fails at {reporters}",
        "D3.dkim.body": (
            "DMARC still passes because another mechanism holds, but there "
            "is no reserve left. Result: `{result}`. If this reporter cannot "
            "verify the key type, add an exception under the options."
        ),
        "D3.dkim-missing.title": "No DKIM signature in reports from {reporters}",
        "D3.dkim-missing.body": (
            "Mail from your server **{ip}** carried no DKIM signature of "
            "{domain}. DMARC passed on SPF alone."
        ),
        "D3.spf.title": "SPF fails for your own mail server at {reporters}",
        "D3.spf.body": (
            "SPF for {spf_domain} returned `{result}` for **{ip}**. DMARC "
            "passed on DKIM alone. Check that the SPF record lists this address."
        ),
        "D4.title": "DMARC policy differs: {field}={found}",
        "D4.body": (
            "The reporters found `{field}={found}` in the DMARC record of "
            "{domain}, expected `{field}={expected}`. Check the TXT record "
            "`_dmarc.{domain}`."
        ),
        "T1.title": "TLS delivery to {domain} fails: {result_type}",
        "T1.body": (
            "**{count}** session(s) could not be established with TLS. Mail "
            "to you may be delayed, bounced or delivered unencrypted."
        ),
        "T2.title": "No MTA-STS or DANE policy for {domain}",
        "T2.body": (
            "Mail to you is delivered with opportunistic TLS only. This is a "
            "hint and is not repeated; it can be turned off under the options."
        ),
        "R1.title": "No DMARC reports from {reporter} for {days} days",
        "R1.body": (
            "Either no mail went to {reporter}, the `rua` address of the DMARC "
            "record is broken, or Stalwart no longer intercepts the reports."
        ),
        "resolved.title": "Resolved: {title}",
        "resolved.body": "Not seen in the reports any more.",
        "resolved.body.R1": "Reports arrive again.",
        "label.domain": "Domain",
        "label.source": "Source",
        "label.host": "Host",
        "label.messages": "Messages",
        "label.sessions": "Sessions",
        "label.reporters": "Reported by",
        "label.first_seen": "First seen",
        "label.last_seen": "Last seen",
        "label.mx": "MX host",
        "label.reason": "Reason",
        "label.last_received": "Last report",
        "never": "never",
    },
    "de": {
        "D1.title": "DMARC scheitert beim eigenen Mailserver",
        "D1.body": (
            "**{count}** Mail(s) von deinem Server **{ip}** haben weder DKIM "
            "noch SPF aligned bestanden. Empfänger weisen sie wegen deiner "
            "Richtlinie ab. Prüfe die DKIM-Schlüssel und den SPF-Eintrag von "
            "{domain}."
        ),
        "D2.title": "Fremder Absender nutzt {domain}",
        "D2.body": (
            "**{count}** Mail(s) von **{ip}** gaben sich als {domain} aus und "
            "sind an DMARC gescheitert. Deine Richtlinie weist Empfänger an, "
            "sie abzulehnen. Gehört die Quelle zu dir, trag ihre Adresse in "
            "den Optionen der Integration ein."
        ),
        "D3.dkim.title": "DKIM-Signatur {selector} scheitert bei {reporters}",
        "D3.dkim.body": (
            "DMARC besteht noch, weil ein anderes Verfahren greift, aber ohne "
            "Reserve. Ergebnis: `{result}`. Prüft dieser Berichtsabsender den "
            "Schlüsseltyp nicht, trag in den Optionen eine Ausnahme ein."
        ),
        "D3.dkim-missing.title": "Keine DKIM-Signatur in Berichten von {reporters}",
        "D3.dkim-missing.body": (
            "Mails von deinem Server **{ip}** trugen keine DKIM-Signatur von "
            "{domain}. DMARC hat nur dank SPF bestanden."
        ),
        "D3.spf.title": "SPF scheitert beim eigenen Mailserver ({reporters})",
        "D3.spf.body": (
            "SPF für {spf_domain} ergab `{result}` für **{ip}**. DMARC hat nur "
            "dank DKIM bestanden. Prüfe, ob der SPF-Eintrag diese Adresse enthält."
        ),
        "D4.title": "DMARC-Richtlinie weicht ab: {field}={found}",
        "D4.body": (
            "Die Berichtsabsender fanden `{field}={found}` im DMARC-Eintrag "
            "von {domain}, erwartet ist `{field}={expected}`. Prüfe den "
            "TXT-Eintrag `_dmarc.{domain}`."
        ),
        "T1.title": "TLS-Zustellung an {domain} scheitert: {result_type}",
        "T1.body": (
            "**{count}** Sitzung(en) konnten nicht per TLS aufgebaut werden. "
            "Mails an dich kommen eventuell verspätet, gar nicht oder "
            "unverschlüsselt an."
        ),
        "T2.title": "Keine MTA-STS- oder DANE-Richtlinie für {domain}",
        "T2.body": (
            "Mails an dich werden nur mit opportunistischem TLS zugestellt. "
            "Das ist ein Hinweis und wird nicht wiederholt; abschalten lässt "
            "er sich in den Optionen."
        ),
        "R1.title": "Seit {days} Tagen keine DMARC-Berichte von {reporter}",
        "R1.body": (
            "Entweder gingen keine Mails an {reporter}, die `rua`-Adresse im "
            "DMARC-Eintrag ist kaputt, oder Stalwart fängt die Berichte nicht "
            "mehr ab."
        ),
        "resolved.title": "Behoben: {title}",
        "resolved.body": "Taucht in den Berichten nicht mehr auf.",
        "resolved.body.R1": "Es kommen wieder Berichte an.",
        "label.domain": "Domain",
        "label.source": "Quelle",
        "label.host": "Host",
        "label.messages": "Mails",
        "label.sessions": "Sitzungen",
        "label.reporters": "Gemeldet von",
        "label.first_seen": "Zuerst gesehen",
        "label.last_seen": "Zuletzt gesehen",
        "label.mx": "MX-Host",
        "label.reason": "Grund",
        "label.last_received": "Letzter Bericht",
        "never": "nie",
    },
}

TAGS = {
    RULE_OWN_DMARC_FAIL: "dmarc",
    RULE_FOREIGN_DMARC_FAIL: "dmarc",
    RULE_OWN_PARTIAL_FAIL: "dmarc",
    RULE_POLICY_MISMATCH: "dmarc",
    RULE_REPORTS_MISSING: "dmarc",
    RULE_TLS_FAILURE: "tls-rpt",
    RULE_TLS_NO_POLICY: "tls-rpt",
}


class _Defaults(dict[str, Any]):
    """Placeholders a problem does not carry render as a dash."""

    def __missing__(self, key: str) -> str:
        return "–"


def _texts(language: str) -> dict[str, str]:
    return TEXTS["de"] if language.lower().startswith("de") else TEXTS["en"]


def _text_key(problem: dict[str, Any], part: str) -> str:
    rule = problem["rule"]
    if rule == RULE_OWN_PARTIAL_FAIL:
        return f"{rule}.{problem['params'].get('mechanism', 'dkim')}.{part}"
    return f"{rule}.{part}"


def _field(label: str, value: Any, fmt: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"label": label, "value": str(value)}
    if fmt:
        item["format"] = fmt
    return item


def _values(problem: dict[str, Any], domain: str) -> _Defaults:
    params = problem.get("params") or {}
    return _Defaults(
        {
            **{k: v for k, v in params.items() if v is not None},
            "domain": domain,
            "count": problem.get("count", 0),
            "reporters": ", ".join(problem.get("reporters") or []) or "–",
        }
    )


def problem_title(problem: dict[str, Any], domain: str, language: str) -> str:
    """The headline of a problem, as the problem sensor lists it."""
    texts = _texts(language)
    return texts[_text_key(problem, "title")].format_map(_values(problem, domain))


def build_message(
    notification: Notification, domain: str, channel: str, language: str
) -> dict[str, Any]:
    """Service data for ``lognotifier.send``."""
    texts = _texts(language)
    problem = notification.problem
    params = problem.get("params") or {}
    values = _values(problem, domain)
    title = texts[_text_key(problem, "title")].format_map(values)
    body = texts[_text_key(problem, "body")].format_map(values)
    level = problem["level"]
    if notification.event == EVENT_RESOLVED:
        title = texts["resolved.title"].format(title=title)
        body = texts.get(f"resolved.body.{problem['rule']}", texts["resolved.body"])
        level = LEVEL_INFO

    rows: list[list[dict[str, Any]]] = [[_field(texts["label.domain"], domain)]]
    if params.get("ip"):
        source = [_field(texts["label.source"], params["ip"])]
        if params.get("host"):
            source.append(_field(texts["label.host"], params["host"]))
        rows.append(source)
    if params.get("mx_host"):
        rows.append([_field(texts["label.mx"], params["mx_host"])])
    if params.get("reason"):
        rows.append([_field(texts["label.reason"], params["reason"])])
    if problem["rule"] == RULE_REPORTS_MISSING:
        last = params.get("last_received")
        rows.append(
            [
                _field(texts["label.last_received"], last, "datetime")
                if last
                else _field(texts["label.last_received"], texts["never"])
            ]
        )
    else:
        counted = "label.sessions" if problem.get("kind") == "tls" else "label.messages"
        rows.append(
            [
                _field(texts[counted], problem.get("count", 0)),
                _field(texts["label.reporters"], values["reporters"]),
            ]
        )
        rows.append(
            [
                _field(texts["label.first_seen"], problem["first_seen"], "datetime"),
                _field(texts["label.last_seen"], problem["last_seen"], "datetime"),
            ]
        )

    return {
        "channel_id": channel,
        "level": level,
        "title": title,
        "content": body,
        "source": NOTIFY_SOURCE,
        "tags": [TAGS.get(problem["rule"], "dmarc"), problem["rule"]],
        "blocks": [{"type": "fields", "rows": rows}],
    }
