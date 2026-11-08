# DMARC Monitor for Home Assistant

[![Release](https://img.shields.io/github/v/release/stefgo/ha-dmarc-monitor?style=flat-square)](https://github.com/stefgo/ha-dmarc-monitor/releases)
[![HACS: custom](https://img.shields.io/badge/HACS-custom-41BDF5?style=flat-square)](https://hacs.xyz/)
[![Home Assistant 2025.2+](https://img.shields.io/badge/Home%20Assistant-2025.2%2B-41BDF5?style=flat-square)](https://www.home-assistant.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](https://github.com/stefgo/ha-dmarc-monitor/blob/main/LICENSE)

Large mail providers send daily reports about the mail they received in your
domain's name: **DMARC aggregate reports** (who sent mail as your domain, did
SPF and DKIM pass) and **SMTP TLS reports** (could mail *to* you be delivered
encrypted). Nobody reads them. This integration does, and posts a message to
[Log Notifier](https://github.com/stefgo/ha-log-notifier) when something is
wrong — and another one when it is fixed.

It does not parse mail itself: [Stalwart](https://stalw.art) (0.16 or newer)
already intercepts, decompresses and stores incoming reports. The integration
reads them through Stalwart's JMAP management API with a read-only API key.

```
Google, Microsoft, … ──SMTP──▶ Stalwart (stores reports for 30 days)
                                   │  JMAP, API key with read permissions only
                                   ▼
                       DMARC Monitor (hourly) ──▶ entities
                                              └─▶ lognotifier.send
```

## What it detects

| Rule | Problem | Level |
| --- | --- | --- |
| D1 | **DMARC fails for your own mail server** — neither DKIM nor SPF passed aligned. Your keys or your SPF record are broken. | ERROR |
| D2 | **A foreign source sends as your domain** and fails DMARC — spoofing, or a sender of yours you forgot to list. | WARNING |
| D3 | **One mechanism fails for your own server** while DMARC still passes: a DKIM signature, a missing signature or SPF. | WARNING |
| D4 | **The published policy differs** from the expected one (`p`, `sp`, or test mode `t=y`). | ERROR |
| T1 | **TLS sessions to your MX failed**, with the RFC 8460 result type (`certificate-expired`, `starttls-not-supported`, …). | ERROR |
| T2 | **No MTA-STS or DANE policy** is published. Reported **once**, then never again. | INFO |
| R1 | **A watched reporter went quiet** (default: no report from google.com for 3 days). | INFO |
| — | **Resolved**: a reported problem has not occurred for 3 days *and* newer reports exist. | INFO |

Not a problem:

- **Forwarded mail.** SPF fails at a forwarder, DKIM survives, DMARC passes. A
  failure the reporter marks as forwarded or mailing list is not counted as
  spoofing either.
- **Google and Ed25519.** Google does not verify Ed25519 DKIM signatures (RFC
  8463) and reports them as `fail`, while other reporters verify them fine. The
  default exception `google.com *ed25519*` covers this. Selectors are matched
  by pattern because Stalwart rotates its DKIM keys and the selector names
  carry the date.
- **SPF for the HELO name.** DMARC aligns on MAIL FROM only.

A problem is reported once, when it appears. It stays open while it keeps
occurring and is resolved only when newer reports no longer show it — no
reports at all is no evidence that it went away.

## Requirements

- Home Assistant 2025.2 or newer
- Stalwart **0.16** or newer, receiving the reports (see below)
- [Log Notifier](https://github.com/stefgo/ha-log-notifier) with a channel for
  the messages

### Stalwart

1. **Reports are intercepted.** Stalwart analyses a message only if it is
   addressed to one of the *inbound report addresses* (Settings → MTA → Reports
   → General, default `postmaster@*`). The `rua=` address of your DMARC record
   and the address in `_smtp._tls` have to match one of them. The reports then
   show up under Management → Reports → Inbox.
2. **API key.** Create one with exactly these permissions:
   `authenticate` (*Sign in to the server*),
   `sysDmarcExternalReportGet`, `sysDmarcExternalReportQuery`,
   `sysTlsExternalReportGet`, `sysTlsExternalReportQuery`.
   If the key replaces the permissions of its account, the account has to hold
   them as well — a key only gets the listed permissions its account also has.
   Setup checks all of them and refuses a key that lacks one.
3. Optional: turn off *inbound report forwarding* so the reports no longer land
   in the mailbox as well.

## Installation

**HACS → ⋮ → Custom repositories** → `stefgo/ha-dmarc-monitor`, category
**Integration** → *Add*. Then install "DMARC Monitor" and restart Home
Assistant.

Manually: copy `custom_components/dmarc_monitor` to the `custom_components`
directory of your instance and restart.

## Setup

**Settings → Devices & services → Add integration → DMARC Monitor.**

1. **Server:** the URL of Stalwart's web interface and the API key.
2. **Domain:** the domain, your own sending servers (addresses or CIDR ranges,
   pre-filled with the address of the Stalwart host), the Log Notifier channel
   and the expected policy. Domain and policy are taken from the newest report
   where possible.

One entry per domain; several domains on the same server are several entries.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| Own sending servers | address of the server | Sources that count as yours (D1/D3) instead of foreign (D2) |
| Log Notifier channel | `alarm` | Where messages are posted |
| Expected policy `p` / `sp` | from the newest report | D4 compares against these |
| Fetch interval | 60 min | Reports arrive once a day per reporter; after a failed fetch the next try follows in 5 min |
| DKIM exceptions | `google.com *ed25519*` | One per line: reporter pattern and selector pattern |
| Foreign sources from | 1 message | D2 threshold |
| Watched reporters | `google.com` | R1; empty turns it off |
| Report missing after | 3 days | R1 |
| Resolved after | 3 days | Days without occurrence before a problem counts as resolved |
| MTA-STS/DANE hint | on | T2 |

## Entities

One device per domain. The entity IDs are derived from the domain, so
`example.org` gives:

| Entity | State |
| --- | --- |
| `binary_sensor.example_org_mail_problem` | on while a WARNING or ERROR is open; attribute `problems` lists the open ones |
| `sensor.example_org_dmarc_pass_rate` | % of messages that passed DMARC, last 7 days |
| `sensor.example_org_dmarc_messages` | messages in the reports, last 7 days; attributes per reporter |
| `sensor.example_org_tls_failed_sessions` | failed TLS sessions, last 7 days |
| `sensor.example_org_last_report` | time the newest report arrived |
| `sensor.example_org_api_status` | `ok`, `auth_failed` or `cannot_connect` (diagnostic) |

The service `dmarc_monitor.refresh` fetches the reports now.

## Messages

Every message goes to the configured Log Notifier channel with source
`dmarc-monitor` and the tags `dmarc` or `tls-rpt` plus the rule (`D2`, `T1`,
…), so a Log Notifier push blueprint can filter on them. The text follows the
language of the Home Assistant instance (English or German); the details —
source, host, count, reporters, period — are a field block below it.

If Log Notifier is missing or the channel does not exist, the messages wait
and a repair issue says so. They are sent once delivery works again, at most
ten per cycle.

## Limits

- **Anyone can send a report.** Stalwart accepts reports from unauthenticated
  senders, as the standards require. A forged report can raise a false alarm;
  the per-cycle limit keeps a flood of them from flooding Log Notifier as well.
- The statistics cover what Stalwart still holds — 30 days by default
  (`holdMtaReportsFor`).
- Reverse DNS names in messages come from the Home Assistant host's resolver.

## Development

See [CLAUDE.md](CLAUDE.md) for the commands and the architecture.
