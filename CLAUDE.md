# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`ha-dmarc-monitor` is a Home Assistant integration (domain `dmarc_monitor`)
that reads the DMARC aggregate and SMTP TLS reports a Stalwart mail server
(0.16+) has received, evaluates them and posts problems to Log Notifier
(`lognotifier.send`, see the sibling project `ha-log-notifier`).

## Commands

```bash
# Python tests (no Home Assistant install required)
python3 -m venv .venv && .venv/bin/pip install -r requirements_test.txt
.venv/bin/python -m pytest
.venv/bin/pre-commit run --all-files && .venv/bin/mypy   # ruff runs as a hook

# The Home-Assistant-dependent tests, in their own environment
python3 -m venv .venv-ha && .venv-ha/bin/pip install -r requirements_test_ha.txt
.venv-ha/bin/python -m pytest -c pytest_ha.ini

# Record the answers of a real Stalwart server into .recorded/ (git-ignored)
python3 scripts/record_fixtures.py
```

ruff runs through `.pre-commit-config.yaml` (`pre-commit install` once); its
configuration is in `pyproject.toml`. The hook's `rev` is the only ruff version
in the project: CI runs `pre-commit run --all-files` instead of installing ruff
on its own.

`builddeploy.sh` rsyncs the integration to a Home Assistant host; it reads the
target from `.env`, see `.env.example`.

## Architecture

### Stalwart does the parsing

Stalwart intercepts reports sent to its inbound report addresses, decompresses
and parses them and stores them as JMAP objects `x:DmarcExternalReport` and
`x:TlsExternalReport` (30 days by default). `stalwart.py` reads them with
`/query` (ids) and `/get` (objects); the JMAP endpoint comes from the session
resource (`/.well-known/jmap`), falling back to `/jmap/` when a restricted key
may not read the session. Only the path of the session's `apiUrl` counts:
Stalwart puts its public hostname there, and the calls must go to the
configured URL (often the internal address). The `accountId` from the session
is added in `_call`, after discovery.

Stored reports never change, so the coordinator caches parsed reports by id and
fetches only new ids each cycle; ids that disappear (expired) are dropped.
When Stalwart is unreachable the coordinator sets `update_interval` to
`RETRY_INTERVAL` (5 min) and back to the fetch interval after the next success;
HA logs only the first of a series of failures.

### HA-free core

`const.py`, `models.py`, `parse.py`, `analysis.py`, `tracker.py` and
`messages.py` contain no Home Assistant imports — they are what the
framework-free suite in `tests/` covers and what mypy checks.
`tests/conftest.py` registers the component directory as the synthetic package
`dmarc_monitor_component` without executing `__init__.py`. Keep new pure logic
there.

- `parse.py` is lenient: an enum is compared through `norm()` (lower case,
  letters and digits only), so `noPolicyFound` and `no-policy-found` match. A
  report without its core fields raises `ParseError` and is skipped.
- Stalwart sends JSON lists as objects keyed by index (`{"0": …, "1": …}`);
  `_list()` turns them back into lists and also accepts plain arrays. The
  start of a DMARC period is `dateRangeBegin`, of a TLS period
  `dateRangeStart`. The fixtures follow the real shape — check new ones
  against `scripts/record_fixtures.py` output, not the JMAP docs.
- `analysis.evaluate()` is a pure function of reports, `RuleConfig` and `now`.
  It returns *findings* (keyed, merged across reports), statistics and the end
  of the newest report per kind.
- `tracker.ProblemTracker` turns successive evaluations into `opened` and
  `resolved` notifications and persists its state (HA `Store`, one file per
  entry). A finding is active while it occurred within `resolve_after`; an open
  problem resolves only when it is inactive **and** a newer report of the same
  kind exists. T2 is reported once (`silenced`); R1 describes the present and
  resolves as soon as the evaluation stops yielding it.
- `messages.py` holds the English and German texts — HA translations do not
  reach the content of a service call.

### Delivery

Notifications go into the tracker's persisted outbox first and are sent by
`coordinator.async_deliver()`, at most `MAX_DELIVERIES_PER_CYCLE` per cycle and
only once HA is running (`async_at_started`), because Log Notifier may load
after this integration. A failed delivery keeps the message and raises the
repair issue `delivery_failed_<entry_id>`; a successful one clears it.

### Entity IDs carry the domain

`entity.py` pre-sets `<platform>.<slug(domain)>_<key>`. Left to HA, the ID
would come from the translated entity name in the system language.

## Testing

- **`tests/`** — parser, rules, tracker, messages, manifest/translation
  consistency. Nothing but pytest.
- **`tests/ha/`** — config/options/reauth flow, setup, entities, delivery,
  diagnostics and the JMAP client against `aioclient_mock`. Stalwart is
  replaced by `FakeStalwart` (serves `tests/fixtures`), Log Notifier by a
  recording `lognotifier.send` service, time is frozen at 2026-10-29.

The fixtures are anonymized (`example.org`, `192.0.2.10`, `198.51.100.0/24`);
this repository is public, real addresses never go into it.

## Translations

`strings.json` is the source; `translations/en.json` and `translations/de.json`
must carry identical key sets (`test_integrity.py`). The message texts in
`messages.TEXTS` must carry the same keys in both languages as well.

Code, comments and docs are English; `translations/de.json` and the German
half of `messages.TEXTS` are the exceptions.

## Releasing

Same process as the other stefgo integrations: **Actions → Create Release**,
never a tag by hand; versions come from Conventional Commits, checked by
commitlint. `custom_components/dmarc_monitor/manifest.json` is the single
source of the version (`const.INTEGRATION_VERSION` reads it).

Before every commit, bring `.release/next.md` up to date with what the commit
changes for a user — in the same commit, below the HTML comment, with `###`
headings. Commits that change nothing for a user leave it alone.

Dependency updates come from Renovate, run centrally from
[stefgo/renovate-config](https://github.com/stefgo/renovate-config) (shared
preset and the runner, daily at noon). Renovate opens its pull requests on
Mondays — all minor and patch updates in one, each major update in its own,
because it merges only one pull request per run — and merges them itself,
squashed, on the first run after every check — Tests and Validate — is green;
a red one stays open for a human, and so does an update of the Python version
the workflows run on. Rules particular to this repository would go into
`.github/renovate.json5`. The commits are typed `ci(deps)` and `chore(deps)`
and release nothing by themselves.
