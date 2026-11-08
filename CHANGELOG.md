# Changelog

## [1.0.1](https://github.com/stefgo/ha-dmarc-monitor/compare/v1.0.0...v1.0.1) (2026-11-08)

### Fetch now

Each domain has a new **Fetch now** button (`button.example_org_refresh` for
example.org). It fetches the reports of that domain at once, from the device
page or a dashboard, and stays usable while Stalwart is unreachable, which is
when you need it. The service `dmarc_monitor.refresh` still fetches all domains.

### Back on track faster after an outage

- When Stalwart cannot be reached, the next attempt now follows after 5
  minutes instead of a full fetch interval (60 minutes by default). After a
  mail server reboot the integration leaves `cannot_connect` within minutes;
  the configured interval applies again after the next success.
- The calls now always go to the URL you configured. Stalwart advertises its
  public hostname in the JMAP session, and following it sent the calls
  through the external proxy even when the internal address was configured,
  so a proxy outage made Stalwart look unreachable.

Nothing to do when upgrading.

### Features

* **button:** add a "Fetch now" button per domain ([712a9b6](https://github.com/stefgo/ha-dmarc-monitor/commit/712a9b69e6fcd55e537b0ca26e18a3b939fe4375))

### Bug Fixes

* **coordinator:** retry after 5 minutes when Stalwart is unreachable ([dc0fca5](https://github.com/stefgo/ha-dmarc-monitor/commit/dc0fca55049e591d4ff5b41c1ce7f6142624bfa0))
* **stalwart:** send JMAP calls to the configured URL, not the session's host ([cb598f1](https://github.com/stefgo/ha-dmarc-monitor/commit/cb598f10021b1a6748742ddce4499a91b18e3898))

## 1.0.0 (2026-11-02)

### First release

DMARC Monitor reads the DMARC aggregate and SMTP TLS reports your Stalwart
mail server (0.16 or newer) has received and posts to Log Notifier when
something is wrong — and again when it is fixed:

- DMARC failing for your own mail server, or a single DKIM signature or SPF
  failing while DMARC still passes
- foreign sources sending as your domain
- a published policy that differs from the expected one
- failed TLS sessions towards your MX, and once a hint about a missing
  MTA-STS or DANE policy
- a reporter such as Google that stopped sending reports

Google's "fail" for Ed25519 DKIM signatures is excepted by default. Entities
per domain show the open problems, the DMARC pass rate, the message and TLS
counts of the last seven days and the time of the last report.

The Stalwart API key needs five permissions: `authenticate`,
`sysDmarcExternalReportGet`, `sysDmarcExternalReportQuery`,
`sysTlsExternalReportGet` and `sysTlsExternalReportQuery`. Setup checks
that the key may both query and fetch the reports.

### Features

* Evaluate DMARC and TLS reports ([29b75d5](https://github.com/stefgo/ha-dmarc-monitor/commit/29b75d5a2321b675449630f22bea0b108834bf6c))
* Read the reports from Stalwart and post problems to Log Notifier ([1ef8855](https://github.com/stefgo/ha-dmarc-monitor/commit/1ef8855ab8c67675afca51d4a0a2c14517b03ea5))

### Bug Fixes

* Check that the API key may also fetch reports ([c209d89](https://github.com/stefgo/ha-dmarc-monitor/commit/c209d8999e1a5b56489f868bb6eb80876b0e6706))
* Keep URLs out of the translation strings ([449d802](https://github.com/stefgo/ha-dmarc-monitor/commit/449d802004929b84c9707b795dec58c0f679e0c8))
* Read the reports in the shape Stalwart really sends ([85c0a50](https://github.com/stefgo/ha-dmarc-monitor/commit/85c0a50d405bced505793d62b074781ed73fcb9e))
