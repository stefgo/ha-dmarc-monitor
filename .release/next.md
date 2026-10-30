<!--
The hand-written part of the next release: what is new, why it matters, and
what an upgrade needs. It is placed above the list of commits in the GitHub
release and in CHANGELOG.md.

Write below this comment. Use "###" for headings -- "##" is the level of the
version itself. A release with nothing written here is refused. A beta from
dev keeps the text; the stable release from main empties this file again.

Nothing inside an HTML comment is published.
-->

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
