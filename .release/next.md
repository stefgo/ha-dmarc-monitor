<!--
The hand-written part of the next release: what is new, why it matters, and
what an upgrade needs. It is placed above the list of commits in the GitHub
release and in CHANGELOG.md.

Write below this comment. Use "###" for headings -- "##" is the level of the
version itself. A release with nothing written here is refused. A beta from
dev keeps the text; the stable release from main empties this file again.

Nothing inside an HTML comment is published.
-->

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
