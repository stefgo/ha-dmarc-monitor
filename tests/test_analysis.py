"""The rules D1–D4, T1–T2 and R1, and the statistics."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime

from conftest import PACKAGE, add, fixture

analysis = importlib.import_module(f"{PACKAGE}.analysis")
parse = importlib.import_module(f"{PACKAGE}.parse")

NOW = datetime(2026, 10, 29, 1, 0, tzinfo=UTC)
OWN_IP = "192.0.2.10"
FOREIGN_IP = "198.51.100.7"


def config(**overrides):
    values = {
        "domain": "example.org",
        "own_networks": analysis.parse_networks([OWN_IP]),
        "dkim_exceptions": analysis.DEFAULT_EXCEPTIONS,
    }
    values.update(overrides)
    return analysis.RuleConfig(**values)


def dmarc(name="dmarc_google", edit=None):
    obj = fixture(name)
    if edit:
        edit(obj["report"])
    return parse.parse_dmarc_report(obj)


def tls(edit=None):
    obj = fixture("tls_google")
    if edit:
        edit(obj["report"])
    return parse.parse_tls_report(obj)


def rules(evaluation):
    return {f.key: f for f in evaluation.findings}


def run(dmarc_reports=(), tls_reports=(), **cfg):
    return analysis.evaluate(list(dmarc_reports), list(tls_reports), config(**cfg), NOW)


def test_the_three_sample_reports_are_clean_apart_from_the_hint():
    """Google's Ed25519 "fail" is excepted; only T2 remains, as INFO."""
    result = run([dmarc("dmarc_google"), dmarc("dmarc_mimecast")], [tls()])

    assert list(rules(result)) == ["T2"]
    assert rules(result)["T2"].level == "INFO"
    assert result.stats.messages == 3
    assert result.stats.pass_rate == 100.0


def test_without_the_exception_google_raises_d3():
    result = run([dmarc()], dkim_exceptions=())

    finding = rules(result)["D3:dkim:google.com:v1-ed25519-20261020"]
    assert finding.level == "WARNING"
    assert finding.params["selector"] == "v1-ed25519-20261020"


def test_the_exception_survives_key_rotation():
    def rotate(report):
        for sig in report["records"]["0"]["dkimResults"].values():
            sig["selector"] = sig["selector"].replace("20261020", "20270115")

    assert not rules(run([dmarc(edit=rotate)]))


def test_the_exception_does_not_cover_other_reporters():
    def ed_fails(report):
        report["records"]["0"]["dkimResults"]["0"]["result"] = "fail"

    found = rules(run([dmarc("dmarc_mimecast", edit=ed_fails)]))
    assert "D3:dkim:mimecast:v1-ed25519-20261020" in found


def test_d1_own_server_fails_dmarc():
    def broken(report):
        record = report["records"]["0"]
        record["evaluatedDkim"] = "fail"
        record["evaluatedSpf"] = "fail"

    finding = rules(run([dmarc(edit=broken)]))[f"D1:{OWN_IP}"]
    assert finding.level == "ERROR"
    assert finding.count == 1


def test_d2_foreign_source_fails_dmarc():
    def spoofed(report):
        add(
            report["records"],
            {
                "sourceIp": FOREIGN_IP,
                "count": 4,
                "evaluatedDisposition": "reject",
                "evaluatedDkim": "fail",
                "evaluatedSpf": "fail",
                "headerFrom": "example.org",
                "envelopeFrom": "",
            },
        )

    finding = rules(run([dmarc(edit=spoofed)]))[f"D2:{FOREIGN_IP}"]
    assert finding.level == "WARNING"
    assert finding.count == 4
    assert not rules(run([dmarc(edit=spoofed)], foreign_min_count=5))


def test_forwarded_mail_is_no_problem():
    """SPF fails at the forwarder, DKIM survives: DMARC passes."""

    def forwarded(report):
        add(
            report["records"],
            {
                "sourceIp": FOREIGN_IP,
                "count": 2,
                "evaluatedDisposition": "none",
                "evaluatedDkim": "pass",
                "evaluatedSpf": "fail",
                "headerFrom": "example.org",
                "envelopeFrom": "",
                "spfResults": [
                    {"domain": "forwarder.test", "scope": "mailFrom", "result": "fail"}
                ],
            },
        )

    assert not rules(run([dmarc(edit=forwarded)]))


def test_a_mailing_list_override_is_not_spoofing():
    def listed(report):
        add(
            report["records"],
            {
                "sourceIp": FOREIGN_IP,
                "count": 1,
                "evaluatedDisposition": "none",
                "evaluatedDkim": "fail",
                "evaluatedSpf": "fail",
                "headerFrom": "example.org",
                "envelopeFrom": "",
                "policyOverrideReasons": [{"overrideType": "MailingList"}],
            },
        )

    assert not rules(run([dmarc(edit=listed)]))


def test_d3_spf_fails_for_own_server_but_not_for_helo():
    def spf_fail(report):
        report["records"]["0"]["spfResults"] = [
            {"domain": "mail.example.org", "scope": "helo", "result": "none"},
            {"domain": "example.org", "scope": "mailFrom", "result": "softFail"},
        ]

    found = rules(run([dmarc(edit=spf_fail)]))
    assert list(found) == [f"D3:spf:google.com:{OWN_IP}"]
    assert found[f"D3:spf:google.com:{OWN_IP}"].params["result"] == "softfail"


def test_d4_policy_downgrade_and_test_mode():
    def downgraded(report):
        report["policyDisposition"] = "none"
        report["policySubdomainDisposition"] = "unspecified"
        report["policyTestingMode"] = True

    found = rules(run([dmarc(edit=downgraded)]))
    # sp is unspecified and inherits p=none.
    assert {"D4:p:none", "D4:sp:none", "D4:t:y"} <= set(found)
    assert found["D4:p:none"].params["expected"] == "reject"


def test_d4_follows_the_expected_policy():
    assert not rules(run([dmarc()], expected_p="reject", expected_sp="reject"))
    found = rules(run([dmarc()], expected_p="quarantine"))
    assert "D4:p:reject" in found


def test_t1_failed_sessions():
    def failing(report):
        report["policies"]["0"].update(
            policyType="sts",
            totalFailedSessions=5,
            failureDetails=[
                {
                    "resultType": "certificateExpired",
                    "failedSessionCount": 3,
                    "receivingMxHostname": "mail.example.org",
                }
            ],
        )

    found = rules(run([], [tls(edit=failing)]))
    assert found["T1:certificate-expired:mail.example.org"].count == 3
    # Two sessions without details still count.
    assert found["T1:unknown:-"].count == 2
    assert "T2" not in found


def test_t2_can_be_turned_off():
    assert not rules(run([], [tls()], notify_no_tls_policy=False, watched_reporters=()))


def test_r1_watched_reporter_goes_quiet():
    found = rules(run([dmarc("dmarc_mimecast")]))
    assert found["R1:google.com"].params["last_received"] is None

    found = rules(run([dmarc()], missing_days=1))
    assert found["R1:google.com"].params["last_received"].startswith("2026-10-27")
    assert not rules(run([dmarc()], missing_days=3))


def test_reports_for_other_domains_are_ignored():
    def other(report):
        report["policyDomain"] = "other.test"
        report["records"]["0"]["evaluatedDkim"] = "fail"
        report["records"]["0"]["evaluatedSpf"] = "fail"

    result = run([dmarc(edit=other)], watched_reporters=())
    assert not result.findings
    assert result.foreign_domain_reports == 1
    assert result.stats.messages == 0


def test_cidr_ranges_count_as_own():
    cfg = config(own_networks=analysis.parse_networks(["192.0.2.0/24"]))
    assert cfg.is_own(OWN_IP)
    assert not cfg.is_own(FOREIGN_IP)
    assert not cfg.is_own("not-an-ip")


def test_stats_name_the_latest_report():
    result = run([dmarc(), dmarc("dmarc_mimecast")], [tls()])
    assert result.stats.last_report_from == "Google Inc."
    assert result.stats.last_report_kind == "tls"
    assert result.stats.by_reporter["mimecast"].messages == 2
    assert result.stats.tls_successful == 1
