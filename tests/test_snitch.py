import gzip
import http.client
import json
import smtplib
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from snitch import __main__ as cli
from snitch import config, evidence, lookup, mailer, pipeline
from snitch.server import make_server
from snitch.store import Store

ATTACKER = "78.47.241.202"
NOW = int(datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc).timestamp())
LOG_TIME = "07/Nov/2026:11:59:00 +0000"


def make_alert(ip=ATTACKER, scenario="crowdsecurity/http-sensitive-files", **overrides):
    alert = {
        "scenario": scenario,
        "simulated": False,
        "events_count": 2,
        "start_at": "2026-11-07T11:58:00.123456789Z",
        "stop_at": "2026-11-07T11:59:30Z",
        "source": {
            "scope": "Ip",
            "value": ip,
            "ip": ip,
            "as_number": "24940",
            "as_name": "Hetzner Online GmbH",
            "cn": "DE",
        },
        "decisions": [
            {"origin": "crowdsec", "type": "ban", "scope": "Ip", "value": ip, "duration": "4h"}
        ],
        "events": [
            {
                "timestamp": "2026-11-07T11:59:00Z",
                "meta": [
                    {"key": "http_path", "value": "/.env"},
                    {"key": "http_status", "value": "404"},
                    {"key": "target_fqdn", "value": "private.example.org"},
                ],
            }
        ],
    }
    alert.update(overrides)
    return alert


def lookups(hosting=None, contacts=("abuse@host.example",), source="abusix"):
    info = {"hosting": True, "mobile": False, "proxy": False} if hosting is None else hosting
    return SimpleNamespace(
        hosting_info=lambda ip: info,
        find_contacts=lambda ip: (list(contacts), source),
    )


@pytest.fixture
def cfg(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    return replace(
        config.load({"SNITCH_TOKEN": "secret"}),
        data_dir=tmp_path,
        log_globs=(str(logs / "access.log*"),),
        mail_from="reports@example.net",
        smtp_host="smtp.example.net",
        reporter_name="Example Reports",
    )


@pytest.fixture
def store(cfg):
    return Store(cfg.db_path)


class FakeSend:
    def __init__(self, error=None):
        self.messages = []
        self.error = error

    def __call__(self, cfg, message):
        if self.error:
            raise self.error
        self.messages.append(message)


def attachment_text(path):
    message = mailer.parse(Path(path).read_bytes())
    attachment = next(message.iter_attachments())
    return message, attachment.get_content()


# Filtering


@pytest.mark.parametrize(
    "alert, reason",
    [
        (make_alert(simulated=True), "simulated"),
        (make_alert(decisions=[]), "no_local_ban"),
        (
            make_alert(decisions=[{"origin": "cscli", "type": "ban"}]),
            "no_local_ban",
        ),
        (
            make_alert(decisions=[{"origin": "crowdsec", "type": "captcha"}]),
            "no_local_ban",
        ),
        (make_alert(ip="192.168.1.5"), "non_public_ip"),
        (make_alert(ip="not-an-ip"), "invalid_ip"),
        (make_alert(scenario="crowdsecurity/http-probing"), "scenario_not_selected"),
        (make_alert(scenario="crowdsecurity/http-crawl-non_statics"), "scenario_not_selected"),
        (make_alert(scenario="crowdsecurity/http-cve-probing"), "scenario_not_selected"),
        (
            make_alert(source={"scope": "Range", "value": "78.47.0.0/16"}),
            "not_single_ip",
        ),
    ],
)
def test_rejected_alerts(cfg, alert, reason):
    assert pipeline.rejection_reason(cfg, alert) == reason


@pytest.mark.parametrize(
    "scenario",
    [
        "crowdsecurity/CVE-2021-41773",
        "crowdsecurity/grafana-cve-2021-43798",
        "crowdsecurity/apache_log4j2_cve-2021-44228",
        "crowdsecurity/ssh-cve-2024-6387",
        "crowdsecurity/netgear_rce",
        "crowdsecurity/vmware-vcenter-vmsa-2021-0027",
        "crowdsecurity/http-backdoors-attempts",
        "crowdsecurity/http-sensitive-files",
        "crowdsecurity/ssh-bf",
        "crowdsecurity/ssh-slow-bf_user-enum",
    ],
)
def test_selected_scenarios(cfg, scenario):
    assert pipeline.rejection_reason(cfg, make_alert(scenario=scenario)) is None


def test_allowlisted_network(cfg):
    import ipaddress

    allowed = replace(cfg, allow_networks=(ipaddress.ip_network("78.47.0.0/16"),))
    assert pipeline.rejection_reason(allowed, make_alert()) == "allowlisted"


@pytest.mark.parametrize(
    "info, reason",
    [
        ({"hosting": False, "mobile": False, "proxy": False}, "not_hosting"),
        ({"hosting": True, "mobile": True, "proxy": False}, "mobile_network"),
        ({"hosting": True, "mobile": False, "proxy": True}, "proxy_vpn_tor"),
    ],
)
def test_non_datacenter_addresses_are_skipped(cfg, store, info, reason):
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups(hosting=info))
    assert store.get(report)["reason"] == reason


def test_hosting_check_can_be_disabled(cfg, store):
    relaxed = replace(cfg, require_hosting=False)
    def never(ip):
        raise AssertionError("hosting lookup must not run")
    probe = SimpleNamespace(
        hosting_info=never, find_contacts=lambda ip: (["abuse@host.example"], "rdap")
    )
    report = pipeline.process_alert(relaxed, store, make_alert(), NOW, probe)
    assert store.get(report)["status"] == "dry_run"


def test_no_contact_is_skipped(cfg, store):
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups(contacts=()))
    assert store.get(report)["reason"] == "no_abuse_contact"


def test_no_evidence_is_skipped(cfg, store):
    report = pipeline.process_alert(cfg, store, make_alert(events=[]), NOW, lookups())
    assert store.get(report)["reason"] == "no_evidence"


# Evidence


WINDOW = timedelta(minutes=60)
START = datetime(2026, 11, 7, 11, 58, tzinfo=timezone.utc)
STOP = datetime(2026, 11, 7, 11, 59, tzinfo=timezone.utc)


def nginx_line(ip=ATTACKER, path="/.env", time=LOG_TIME, agent="curl"):
    return f'{ip} - - [{time}] "GET {path} HTTP/1.1" 404 10 "-" "{agent}"\n'


def collect(cfg, ip=ATTACKER, limit=200, redact=()):
    return evidence.collect_log_lines(cfg.log_globs, ip, START, STOP, WINDOW, limit, redact)


def write_log(cfg, text, name="access.log"):
    (Path(cfg.log_globs[0]).parent / name).write_text(text)


def test_collects_plain_and_rotated_logs_in_time_order(cfg):
    write_log(cfg, nginx_line(path="/new"))
    rotated = Path(cfg.log_globs[0]).parent / "access.log.1.gz"
    with gzip.open(rotated, "wt") as handle:
        handle.write(nginx_line(path="/old", time="07/Nov/2026:11:30:00 +0000"))
    lines, dropped = collect(cfg)
    assert dropped == 0
    assert "/old" in lines[0] and "/new" in lines[1]


def test_address_in_user_agent_does_not_match(cfg):
    """A client must not be able to frame another address via its own headers."""
    write_log(cfg, nginx_line(ip="203.0.113.9", agent=f"{ATTACKER} from {ATTACKER}"))
    assert collect(cfg) == ([], 0)


def test_line_with_leading_host_field_matches(cfg):
    write_log(cfg, f"www.example.org:443 {nginx_line()}")
    assert len(collect(cfg)[0]) == 1


def test_address_in_host_field_does_not_match(cfg):
    """The Host header is client-controlled too, and can precede the real client."""
    write_log(cfg, f"{ATTACKER} {nginx_line(ip='203.0.113.9')}")
    assert collect(cfg) == ([], 0)
    assert len(collect(cfg, ip="203.0.113.9")[0]) == 1


def test_longer_address_with_same_prefix_does_not_match(cfg):
    write_log(cfg, nginx_line(ip=ATTACKER + "9"))
    assert collect(cfg) == ([], 0)


def test_lines_outside_window_are_excluded(cfg):
    write_log(cfg, nginx_line(time="07/Nov/2026:09:00:00 +0000"))
    assert collect(cfg) == ([], 0)


def test_time_offset_is_respected(cfg):
    write_log(cfg, nginx_line(time="07/Nov/2026:14:59:00 +0300"))
    assert len(collect(cfg)[0]) == 1


def test_limit_keeps_newest_lines(cfg):
    write_log(
        cfg,
        nginx_line(path="/first", time="07/Nov/2026:11:00:00 +0000")
        + nginx_line(path="/last"),
    )
    lines, dropped = collect(cfg, limit=1)
    assert dropped == 1 and "/last" in lines[0]


def test_sanitize_removes_secrets_controls_and_non_ascii():
    line = evidence.sanitize(
        'GET /a?id=1&api_key=abc&Token=def "\x1b[31mпривет\x07" example.org\r\n',
        ("EXAMPLE.org",),
    )
    assert "abc" not in line and "def" not in line and "id=1" in line
    assert "\x1b" not in line and "\x07" not in line
    assert line.isascii()
    assert "example.org" not in line and "[redacted]" in line


def test_event_lines_exclude_private_fields():
    lines = evidence.event_lines(make_alert()["events"])
    assert "http_path=/.env" in lines[0]
    assert "private.example.org" not in lines[0]


# Report contents


def test_report_contents(cfg, store):
    write_log(cfg, nginx_line())
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    message, attached = attachment_text(store.get(report)["eml_path"])
    assert message["To"] == "abuse@host.example"
    assert ATTACKER in message["Subject"]
    assert message["Auto-Submitted"] == "auto-generated"
    body = message.get_body().get_content()
    assert "AS24940 Hetzner Online GmbH" in body
    assert "2026-11-07 11:58:00 UTC" in body
    assert "Abusix" in body
    assert nginx_line().strip() in attached
    assert "http_path=/.env" in attached


def test_hostile_scenario_cannot_inject_headers(cfg, store):
    hostile = make_alert(scenario="x/cve-1\r\nBcc: victim@example.org")
    report = pipeline.process_alert(cfg, store, hostile, NOW, lookups())
    raw = Path(store.get(report)["eml_path"]).read_bytes()
    assert b"\nBcc:" not in raw


def test_report_file_is_private(cfg, store):
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    assert Path(store.get(report)["eml_path"]).stat().st_mode & 0o077 == 0


# Modes


def test_dry_run_never_sends(cfg, store):
    send = FakeSend()
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    assert store.get(report)["status"] == "dry_run"
    # Even a row forced into the queue must not leave while in dry-run.
    store.transition(report, ("dry_run",), "queued", NOW)
    pipeline.send_due(cfg, store, NOW, send)
    pipeline.send_digest(cfg, store, NOW, send)
    assert send.messages == []
    assert store.get(report)["status"] == "queued"


def test_approve_waits_for_approval(cfg, store):
    approving = replace(cfg, mode="approve")
    send = FakeSend()
    report = pipeline.process_alert(approving, store, make_alert(), NOW, lookups())
    pipeline.send_due(approving, store, NOW, send)
    assert send.messages == [] and store.get(report)["status"] == "pending"
    store.transition(report, ("pending", "failed"), "queued", NOW)
    pipeline.send_due(approving, store, NOW, send)
    assert len(send.messages) == 1 and store.get(report)["status"] == "sent"


def test_rejected_report_is_never_sent_and_stays_deduplicated(cfg, store):
    approving = replace(cfg, mode="approve")
    send = FakeSend()
    report = pipeline.process_alert(approving, store, make_alert(), NOW, lookups())
    store.transition(report, ("pending",), "rejected", NOW)
    pipeline.send_due(approving, store, NOW, send)
    again = pipeline.process_alert(approving, store, make_alert(), NOW + 60, lookups())
    assert send.messages == [] and store.get(again)["reason"] == "duplicate"


def test_auto_sends_and_does_not_resend(cfg, store):
    automatic = replace(cfg, mode="auto")
    send = FakeSend()
    pipeline.process_alert(automatic, store, make_alert(), NOW, lookups())
    pipeline.send_due(automatic, store, NOW, send)
    pipeline.send_due(automatic, store, NOW + 60, send)
    assert len(send.messages) == 1


def test_real_mode_requires_smtp_settings():
    with pytest.raises(config.ConfigError):
        config.load({"SNITCH_MODE": "auto", "SNITCH_TOKEN": "x"}).validate_for_serving()
    with pytest.raises(config.ConfigError):
        config.load({}).validate_for_serving()
    config.load({"SNITCH_TOKEN": "x"}).validate_for_serving()


def test_default_mode_is_dry_run():
    assert config.load({}).mode == "dry-run"


# Rate limits and deduplication


def test_repeat_ban_of_same_ip_is_deduplicated(cfg, store):
    pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    again = pipeline.process_alert(cfg, store, make_alert(), NOW + 3600, lookups())
    assert store.get(again)["reason"] == "duplicate"


def test_ip_can_be_reported_again_after_dedupe_period(cfg, store):
    pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    later = NOW + (cfg.dedupe_days + 1) * 86400
    report = pipeline.process_alert(cfg, store, make_alert(), later, lookups())
    assert store.get(report)["status"] == "dry_run"


def test_rehearsal_does_not_suppress_real_reports(cfg, store):
    pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    automatic = replace(cfg, mode="auto")
    report = pipeline.process_alert(automatic, store, make_alert(), NOW + 60, lookups())
    assert store.get(report)["status"] == "queued"


def test_contact_limit(cfg, store):
    limited = replace(cfg, max_per_contact_day=1)
    pipeline.process_alert(limited, store, make_alert(), NOW, lookups())
    report = pipeline.process_alert(limited, store, make_alert(ip="78.47.241.203"), NOW, lookups())
    assert store.get(report)["reason"] == "contact_limit"
    other = pipeline.process_alert(
        limited, store, make_alert(ip="78.47.241.204"), NOW, lookups(contacts=("abuse@other.example",))
    )
    assert store.get(other)["status"] == "dry_run"


def test_daily_limit(cfg, store):
    limited = replace(cfg, max_per_day=1)
    pipeline.process_alert(limited, store, make_alert(), NOW, lookups())
    report = pipeline.process_alert(
        limited, store, make_alert(ip="78.47.241.203"), NOW, lookups(contacts=("abuse@other.example",))
    )
    assert store.get(report)["reason"] == "daily_limit"


def test_send_time_limit_holds_a_large_approved_backlog(cfg, store):
    approving = replace(cfg, mode="approve", max_per_day=1)
    send = FakeSend()
    first = pipeline.process_alert(approving, store, make_alert(), NOW - 3 * 86400, lookups())
    second = pipeline.process_alert(
        approving, store, make_alert(ip="78.47.241.203"), NOW - 86400, lookups()
    )
    store.transition(first, ("pending",), "queued", NOW)
    store.transition(second, ("pending",), "queued", NOW)
    pipeline.send_due(approving, store, NOW, send)
    assert len(send.messages) == 1
    assert store.get(second)["status"] == "queued"
    assert store.get(second)["reason"] == "waiting_for_rate_limit"


# Failures


def test_transient_lookup_failure_is_retried_then_given_up(cfg, store):
    def boom(ip):
        raise lookup.TransientLookupError("down")

    failing = SimpleNamespace(hosting_info=boom, find_contacts=boom)
    store.add_inbox(json.dumps(make_alert()), NOW)
    now = NOW
    for _ in range(pipeline.MAX_ATTEMPTS):
        rows = store.due_inbox(now + 10**7)
        assert len(rows) == 1
        pipeline.process_inbox(cfg, store, now + 10**7, failing)
        now += 10**7
    assert store.due_inbox(now + 10**8) == []
    assert store.list_reports()[0]["reason"] == "lookup_failed"


def test_bad_alert_does_not_block_queue(cfg, store):
    store.add_inbox('"not an alert"', NOW)
    store.add_inbox(json.dumps(make_alert()), NOW)
    pipeline.process_inbox(cfg, store, NOW, lookups())
    assert store.due_inbox(NOW) == []
    assert store.list_reports()[0]["status"] == "dry_run"


def test_refused_recipient_fails_without_retry(cfg, store):
    automatic = replace(cfg, mode="auto")
    report = pipeline.process_alert(automatic, store, make_alert(), NOW, lookups())
    send = FakeSend(smtplib.SMTPRecipientsRefused({}))
    pipeline.send_due(automatic, store, NOW, send)
    assert store.get(report)["status"] == "failed"


def test_relay_outage_retries_with_backoff_and_preserves_queue(cfg, store):
    automatic = replace(cfg, mode="auto")
    first = pipeline.process_alert(automatic, store, make_alert(), NOW, lookups())
    second = pipeline.process_alert(
        automatic, store, make_alert(ip="78.47.241.203"), NOW, lookups()
    )
    pipeline.send_due(automatic, store, NOW, FakeSend(OSError("connection refused")))
    assert store.get(first)["attempts"] == 1
    assert store.get(first)["next_try"] > NOW
    assert store.get(second)["attempts"] == 0
    assert store.get(first)["status"] == "queued"


# Digest


def test_digest_sent_once_a_day_only_when_something_is_pending(cfg, store):
    approving = replace(cfg, mode="approve", operator_email="me@example.net", digest_hour_utc=9)
    send = FakeSend()
    pipeline.send_digest(approving, store, NOW, send)
    assert send.messages == []
    pipeline.process_alert(approving, store, make_alert(), NOW, lookups())
    pipeline.send_digest(approving, store, NOW, send)
    pipeline.send_digest(approving, store, NOW + 60, send)
    assert len(send.messages) == 1
    assert send.messages[0]["To"] == "me@example.net"
    assert ATTACKER in send.messages[0].get_content()


# Time parsing


@pytest.mark.parametrize(
    "value",
    ["2026-11-07T11:58:00Z", "2026-11-07T11:58:00.123456789Z", "2026-11-07T14:58:00+03:00"],
)
def test_parse_time(value):
    fallback = datetime(2000, 1, 1, tzinfo=timezone.utc)
    assert pipeline.parse_time(value, fallback).replace(microsecond=0) == START


def test_parse_time_falls_back():
    fallback = datetime(2000, 1, 1, tzinfo=timezone.utc)
    assert pipeline.parse_time("garbage", fallback) == fallback
    assert pipeline.parse_time(None, fallback) == fallback


# Contact lookup


def test_clean_contacts_rejects_malformed_addresses():
    values = ["Abuse@Host.Example", "abuse@host.example", "x\r\nBcc: a@b.c", "no-at-sign", ""]
    assert lookup.clean_contacts(values) == ["abuse@host.example"]


def test_rdap_finds_nested_abuse_role():
    entities = [
        {
            "roles": ["registrant"],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@ripe.example"]]],
                }
            ],
        }
    ]
    assert lookup._rdap_abuse_emails(entities) == ["abuse@ripe.example"]


def test_find_contacts_falls_back_to_rdap(monkeypatch):
    def down(ip):
        raise lookup.TransientLookupError("dns down")

    monkeypatch.setattr(lookup, "abusix_contacts", down)
    monkeypatch.setattr(lookup, "rdap_contacts", lambda ip: ["abuse@rdap.example"])
    assert lookup.find_contacts(ATTACKER) == (["abuse@rdap.example"], "rdap")


def test_find_contacts_reports_failure_rather_than_no_contact(monkeypatch):
    def down(ip):
        raise lookup.TransientLookupError("down")

    monkeypatch.setattr(lookup, "abusix_contacts", down)
    monkeypatch.setattr(lookup, "rdap_contacts", lambda ip: [])
    with pytest.raises(lookup.TransientLookupError):
        lookup.find_contacts(ATTACKER)


# Webhook


@pytest.fixture
def webhook(cfg):
    server = make_server(replace(cfg, listen_host="127.0.0.1", listen_port=0))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def post(port, body, token="secret", path="/alert"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    connection.request("POST", path, body=body, headers=headers)
    status = connection.getresponse().status
    connection.close()
    return status


def test_webhook_persists_alerts(webhook, store):
    assert post(webhook, json.dumps([make_alert(), make_alert()])) == 202
    assert len(store.due_inbox(2**40)) == 2


@pytest.mark.parametrize("token", ["wrong", None])
def test_webhook_requires_token(webhook, store, token):
    assert post(webhook, "[]", token=token) == 401
    assert store.due_inbox(2**40) == []


@pytest.mark.parametrize("body", ["not json", '{"a": 1}', "[1]"])
def test_webhook_rejects_bad_bodies(webhook, body):
    assert post(webhook, body) == 400


def test_webhook_other_paths(webhook):
    assert post(webhook, "[]", path="/other") == 404
    connection = http.client.HTTPConnection("127.0.0.1", webhook, timeout=5)
    connection.request("GET", "/healthz")
    assert connection.getresponse().status == 200
    connection.close()


# Command line


@pytest.fixture
def cli_env(cfg, monkeypatch):
    monkeypatch.setenv("SNITCH_DATA_DIR", str(cfg.data_dir))
    monkeypatch.delenv("SNITCH_MODE", raising=False)


def test_cli_cannot_approve_in_dry_run(cfg, store, cli_env, capsys):
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    assert cli.main(["approve", str(report)]) == 1
    assert store.get(report)["status"] == "dry_run"


def test_cli_approve_all_and_reject(cfg, store, cli_env, monkeypatch):
    monkeypatch.setenv("SNITCH_MODE", "approve")
    approving = replace(cfg, mode="approve")
    first = pipeline.process_alert(approving, store, make_alert(), NOW, lookups())
    second = pipeline.process_alert(
        approving, store, make_alert(ip="78.47.241.203"), NOW, lookups()
    )
    assert cli.main(["reject", str(first)]) == 0
    assert cli.main(["approve", "--all"]) == 0
    assert store.get(first)["status"] == "rejected"
    assert store.get(second)["status"] == "queued"


def test_cli_approve_needs_a_target(cfg, store, cli_env, monkeypatch):
    monkeypatch.setenv("SNITCH_MODE", "approve")
    assert cli.main(["approve"]) == 1


def test_cli_show_and_list(cfg, store, cli_env, capsys):
    write_log(cfg, nginx_line())
    report = pipeline.process_alert(cfg, store, make_alert(), NOW, lookups())
    assert cli.main(["show", str(report)]) == 0
    shown = capsys.readouterr().out
    assert "abuse@host.example" in shown and "/.env" in shown
    assert cli.main(["list"]) == 0
    assert ATTACKER in capsys.readouterr().out
    assert cli.main(["stats"]) == 0
    assert "dry_run" in capsys.readouterr().out
