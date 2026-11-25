"""Turns a CrowdSec alert into a stored report, then delivers queued reports.

The mode alone decides what leaves the machine. In dry-run nothing is ever sent:
reports end as .eml files in the outbox, and send_due and send_digest do nothing.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from types import SimpleNamespace

from . import evidence, lookup, mailer
from .config import Config
from .store import Store

log = logging.getLogger("snitch")

MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 300
DAY = 86400

DEFAULT_LOOKUPS = SimpleNamespace(
    hosting_info=lookup.hosting_info, find_contacts=lookup.find_contacts
)

# Statuses that count, per mode, as "already reported" and against rate limits.
# Dry-run history is kept apart so a rehearsal doesn't suppress real reports later.
DEDUPE_STATUSES = {
    "dry-run": ("dry_run",),
    "approve": ("pending", "queued", "sent", "rejected"),
    "auto": ("pending", "queued", "sent", "rejected"),
}
LIMIT_STATUSES = {
    "dry-run": ("dry_run",),
    "approve": ("pending", "queued", "sent"),
    "auto": ("pending", "queued", "sent"),
}
NEW_REPORT_STATUS = {"dry-run": "dry_run", "approve": "pending", "auto": "queued"}

ATTACK_TYPES = (
    ("cve-", "attempt to exploit a known software vulnerability"),
    ("_rce", "attempt to exploit a known software vulnerability"),
    ("vmsa-", "attempt to exploit a known software vulnerability"),
    ("backdoor", "attempt to access web shells or backdoors"),
    ("sensitive-files", "scanning for sensitive files such as credentials and backups"),
    ("ssh-", "SSH password brute force"),
)


def parse_time(value: object, fallback: datetime) -> datetime:
    """Parse CrowdSec's RFC 3339 timestamps, which can carry nanoseconds."""
    if not isinstance(value, str):
        return fallback
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return fallback
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def rejection_reason(cfg: Config, alert: dict) -> str | None:
    """Local checks that need no network. Returns why to skip, or None."""
    if alert.get("simulated"):
        return "simulated"
    source = alert.get("source") or {}
    if str(source.get("scope", "")).lower() != "ip":
        return "not_single_ip"
    bans = [
        d
        for d in alert.get("decisions") or []
        if d.get("type") == "ban"
        and d.get("origin") == "crowdsec"
        and not d.get("simulated")
    ]
    if not bans:
        return "no_local_ban"
    try:
        ip = ipaddress.ip_address(source.get("ip") or source.get("value") or "")
    except ValueError:
        return "invalid_ip"
    if not ip.is_global:
        return "non_public_ip"
    if any(ip.version == net.version and ip in net for net in cfg.allow_networks):
        return "allowlisted"
    scenario = str(alert.get("scenario", "")).lower()
    if not any(fnmatchcase(scenario, pattern) for pattern in cfg.scenarios):
        return "scenario_not_selected"
    return None


def _attack_type(scenario: str) -> str:
    lowered = scenario.lower()
    for needle, description in ATTACK_TYPES:
        if needle in lowered:
            return description
    return "malicious activity"


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_report(
    cfg: Config,
    alert: dict,
    ip: str,
    contacts: list[str],
    contact_source: str,
    log_lines: list[str],
    dropped: int,
    events: list[str],
    start: datetime,
    stop: datetime,
):
    scenario = evidence.sanitize(str(alert.get("scenario", "unknown")))
    source = alert.get("source") or {}
    as_number = evidence.sanitize(str(source.get("as_number") or ""))
    as_name = evidence.sanitize(str(source.get("as_name") or ""))
    as_label = f"AS{as_number}" if as_number not in ("", "0") else ""
    network = " ".join(part for part in (as_label, as_name) if part)
    attack = _attack_type(scenario)
    count = alert.get("events_count")

    facts = [
        ("Source IP", ip),
        ("Network", network),
        ("Activity", attack),
        ("Detection", scenario),
        ("First seen", _utc(start)),
        ("Last seen", _utc(stop)),
        ("Events", str(count) if isinstance(count, int) else ""),
        ("Target", cfg.target),
    ]
    table = "\n".join(f"{name + ':':<12} {value}" for name, value in facts if value)

    attachment_name = f"evidence-{ip.replace(':', '_')}-{start:%Y%m%d}.txt"
    paragraphs = [
        "Hello,",
        "A host on your network attacked a server we operate. Our intrusion "
        "prevention system (CrowdSec) detected the activity and blocked the "
        "address. This report was generated automatically.",
        table,
        f"The relevant log entries are attached as {attachment_name}.",
        "The host may itself be compromised, so its owner may be unaware of "
        "this. Please investigate and take the action you consider appropriate.",
    ]
    if cfg.mail_reply_to:
        paragraphs.append(
            f"If this report is wrong, please let us know at {cfg.mail_reply_to}."
        )
    if contact_source == "abusix":
        paragraphs.append("Abuse contact found via the Abusix Abuse Contact DB.")
    body = "\n\n".join(paragraphs) + "\n"

    subject = f"Abuse report: {attack} from {ip}"
    message = mailer.new_message(cfg, contacts, subject, body)

    sections = [f"Abuse report evidence for {ip}", "", table, ""]
    if log_lines:
        sections.append("--- Web server access log (times as logged) ---")
        if dropped:
            sections.append(f"[{dropped} older matching lines omitted]")
        sections.extend(log_lines)
        sections.append("")
    if events:
        sections.append("--- Events recorded by CrowdSec ---")
        sections.extend(events)
        sections.append("")
    message.add_attachment(
        "\n".join(sections), subtype="plain", filename=attachment_name, cte="base64"
    )
    return message


def _save_eml(cfg: Config, message) -> str:
    cfg.outbox.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = cfg.outbox / f"{uuid.uuid4().hex}.eml"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(message.as_bytes())
    return str(path)


def process_alert(
    cfg: Config, store: Store, alert: dict, now: int, lookups=DEFAULT_LOOKUPS
) -> int:
    """Store one report row for the alert and return its id.

    Raises lookup.TransientLookupError when a network lookup should be retried.
    """
    source = alert.get("source") or {}
    raw_ip = str(source.get("ip") or source.get("value") or "")
    scenario = evidence.sanitize(str(alert.get("scenario", "")))

    def skip(reason: str, ip: str = raw_ip, contacts: str = "") -> int:
        log.info("skipped report: reason=%s", reason)
        return store.add_report(
            ip=evidence.sanitize(ip)[:64],
            scenario=scenario,
            status="skipped",
            reason=reason,
            contacts=contacts,
            now=now,
        )

    reason = rejection_reason(cfg, alert)
    if reason:
        return skip(reason)

    ip = str(ipaddress.ip_address(raw_ip))
    since = now - cfg.dedupe_days * DAY
    if store.seen_since(ip, since, DEDUPE_STATUSES[cfg.mode]):
        return skip("duplicate", ip)

    if cfg.require_hosting:
        info = lookups.hosting_info(ip)
        if info.get("mobile"):
            return skip("mobile_network", ip)
        if info.get("proxy"):
            return skip("proxy_vpn_tor", ip)
        if not info.get("hosting"):
            return skip("not_hosting", ip)

    contacts, contact_source = lookups.find_contacts(ip)
    if not contacts:
        return skip("no_abuse_contact", ip)
    contact_key = ",".join(sorted(contacts))

    fallback = datetime.fromtimestamp(now, timezone.utc)
    start = parse_time(alert.get("start_at"), fallback)
    stop = parse_time(alert.get("stop_at"), fallback)
    log_lines, dropped = evidence.collect_log_lines(
        cfg.log_globs,
        ip,
        start,
        stop,
        timedelta(minutes=cfg.window_minutes),
        cfg.max_log_lines,
        cfg.redact,
    )
    events = evidence.event_lines(alert.get("events"), cfg.redact)
    if not log_lines and not events:
        return skip("no_evidence", ip, contact_key)

    statuses = LIMIT_STATUSES[cfg.mode]
    day_ago = now - DAY
    if store.count_created_since(day_ago, statuses) >= cfg.max_per_day:
        return skip("daily_limit", ip, contact_key)
    if store.count_created_since(day_ago, statuses, contact_key) >= cfg.max_per_contact_day:
        return skip("contact_limit", ip, contact_key)

    message = build_report(
        cfg, alert, ip, contacts, contact_source, log_lines, dropped, events, start, stop
    )
    eml_path = _save_eml(cfg, message)
    status = NEW_REPORT_STATUS[cfg.mode]
    report_id = store.add_report(
        ip=ip,
        scenario=scenario,
        status=status,
        contacts=contact_key,
        eml_path=eml_path,
        now=now,
    )
    log.info("report %d: status=%s ip=%s to=%s", report_id, status, ip, contact_key)
    return report_id


def process_inbox(cfg: Config, store: Store, now: int, lookups=DEFAULT_LOOKUPS) -> None:
    for row in store.due_inbox(now):
        try:
            alert = json.loads(row["payload"])
            process_alert(cfg, store, alert, now, lookups)
        except lookup.TransientLookupError as exc:
            attempts = row["attempts"] + 1
            log.warning("lookup failed, attempt %d: %s", attempts, exc)
            if attempts < MAX_ATTEMPTS:
                store.retry_inbox(row["id"], attempts, now + BACKOFF_SECONDS * 2**attempts)
                continue
            source = alert.get("source") or {}
            store.add_report(
                ip=evidence.sanitize(str(source.get("ip") or ""))[:64],
                scenario=evidence.sanitize(str(alert.get("scenario", ""))),
                status="skipped",
                reason="lookup_failed",
                now=now,
            )
        except Exception:
            # One malformed alert must not block the queue behind it.
            log.exception("could not process inbox row %d, dropping it", row["id"])
        store.delete_inbox(row["id"])


def send_due(cfg: Config, store: Store, now: int, send=mailer.send) -> None:
    if cfg.mode == "dry-run":
        return
    for row in store.due_queued(now):
        day_ago = now - DAY
        if (
            store.count_sent_since(day_ago) >= cfg.max_per_day
            or store.count_sent_since(day_ago, row["contacts"]) >= cfg.max_per_contact_day
        ):
            store.defer(row["id"], row["attempts"], now + 3600, "waiting_for_rate_limit")
            continue
        try:
            with open(row["eml_path"], "rb") as handle:
                message = mailer.parse(handle.read())
        except OSError as exc:
            store.mark_failed(row["id"], f"cannot read report: {exc.strerror}")
            continue
        try:
            send(cfg, message)
        except smtplib.SMTPRecipientsRefused:
            store.mark_failed(row["id"], "recipient_refused")
            log.warning("report %d: recipient refused", row["id"])
            continue
        except (smtplib.SMTPException, OSError) as exc:
            attempts = row["attempts"] + 1
            detail = f"{type(exc).__name__}: {exc}"[:200]
            log.warning("report %d: send attempt %d failed: %s", row["id"], attempts, detail)
            if attempts >= MAX_ATTEMPTS:
                store.mark_failed(row["id"], detail)
            else:
                store.defer(row["id"], attempts, now + BACKOFF_SECONDS * 2**attempts, detail)
            break  # The relay is the likely problem: leave the rest for later.
        store.mark_sent(row["id"], now)
        log.info("report %d: sent to %s", row["id"], row["contacts"])


def send_digest(cfg: Config, store: Store, now: int, send=mailer.send) -> None:
    """Once a day in approve mode, tell the operator that reports await review."""
    if cfg.mode != "approve" or not cfg.operator_email:
        return
    moment = datetime.fromtimestamp(now, timezone.utc)
    today = moment.strftime("%Y-%m-%d")
    if moment.hour < cfg.digest_hour_utc or store.get_meta("digest_date") == today:
        return
    if now < int(store.get_meta("digest_next_try") or 0):
        return
    rows = store.list_reports("pending", limit=100)
    if not rows:
        return
    lines = [f"{len(rows)} abuse report(s) await review:", ""]
    lines += [
        f"#{r['id']}  {r['ip']}  {r['scenario']}  ->  {r['contacts']}" for r in rows
    ]
    lines += [
        "",
        "Inspect:  docker exec crowdsec-snitch snitch show ID",
        "Approve:  docker exec crowdsec-snitch snitch approve ID [ID...]",
        "Reject:   docker exec crowdsec-snitch snitch reject ID [ID...]",
    ]
    message = mailer.new_message(
        cfg,
        [cfg.operator_email],
        f"crowdsec-snitch: {len(rows)} report(s) await review",
        "\n".join(lines) + "\n",
    )
    try:
        send(cfg, message)
    except (smtplib.SMTPException, OSError) as exc:
        log.warning("digest failed: %s", exc)
        store.set_meta("digest_next_try", str(now + 3600))
        return
    store.set_meta("digest_date", today)
