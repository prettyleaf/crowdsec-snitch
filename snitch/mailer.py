"""Builds and sends mail. Provider-neutral: any authenticated SMTP relay works."""

from __future__ import annotations

import smtplib
import ssl
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid
from datetime import datetime, timezone

from .config import Config

TIMEOUT = 30


def new_message(cfg: Config, to: list[str], subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = formataddr((cfg.reporter_name, cfg.mail_from or "unset@invalid"))
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    domain = (cfg.mail_from.rpartition("@")[2]) or None
    message["Message-ID"] = make_msgid(domain=domain)
    # RFC 3834: asks mail systems not to reply automatically.
    message["Auto-Submitted"] = "auto-generated"
    if cfg.mail_reply_to:
        message["Reply-To"] = cfg.mail_reply_to
    message.set_content(body)
    return message


def parse(raw: bytes) -> EmailMessage:
    return message_from_bytes(raw, policy=policy.default)


def send(cfg: Config, message: EmailMessage) -> None:
    cfg.require_smtp()
    # A report may wait days for approval, so date it when it actually leaves.
    del message["Date"]
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    context = ssl.create_default_context()
    if cfg.smtp_security == "ssl":
        client = smtplib.SMTP_SSL(
            cfg.smtp_host, cfg.smtp_port, timeout=TIMEOUT, context=context
        )
    else:
        client = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=TIMEOUT)
    with client:
        if cfg.smtp_security == "starttls":
            client.starttls(context=context)
        if cfg.smtp_user:
            client.login(cfg.smtp_user, cfg.smtp_password)
        client.send_message(message, from_addr=cfg.mail_from)
