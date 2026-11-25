"""Configuration, read entirely from environment variables."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

MODES = ("dry-run", "approve", "auto")

# High-signal scenarios only. Noisy ones such as http-probing and
# http-crawl-non_statics are deliberately left out. Matched case-insensitively.
DEFAULT_SCENARIOS = (
    "*cve-[0-9]*",  # Exploits of a named CVE, but not generic http-cve-probing.
    "crowdsecurity/netgear_rce",
    "crowdsecurity/vmware-vcenter-vmsa-*",
    "crowdsecurity/http-backdoors-attempts",
    "crowdsecurity/http-sensitive-files",
    "crowdsecurity/ssh-bf*",
    "crowdsecurity/ssh-slow-bf*",
)


class ConfigError(Exception):
    pass


def _list(value: str | None, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if value is None or not value.strip():
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _int(env: dict, name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None


def _bool(env: dict, name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


@dataclass(frozen=True)
class Config:
    mode: str = "dry-run"
    token: str = ""
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    data_dir: Path = Path("/data")
    log_globs: tuple[str, ...] = ("/logs/nginx/access.log*",)
    scenarios: tuple[str, ...] = DEFAULT_SCENARIOS
    allow_networks: tuple = ()
    require_hosting: bool = True
    dedupe_days: int = 30
    max_per_contact_day: int = 3
    max_per_day: int = 20
    window_minutes: int = 60
    max_log_lines: int = 200
    redact: tuple[str, ...] = ()
    target: str = ""
    reporter_name: str = "Abuse reports"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_user: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    mail_reply_to: str = ""
    operator_email: str = ""
    digest_hour_utc: int = 9

    @property
    def outbox(self) -> Path:
        return self.data_dir / "outbox"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "snitch.db"

    def require_smtp(self) -> None:
        if not self.smtp_host or not self.mail_from:
            raise ConfigError("SMTP_HOST and MAIL_FROM are required to send mail")

    def validate_for_serving(self) -> None:
        if not self.token:
            raise ConfigError("SNITCH_TOKEN is required")
        if self.mode != "dry-run":
            self.require_smtp()


def load(env: dict | None = None) -> Config:
    env = os.environ if env is None else env

    mode = env.get("SNITCH_MODE", "dry-run").strip() or "dry-run"
    if mode not in MODES:
        raise ConfigError(f"SNITCH_MODE must be one of {MODES}, got {mode!r}")

    security = env.get("SMTP_SECURITY", "starttls").strip().lower() or "starttls"
    if security not in ("starttls", "ssl"):
        raise ConfigError("SMTP_SECURITY must be starttls or ssl")

    try:
        allow = tuple(
            ipaddress.ip_network(item, strict=False)
            for item in _list(env.get("SNITCH_ALLOW_CIDRS"))
        )
    except ValueError as exc:
        raise ConfigError(f"SNITCH_ALLOW_CIDRS: {exc}") from None

    return Config(
        mode=mode,
        token=env.get("SNITCH_TOKEN", "").strip(),
        listen_port=_int(env, "SNITCH_PORT", 8080),
        data_dir=Path(env.get("SNITCH_DATA_DIR", "/data")),
        log_globs=_list(env.get("SNITCH_LOG_GLOBS"), ("/logs/nginx/access.log*",)),
        scenarios=tuple(
            s.lower() for s in _list(env.get("SNITCH_SCENARIOS"), DEFAULT_SCENARIOS)
        ),
        allow_networks=allow,
        require_hosting=_bool(env, "SNITCH_REQUIRE_HOSTING", True),
        dedupe_days=_int(env, "SNITCH_DEDUPE_DAYS", 30),
        max_per_contact_day=_int(env, "SNITCH_MAX_PER_CONTACT_DAY", 3),
        max_per_day=_int(env, "SNITCH_MAX_PER_DAY", 20),
        window_minutes=_int(env, "SNITCH_WINDOW_MINUTES", 60),
        max_log_lines=_int(env, "SNITCH_MAX_LOG_LINES", 200),
        redact=_list(env.get("SNITCH_REDACT")),
        target=env.get("SNITCH_TARGET", "").strip(),
        reporter_name=env.get("SNITCH_REPORTER_NAME", "Abuse reports").strip(),
        smtp_host=env.get("SMTP_HOST", "").strip(),
        smtp_port=_int(env, "SMTP_PORT", 587),
        smtp_security=security,
        smtp_user=env.get("SMTP_USER", "").strip(),
        smtp_password=env.get("SMTP_PASSWORD", ""),
        mail_from=env.get("MAIL_FROM", "").strip(),
        mail_reply_to=env.get("MAIL_REPLY_TO", "").strip(),
        operator_email=env.get("SNITCH_OPERATOR_EMAIL", "").strip(),
        digest_hour_utc=_int(env, "SNITCH_DIGEST_HOUR_UTC", 9),
    )
