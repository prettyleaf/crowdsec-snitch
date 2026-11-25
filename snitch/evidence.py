"""Collects and sanitises the log lines attached to a report.

Everything here treats log content as attacker-controlled: request paths and
user agents are written by the very client being reported.
"""

from __future__ import annotations

import glob
import gzip
import re
from datetime import datetime, timedelta

MAX_LINE_CHARS = 2000
TRAILING_MARGIN = timedelta(minutes=5)

# Only these CrowdSec event fields are forwarded. Others, such as target_user or
# target_fqdn, can reveal details about the reporting server.
EVENT_KEYS = ("http_verb", "http_path", "http_status", "http_user_agent", "service", "log_type")

NGINX_TIME = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
SECRET_PARAM = re.compile(
    r"([?&;][^=&;\s\"]*(?:token|key|pass|secret|session|auth|sig)[^=&;\s\"]*=)[^&;\s\"]*",
    re.IGNORECASE,
)


def sanitize(line: str, redact: tuple[str, ...] = ()) -> str:
    """Make a line safe to mail: ASCII only, no secrets, bounded length."""
    text = line.rstrip("\r\n")[:MAX_LINE_CHARS]
    text = SECRET_PARAM.sub(r"\1[redacted]", text)
    for needle in redact:
        text = re.sub(re.escape(needle), "[redacted]", text, flags=re.IGNORECASE)
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    return "".join(c if " " <= c < "\x7f" else f"\\x{ord(c):02x}" for c in text)


def _open(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _line_time(line: str) -> datetime | None:
    match = NGINX_TIME.search(line)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def collect_log_lines(
    globs: tuple[str, ...],
    ip: str,
    start: datetime,
    stop: datetime,
    window: timedelta,
    limit: int,
    redact: tuple[str, ...] = (),
) -> tuple[list[str], int]:
    """Return the newest matching lines and how many older ones were dropped.

    A line belongs to the IP only if the client address field equals it. That field
    comes first in nginx's combined format, optionally after a host field, the same
    layout CrowdSec's nginx parser accepts. Searching the whole line would let any
    client put a third party's address in its user agent and have its own traffic
    reported against that third party.
    """
    client = re.compile(rf"(?:\S+ )?{re.escape(ip)} - ")
    earliest, latest = start - window, stop + TRAILING_MARGIN
    matches: list[tuple[datetime, str]] = []
    paths = sorted({path for pattern in globs for path in glob.glob(pattern)})
    for path in paths:
        try:
            with _open(path) as handle:
                for line in handle:
                    if not client.match(line):
                        continue
                    when = _line_time(line)
                    if when and earliest <= when <= latest:
                        matches.append((when, sanitize(line, redact)))
        except (OSError, EOFError):
            continue  # Rotated away or truncated while reading: use what remains.
    matches.sort(key=lambda item: item[0])
    dropped = max(0, len(matches) - limit)
    return [line for _, line in matches[dropped:]], dropped


def event_lines(events: list, redact: tuple[str, ...] = ()) -> list[str]:
    """Render CrowdSec's own event records, the only evidence for non-HTTP logs."""
    lines: list[str] = []
    for event in events or []:
        meta = {item.get("key"): item.get("value") for item in event.get("meta") or []}
        parts = [
            f"{key}={meta[key]}" for key in EVENT_KEYS if meta.get(key) not in (None, "")
        ]
        if parts:
            when = event.get("timestamp") or "unknown-time"
            lines.append(sanitize(f"{when} " + " ".join(parts), redact))
    return lines
