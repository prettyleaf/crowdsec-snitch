"""SQLite persistence. Each thread or process opens its own Store."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS inbox (
    id INTEGER PRIMARY KEY,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    scenario TEXT NOT NULL,
    contacts TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    eml_path TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    sent_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS reports_ip ON reports (ip, created_at);
CREATE INDEX IF NOT EXISTS reports_status ON reports (status, next_try);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Store:
    def __init__(self, path: Path | str):
        self.db = sqlite3.connect(path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        with self.db:
            self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # Inbox: raw alerts waiting to be processed.

    def add_inbox(self, payload: str, now: int) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO inbox (payload, next_try) VALUES (?, ?)", (payload, now)
            )

    def due_inbox(self, now: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM inbox WHERE next_try <= ? ORDER BY id", (now,)
        ).fetchall()

    def delete_inbox(self, row_id: int) -> None:
        with self.db:
            self.db.execute("DELETE FROM inbox WHERE id = ?", (row_id,))

    def retry_inbox(self, row_id: int, attempts: int, next_try: int) -> None:
        with self.db:
            self.db.execute(
                "UPDATE inbox SET attempts = ?, next_try = ? WHERE id = ?",
                (attempts, next_try, row_id),
            )

    # Reports.

    def add_report(
        self,
        *,
        ip: str,
        scenario: str,
        status: str,
        now: int,
        contacts: str = "",
        reason: str = "",
        eml_path: str = "",
    ) -> int:
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO reports"
                " (ip, scenario, contacts, status, reason, eml_path, created_at, next_try)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ip, scenario, contacts, status, reason, eml_path, now, now),
            )
        return cursor.lastrowid

    def get(self, report_id: int) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()

    def seen_since(self, ip: str, since: int, statuses: tuple[str, ...]) -> bool:
        marks = ",".join("?" * len(statuses))
        row = self.db.execute(
            f"SELECT 1 FROM reports WHERE ip = ? AND created_at >= ?"
            f" AND status IN ({marks}) LIMIT 1",
            (ip, since, *statuses),
        ).fetchone()
        return row is not None

    def count_created_since(
        self, since: int, statuses: tuple[str, ...], contacts: str | None = None
    ) -> int:
        marks = ",".join("?" * len(statuses))
        query = f"SELECT COUNT(*) FROM reports WHERE created_at >= ? AND status IN ({marks})"
        args: list = [since, *statuses]
        if contacts is not None:
            query += " AND contacts = ?"
            args.append(contacts)
        return self.db.execute(query, args).fetchone()[0]

    def count_sent_since(self, since: int, contacts: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM reports WHERE status = 'sent' AND sent_at >= ?"
        args: list = [since]
        if contacts is not None:
            query += " AND contacts = ?"
            args.append(contacts)
        return self.db.execute(query, args).fetchone()[0]

    def due_queued(self, now: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM reports WHERE status = 'queued' AND next_try <= ? ORDER BY id",
            (now,),
        ).fetchall()

    def list_reports(self, status: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
        if status:
            return self.db.execute(
                "SELECT * FROM reports WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return self.db.execute(
            "SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def pending_ids(self) -> list[int]:
        rows = self.db.execute(
            "SELECT id FROM reports WHERE status = 'pending' ORDER BY id"
        ).fetchall()
        return [row["id"] for row in rows]

    def stats(self) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT status, reason, COUNT(*) AS n FROM reports"
            " GROUP BY status, reason ORDER BY status, n DESC"
        ).fetchall()

    def transition(
        self, report_id: int, from_statuses: tuple[str, ...], to_status: str, now: int
    ) -> bool:
        marks = ",".join("?" * len(from_statuses))
        with self.db:
            cursor = self.db.execute(
                f"UPDATE reports SET status = ?, attempts = 0, next_try = ?, reason = ''"
                f" WHERE id = ? AND status IN ({marks})",
                (to_status, now, report_id, *from_statuses),
            )
        return cursor.rowcount == 1

    def mark_sent(self, report_id: int, now: int) -> None:
        with self.db:
            self.db.execute(
                "UPDATE reports SET status = 'sent', sent_at = ?, reason = '' WHERE id = ?",
                (now, report_id),
            )

    def mark_failed(self, report_id: int, reason: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE reports SET status = 'failed', reason = ? WHERE id = ?",
                (reason, report_id),
            )

    def defer(self, report_id: int, attempts: int, next_try: int, reason: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE reports SET attempts = ?, next_try = ?, reason = ? WHERE id = ?",
                (attempts, next_try, reason, report_id),
            )

    # Small key/value state.

    def get_meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
