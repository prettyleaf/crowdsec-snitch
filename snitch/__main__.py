"""Command line: the service itself and the operator's review commands."""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
from datetime import datetime, timezone

from . import config, mailer, pipeline
from .store import Store

TICK_SECONDS = 30


def serve(cfg: config.Config) -> int:
    from .server import make_server

    cfg.validate_for_serving()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(cfg.db_path)
    server = make_server(cfg)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    logging.getLogger("snitch").info(
        "listening on %s:%d, mode=%s", cfg.listen_host, cfg.listen_port, cfg.mode
    )
    while True:
        try:
            now = int(time.time())
            pipeline.process_inbox(cfg, store, now)
            pipeline.send_due(cfg, store, now)
            pipeline.send_digest(cfg, store, now)
        except Exception:
            logging.getLogger("snitch").exception("worker tick failed")
        time.sleep(TICK_SECONDS)


def _when(epoch: int | None) -> str:
    if not epoch:
        return "-"
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M")


def cmd_list(store: Store, args) -> int:
    rows = store.list_reports(args.status, args.limit)
    for row in rows:
        print(
            f"{row['id']:>6}  {_when(row['created_at'])}  {row['status']:<8}  "
            f"{row['ip']:<39}  {row['scenario']}  {row['contacts'] or row['reason']}"
        )
    return 0


def cmd_stats(store: Store, args) -> int:
    for row in store.stats():
        print(f"{row['n']:>6}  {row['status']:<8}  {row['reason']}")
    return 0


def cmd_show(store: Store, args) -> int:
    row = store.get(args.id)
    if row is None or not row["eml_path"]:
        print(f"report {args.id} has no message", file=sys.stderr)
        return 1
    with open(row["eml_path"], "rb") as handle:
        message = mailer.parse(handle.read())
    for header in ("From", "To", "Reply-To", "Subject"):
        if message[header]:
            print(f"{header}: {message[header]}")
    for part in message.walk():
        if part.get_content_type() == "text/plain":
            name = part.get_filename()
            print(f"\n----- {name or 'body'} -----")
            print(part.get_content())
    return 0


def cmd_transition(cfg, store: Store, args, sources, target) -> int:
    if cfg.mode == "dry-run" and target == "queued":
        print("SNITCH_MODE is dry-run: nothing can be approved for sending", file=sys.stderr)
        return 1
    if args.all and args.ids:
        print("give report ids or --all, not both", file=sys.stderr)
        return 2
    ids = store.pending_ids() if args.all else args.ids
    if not ids:
        print("no reports selected", file=sys.stderr)
        return 1
    failed = 0
    now = int(time.time())
    for report_id in ids:
        if store.transition(report_id, sources, target, now):
            print(f"{report_id}: {target}")
        else:
            print(f"{report_id}: not in a state that allows this", file=sys.stderr)
            failed = 1
    return failed


def cmd_test_smtp(cfg: config.Config, args) -> int:
    message = mailer.new_message(
        cfg, [args.to], "crowdsec-snitch SMTP test", "SMTP settings work.\n"
    )
    mailer.send(cfg, message)
    print(f"sent to {args.to}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="snitch")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="run the webhook and worker")

    list_cmd = commands.add_parser("list", help="list recent reports")
    list_cmd.add_argument("--status")
    list_cmd.add_argument("--limit", type=int, default=50)

    commands.add_parser("stats", help="count reports by status and reason")

    show = commands.add_parser("show", help="print a report's message and evidence")
    show.add_argument("id", type=int)

    for name, help_text in (
        ("approve", "queue pending or failed reports for sending"),
        ("reject", "discard pending reports"),
    ):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("ids", nargs="*", type=int)
        sub.add_argument("--all", action="store_true", help="all pending reports")

    test = commands.add_parser("test-smtp", help="send one test message")
    test.add_argument("to")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    try:
        cfg = config.load()
        if args.command == "serve":
            return serve(cfg)
        if args.command == "test-smtp":
            return cmd_test_smtp(cfg, args)
        store = Store(cfg.db_path)
        if args.command == "list":
            return cmd_list(store, args)
        if args.command == "stats":
            return cmd_stats(store, args)
        if args.command == "show":
            return cmd_show(store, args)
        if args.command == "approve":
            return cmd_transition(cfg, store, args, ("pending", "failed"), "queued")
        return cmd_transition(cfg, store, args, ("pending",), "rejected")
    except config.ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
