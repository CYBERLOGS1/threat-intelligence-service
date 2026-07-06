#!/usr/bin/env python3
"""
Threat Intel Service — a personal threat intelligence pipeline.

Usage:
    python ti_service.py update [--feed NAME]
    python ti_service.py check <ioc_value>
    python ti_service.py search <query>
    python ti_service.py stats
    python ti_service.py dashboard [--interval SECONDS]
    python ti_service.py serve [--host HOST] [--port PORT]
"""

import argparse
import sys

from rich.console import Console

import config
from core.database import TIDatabase
from core import feeds as feed_module
from core import checker
from core import dashboard as dash
from core import api

console = Console()


def cmd_update(args, db):
    targets = config.FEEDS
    if args.feed:
        if args.feed not in config.FEEDS:
            console.print(f"[red]Unknown feed:[/] {args.feed}. "
                          f"Available: {', '.join(config.FEEDS)}")
            sys.exit(1)
        targets = {args.feed: config.FEEDS[args.feed]}

    total = 0
    for name, meta in targets.items():
        if not meta.get("enabled", True):
            console.print(f"[dim]Skipping disabled feed: {name}[/]")
            continue
        console.print(f"[cyan]Pulling[/] {name} — {meta['description']}...")
        records, error = feed_module.fetch_and_parse(name, meta["url"])
        if error:
            console.print(f"  [red]FAILED:[/] {error}")
            db.record_feed_run(name, 0, "error", error)
            continue
        count = db.bulk_upsert(records)
        db.record_feed_run(name, count, "ok")
        console.print(f"  [green]OK[/] — {count} indicators ingested")
        total += count

    console.print(f"\n[bold green]Done.[/] {total} indicators processed this run.")


def cmd_check(args, db):
    result = checker.verdict(args.value, db)
    if not result["matches"]:
        console.print(f"[green]CLEAN[/] — no match found for [bold]{result['value']}[/] "
                       f"(guessed type: {result['ioc_type_guess']})")
        return

    console.print(f"[bold red]MALICIOUS[/] — {result['value']} "
                  f"(max confidence: {result['max_confidence']})\n")
    from rich.table import Table
    t = Table()
    t.add_column("Source")
    t.add_column("Type")
    t.add_column("Threat")
    t.add_column("Confidence", justify="right")
    t.add_column("Last Seen")
    for m in result["matches"]:
        t.add_row(
            m.get("source", ""),
            m.get("ioc_type", ""),
            m.get("threat_type") or "",
            str(m.get("confidence", "")),
            (m.get("last_seen") or "")[:19],
        )
    console.print(t)


def cmd_search(args, db):
    results = db.search(args.query)
    if not results:
        console.print(f"[yellow]No indicators matching[/] '{args.query}'")
        return
    from rich.table import Table
    t = Table(title=f"Search: {args.query}")
    t.add_column("Value", overflow="fold")
    t.add_column("Type")
    t.add_column("Source")
    t.add_column("Threat")
    t.add_column("Confidence", justify="right")
    for r in results:
        t.add_row(r["value"], r["ioc_type"], r["source"],
                  r.get("threat_type") or "", str(r.get("confidence", "")))
    console.print(t)


def cmd_stats(args, db):
    dash.render_once(db)


def cmd_dashboard(args, db):
    dash.live_dashboard(db, refresh_seconds=args.interval)


def cmd_serve(args, db):
    api.run_server(db, args.host, args.port)


def main():
    parser = argparse.ArgumentParser(description="Personal Threat Intelligence Service")
    sub = parser.add_subparsers(dest="command", required=True)

    p_update = sub.add_parser("update", help="Pull and ingest threat feeds")
    p_update.add_argument("--feed", help="Only update this specific feed")
    p_update.set_defaults(func=cmd_update)

    p_check = sub.add_parser("check", help="Check a single IOC (ip/domain/url/hash)")
    p_check.add_argument("value", help="The indicator value to check")
    p_check.set_defaults(func=cmd_check)

    p_search = sub.add_parser("search", help="Substring search across stored indicators")
    p_search.add_argument("query", help="Substring to search for")
    p_search.set_defaults(func=cmd_search)

    p_stats = sub.add_parser("stats", help="Print a one-shot summary")
    p_stats.set_defaults(func=cmd_stats)

    p_dash = sub.add_parser("dashboard", help="Launch the live auto-refreshing dashboard")
    p_dash.add_argument("--interval", type=int, default=5, help="Refresh interval in seconds")
    p_dash.set_defaults(func=cmd_dashboard)

    p_serve = sub.add_parser("serve", help="Run the HTTP query API for other tools")
    p_serve.add_argument("--host", default=config.API_HOST)
    p_serve.add_argument("--port", type=int, default=config.API_PORT)
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    db = TIDatabase(config.DB_PATH)
    args.func(args, db)


if __name__ == "__main__":
    main()
