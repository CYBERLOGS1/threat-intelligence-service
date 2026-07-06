"""
Rich terminal dashboard: overview stats, breakdown by type/source,
recent indicators, and last feed-run health.
"""

import time
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

console = Console()


def _stats_panel(stats):
    t = Table.grid(padding=(0, 2))
    t.add_column(justify="left", style="bold")
    t.add_column(justify="right")
    t.add_row("Total indicators", f"[bold cyan]{stats['total']}[/]")
    return Panel(t, title="[bold]Overview[/]", border_style="cyan")


def _by_type_table(stats):
    t = Table(title="By Type", border_style="magenta", show_lines=False)
    t.add_column("Type")
    t.add_column("Count", justify="right")
    for row in stats["by_type"]:
        t.add_row(row["ioc_type"], str(row["c"]))
    return t


def _by_source_table(stats):
    t = Table(title="By Source", border_style="green")
    t.add_column("Source")
    t.add_column("Count", justify="right")
    for row in stats["by_source"]:
        t.add_row(row["source"], str(row["c"]))
    return t


def _recent_table(db, limit=15):
    t = Table(title=f"Most Recently Seen ({limit})", border_style="yellow")
    t.add_column("Value", overflow="fold")
    t.add_column("Type")
    t.add_column("Source")
    t.add_column("Threat")
    t.add_column("Conf.", justify="right")
    t.add_column("Last Seen")
    for row in db.recent(limit):
        conf = row.get("confidence", 0)
        conf_style = "red" if conf >= 80 else ("yellow" if conf >= 50 else "white")
        t.add_row(
            row["value"],
            row["ioc_type"],
            row["source"],
            (row.get("threat_type") or "")[:30],
            f"[{conf_style}]{conf}[/]",
            (row.get("last_seen") or "")[:19],
        )
    return t


def _feed_health_table(stats):
    t = Table(title="Recent Feed Runs", border_style="blue")
    t.add_column("Feed")
    t.add_column("Time")
    t.add_column("Pulled", justify="right")
    t.add_column("Status")
    for row in stats["last_runs"]:
        status = row["status"]
        status_style = "green" if status == "ok" else "red"
        t.add_row(
            row["feed_name"],
            (row["run_time"] or "")[:19],
            str(row["records_pulled"]),
            f"[{status_style}]{status}[/]",
        )
    return t


def render_once(db):
    """Render a single static snapshot (used for `stats` command)."""
    stats = db.stats()
    console.print(_stats_panel(stats))
    console.print(_by_type_table(stats))
    console.print(_by_source_table(stats))
    console.print(_recent_table(db))
    console.print(_feed_health_table(stats))


def build_layout(db):
    stats = db.stats()
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=5),
        Layout(name="middle", size=12),
        Layout(name="bottom"),
    )
    layout["top"].update(_stats_panel(stats))
    layout["middle"].split_row(
        Layout(_by_type_table(stats), name="type"),
        Layout(_by_source_table(stats), name="source"),
        Layout(_feed_health_table(stats), name="health"),
    )
    layout["bottom"].update(_recent_table(db, limit=20))
    return layout


def live_dashboard(db, refresh_seconds=5):
    """Auto-refreshing live dashboard. Ctrl+C to exit."""
    console.print("[bold cyan]Threat Intel Dashboard[/] — press Ctrl+C to quit\n")
    try:
        with Live(build_layout(db), refresh_per_second=1, console=console) as live:
            while True:
                time.sleep(refresh_seconds)
                live.update(build_layout(db))
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard closed.[/]")
