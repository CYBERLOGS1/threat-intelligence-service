"""
net_guard.py — Improved DoS/DDoS Detection & Auto-Blocking Tool
================================================================
Features:
  - Network profile selector at launch (Home / Office / School / ISP / Custom)
  - Cross-platform: Windows (netsh) + Linux (iptables)
  - Smarter detection: burst detection + sustained rate tracking
  - Whitelist support (never block trusted IPs)
  - Persistent logging: blocked IPs saved to JSON on exit
  - Live terminal dashboard with rich
  - Graceful crash recovery (atexit cleanup)
  - Config file support (net_guard_config.json)

Requirements:
  pip install scapy rich

Linux:  run with sudo
Windows: run as Administrator
"""

import os
import sys
import time
import json
import signal
import platform
import subprocess
import atexit
from collections import defaultdict
from datetime import datetime
from pathlib import Path
try:
    from scapy.all import sniff, IP
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("[WARN] rich not installed (pip install rich). Falling back to plain output.")

# ─────────────────────────────────────────────
# Threat Intel integration (optional — degrades gracefully if unavailable)
#
# Requires net_guard.py to be placed inside the threat_intel_service/ folder
# (alongside ti_service.py), so `core` and `config` are importable. If it's
# not found, net_guard still runs fine — it just skips reputation checks
# and detection sharing.
# ─────────────────────────────────────────────
try:
    from core.database import TIDatabase
    from core.checker import verdict as ti_verdict
    import config as ti_config
    ti_db = TIDatabase(ti_config.DB_PATH)
    HAS_TI = True
except ImportError:
    HAS_TI = False
    ti_db = None
    print("[WARN] Threat intel service not found alongside net_guard.py —")
    print("       IP reputation checks and detection sharing are disabled.")
    print("       Move net_guard.py into the threat_intel_service/ folder to enable this.")

# ─────────────────────────────────────────────
# Network Profiles
# ─────────────────────────────────────────────

NETWORK_PROFILES = {
    "1": {
        "name":            "Home / Personal",
        "description":     "Small household — a few devices, low normal traffic.",
        "threshold_pps":   80,
        "burst_threshold": 200,
        "burst_window":    0.2,
        "eval_interval":   1.0,
        "rationale": (
            "Home routers rarely see more than 50–70 pkt/s from any single "
            "source legitimately, so 80 pkt/s is a tight but fair limit."
        ),
    },
    "2": {
        "name":            "Small Office / SMB",
        "description":     "10–50 users, shared internet, light servers.",
        "threshold_pps":   200,
        "burst_threshold": 500,
        "burst_window":    0.2,
        "eval_interval":   1.0,
        "rationale": (
            "Office traffic includes file syncs, VoIP, and video calls. "
            "200 pkt/s gives legitimate traffic headroom while still catching floods."
        ),
    },
    "3": {
        "name":            "School / University",
        "description":     "Hundreds of users, heavy streaming and downloads.",
        "threshold_pps":   500,
        "burst_threshold": 1000,
        "burst_window":    0.3,
        "eval_interval":   1.0,
        "rationale": (
            "Campus networks are noisy — lecture streams, lab traffic, and bulk "
            "downloads are normal. 500 pkt/s avoids false positives on busy links."
        ),
    },
    "4": {
        "name":            "Enterprise / Corporate",
        "description":     "Large org: servers, cloud traffic, 100+ users.",
        "threshold_pps":   1000,
        "burst_threshold": 2500,
        "burst_window":    0.5,
        "eval_interval":   2.0,
        "rationale": (
            "Enterprise hosts legitimate high-volume traffic (DB replication, "
            "backups, CDN). Only sustained multi-thousand pkt/s floods are blocked."
        ),
    },
    "5": {
        "name":            "Data Centre / ISP Edge",
        "description":     "High-throughput infrastructure — servers under heavy load.",
        "threshold_pps":   5000,
        "burst_threshold": 10000,
        "burst_window":    1.0,
        "eval_interval":   5.0,
        "rationale": (
            "Racks see enormous legitimate traffic. Only extreme floods warrant "
            "blocking; false positives here are very costly."
        ),
    },
    "6": {
        "name":            "Custom",
        "description":     "Enter your own thresholds manually.",
        "threshold_pps":   None,
        "burst_threshold": None,
        "burst_window":    None,
        "eval_interval":   None,
        "rationale":       "",
    },
}

def select_network_profile() -> dict:
    """
    Interactive launch prompt — asks the user to pick a network profile
    and returns a dict of threshold overrides to merge into the config.
    """
    # ── Banner ──
    separator = "─" * 60
    print(f"\n{separator}")
    print("  NET GUARD — Network Profile Setup")
    print(separator)
    print("  Choose the profile that best describes this network.")
    print("  Thresholds will be tuned automatically.\n")

    for key, profile in NETWORK_PROFILES.items():
        print(f"  [{key}] {profile['name']}")
        print(f"       {profile['description']}")
        if profile["threshold_pps"] is not None:
            print(
                f"       Threshold: {profile['threshold_pps']} pkt/s  |  "
                f"Burst: {profile['burst_threshold']} pkts in {profile['burst_window']}s"
            )
        print()

    while True:
        choice = input("  Enter choice [1–6]: ").strip()
        if choice in NETWORK_PROFILES:
            break
        print("  [!] Invalid choice — please enter a number from 1 to 6.")

    selected = NETWORK_PROFILES[choice]
    print(f"\n  ✔  Profile selected: {selected['name']}")

    overrides = {}

    if choice == "6":
        # Custom — prompt for each value
        print("\n  Enter custom thresholds (press Enter to keep default):\n")
        try:
            val = input("  Sustained threshold (pkt/s) [150]: ").strip()
            overrides["threshold_pps"] = int(val) if val else 150

            val = input("  Burst packet count [300]: ").strip()
            overrides["burst_threshold"] = int(val) if val else 300

            val = input("  Burst window seconds [0.2]: ").strip()
            overrides["burst_window"] = float(val) if val else 0.2

            val = input("  Evaluation interval seconds [1.0]: ").strip()
            overrides["eval_interval"] = float(val) if val else 1.0
        except ValueError:
            print("  [!] Invalid input — using defaults.")
            overrides = {
                "threshold_pps": 150,
                "burst_threshold": 300,
                "burst_window": 0.2,
                "eval_interval": 1.0,
            }
    else:
        overrides = {
            "threshold_pps":   selected["threshold_pps"],
            "burst_threshold": selected["burst_threshold"],
            "burst_window":    selected["burst_window"],
            "eval_interval":   selected["eval_interval"],
        }
        if selected["rationale"]:
            print(f"\n  ℹ  {selected['rationale']}")

    # Store the profile name in overrides so it shows on the dashboard
    overrides["network_profile"] = selected["name"]

    print(f"\n  Thresholds → sustained: {overrides['threshold_pps']} pkt/s  |  "
          f"burst: {overrides['burst_threshold']} pkts in {overrides['burst_window']}s")
    print(f"{separator}\n")
    return overrides



DEFAULT_CONFIG = {
    "threshold_pps": 150,          # sustained packets/sec to trigger block
    "burst_threshold": 300,        # instantaneous burst (packets in <0.2s) to trigger block
    "burst_window": 0.2,           # seconds to measure a burst
    "eval_interval": 1.0,          # how often (seconds) to evaluate rates
    "network_profile": "Custom",   # set at launch by profile selector
    "whitelist": [                 # IPs that will never be blocked
        "127.0.0.1",
        "::1"
    ],
    "log_file": "net_guard_blocked.json",
    "dashboard_refresh": 0.5       # seconds between dashboard refreshes
}

CONFIG_FILE = Path("net_guard_config.json")

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                user_cfg = json.load(f)
            cfg = {**DEFAULT_CONFIG, **user_cfg}
            print(f"[*] Loaded config from {CONFIG_FILE}")
            return cfg
        except Exception as e:
            print(f"[WARN] Could not read config ({e}), using defaults.")
    else:
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[*] Created default config at {CONFIG_FILE} — edit and re-run to customise.")
    return dict(DEFAULT_CONFIG)

# ─────────────────────────────────────────────
# Platform detection
# ─────────────────────────────────────────────

OS = platform.system()  # "Windows" | "Linux" | "Darwin"

def check_privileges():
    if OS == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Requires Administrator privileges.")
            print("    Right-click your terminal → 'Run as administrator'.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[!] Requires root privileges. Run with: sudo python3 net_guard.py")
            sys.exit(1)

# ─────────────────────────────────────────────
# Firewall helpers
# ─────────────────────────────────────────────

def block_ip(ip: str, reason: str) -> bool:
    """Add a firewall rule to block inbound traffic from ip. Returns True on success."""
    try:
        if OS == "Windows":
            rule_name = f"NetGuard_Block_{ip}"
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip}", "enable=yes",
                ],
                check=True, capture_output=True,
            )
        else:
            # Linux — iptables (works on Kali, Ubuntu, Debian etc.)
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
        return True
    except subprocess.CalledProcessError as e:
        _log(f"[ERROR] Could not block {ip}: {e.stderr.decode().strip() if e.stderr else e}")
        return False


def unblock_ip(ip: str) -> bool:
    """Remove the firewall rule for ip. Returns True on success."""
    try:
        if OS == "Windows":
            rule_name = f"NetGuard_Block_{ip}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True,
            )
        else:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
            )
        return True
    except Exception:
        return False

# ─────────────────────────────────────────────
# State
# ─────────────────────────────────────────────

class State:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.whitelist: set = set(cfg["whitelist"])

        # packet counters — {ip: count} reset every eval_interval
        self.packet_count: defaultdict = defaultdict(int)

        # burst window — {ip: [timestamps]} rolling window
        self.burst_window: defaultdict = defaultdict(list)

        # blocked IPs — {ip: {"reason": ..., "rate": ..., "time": ...}}
        self.blocked: dict = {}

        # top talkers (all time) — {ip: total_packets}
        self.total_packets: defaultdict = defaultdict(int)

        # timing
        self.window_start: float = time.time()
        self.start_time: float = time.time()
        self.total_seen: int = 0

        # log lines for dashboard
        self.event_log: list = []

        # threat-intel lookup cache — avoid hitting the DB on every packet
        # from the same IP; {ip: True/False}
        self.ti_cache: dict = {}

    def log_event(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.event_log.append(f"[{ts}] {msg}")
        if len(self.event_log) > 50:
            self.event_log.pop(0)


_state: State = None   # set in main()

def _log(msg: str):
    """Log to state if available, else print."""
    if _state:
        _state.log_event(msg)
    else:
        print(msg)

# ─────────────────────────────────────────────
# Threat intel lookup helper
# ─────────────────────────────────────────────

def check_threat_intel(ip: str) -> bool:
    """
    Return True if `ip` is already a known-bad indicator in the shared
    threat intel store (e.g. a botnet C2 from Feodo Tracker, or something
    IDS_GUARD/Ad_Blocker reported earlier). Cached per run so a busy IP
    doesn't hit the database on every single packet.
    """
    if not HAS_TI:
        return False
    if ip in _state.ti_cache:
        return _state.ti_cache[ip]
    try:
        result = ti_verdict(ip, ti_db)
        malicious = result["malicious"]
    except Exception as e:
        _log(f"[WARN] Threat intel lookup failed for {ip}: {e}")
        malicious = False
    _state.ti_cache[ip] = malicious
    return malicious


# ─────────────────────────────────────────────
# Packet callback
# ─────────────────────────────────────────────

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    cfg = _state.cfg
    now = time.time()

    # Skip whitelisted IPs
    if src in _state.whitelist:
        return

    # Skip already-blocked IPs
    if src in _state.blocked:
        return

    # Immediate block if this IP is already known-bad in the shared threat
    # intel store — don't wait for it to trip the rate/burst thresholds
    if check_threat_intel(src):
        _trigger_block(src, reason="threat_intel", rate=0)
        return

    _state.total_seen += 1
    _state.packet_count[src] += 1
    _state.total_packets[src] += 1

    # ── Burst detection ──
    window = _state.burst_window[src]
    window.append(now)
    cutoff = now - cfg["burst_window"]
    # prune old timestamps
    while window and window[0] < cutoff:
        window.pop(0)

    if len(window) >= cfg["burst_threshold"]:
        _trigger_block(src, reason="burst",
                       rate=len(window) / cfg["burst_window"])
        return

    # ── Sustained rate detection ──
    elapsed = now - _state.window_start
    if elapsed >= cfg["eval_interval"]:
        for ip, count in list(_state.packet_count.items()):
            if ip in _state.blocked or ip in _state.whitelist:
                continue
            rate = count / elapsed
            if rate > cfg["threshold_pps"]:
                _trigger_block(ip, reason="sustained", rate=rate)

        _state.packet_count.clear()
        _state.window_start = now


def _trigger_block(ip: str, reason: str, rate: float):
    if ip in _state.blocked:
        return
    labels = {"burst": "BURST", "sustained": "SUSTAINED", "threat_intel": "THREAT INTEL MATCH"}
    label = labels.get(reason, reason.upper())
    msg = f"Blocking {ip} [{label}]" + (f" @ {rate:.0f} pkt/s" if rate else "")
    _log(msg)
    success = block_ip(ip, reason)
    if success:
        _state.blocked[ip] = {
            "reason": reason,
            "rate_pps": round(rate, 1),
            "blocked_at": datetime.now().isoformat(),
        }
        # Feed this detection back into the shared threat intel store so
        # IDS_GUARD / Ad_Blocker benefit from it too. Skip re-reporting IPs
        # that were blocked BECAUSE they were already in the store.
        if HAS_TI and reason != "threat_intel":
            try:
                ti_db.upsert_indicator(
                    value=ip,
                    ioc_type="ip",
                    source="net_guard",
                    threat_type=f"dos_{reason}",
                    confidence=70,
                )
            except Exception as e:
                _log(f"[WARN] Could not report {ip} to threat intel store: {e}")

# ─────────────────────────────────────────────
# Dashboard (rich)
# ─────────────────────────────────────────────

console = Console() if HAS_RICH else None

def build_dashboard() -> "Table":
    cfg = _state.cfg
    uptime = int(time.time() - _state.start_time)
    h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60

    # ── Stats panel ──
    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="bold cyan")
    stats.add_column(style="white")
    stats.add_row("Uptime",        f"{h:02d}:{m:02d}:{s:02d}")
    stats.add_row("OS",            OS)
    stats.add_row("Profile",       f"[bold magenta]{cfg.get('network_profile', '—')}[/]")
    stats.add_row("Packets seen",  f"{_state.total_seen:,}")
    stats.add_row("IPs seen",      f"{len(_state.total_packets):,}")
    stats.add_row("Blocked IPs",   f"[bold red]{len(_state.blocked)}[/]")
    stats.add_row("Threshold",     f"{cfg['threshold_pps']} pkt/s  |  burst: {cfg['burst_threshold']} in {cfg['burst_window']}s")
    stats.add_row("Threat Intel",  "[green]Connected[/]" if HAS_TI else "[dim]Unavailable[/]")
    stats.add_row("Whitelist",     ", ".join(sorted(_state.whitelist)) or "—")

    stats_panel = Panel(stats, title="[bold]Net Guard[/] — Status", border_style="cyan")

    # ── Blocked IPs table ──
    blocked_tbl = Table(box=box.SIMPLE_HEAVY, header_style="bold red",
                        show_lines=False, expand=True)
    blocked_tbl.add_column("IP", style="red")
    blocked_tbl.add_column("Reason", style="yellow")
    blocked_tbl.add_column("Rate (pkt/s)", justify="right")
    blocked_tbl.add_column("Blocked at")

    for ip, info in sorted(_state.blocked.items()):
        blocked_tbl.add_row(
            ip,
            info["reason"].upper(),
            str(info["rate_pps"]),
            info["blocked_at"][11:19],   # just the time portion
        )

    if not _state.blocked:
        blocked_tbl.add_row("[dim]none yet[/]", "", "", "")

    blocked_panel = Panel(blocked_tbl, title="Blocked IPs", border_style="red")

    # ── Top talkers table ──
    talkers = sorted(_state.total_packets.items(), key=lambda x: -x[1])[:8]
    talker_tbl = Table(box=box.SIMPLE_HEAVY, header_style="bold yellow",
                       show_lines=False, expand=True)
    talker_tbl.add_column("IP", style="yellow")
    talker_tbl.add_column("Total pkts", justify="right")
    talker_tbl.add_column("Status")
    for ip, cnt in talkers:
        status = "[red]BLOCKED[/]" if ip in _state.blocked else "[green]OK[/]"
        talker_tbl.add_row(ip, f"{cnt:,}", status)
    if not talkers:
        talker_tbl.add_row("[dim]waiting…[/]", "", "")
    talkers_panel = Panel(talker_tbl, title="Top Talkers", border_style="yellow")

    # ── Event log ──
    log_lines = _state.event_log[-10:]
    log_text = "\n".join(log_lines) if log_lines else "[dim]No events yet[/]"
    log_panel = Panel(log_text, title="Event Log", border_style="blue")

    # Compose layout
    root = Table.grid(padding=0)
    root.add_column()
    root.add_row(stats_panel)
    root.add_row(Columns([blocked_panel, talkers_panel], equal=True))
    root.add_row(log_panel)
    return root

# ─────────────────────────────────────────────
# Persistence — save & load blocked IPs
# ─────────────────────────────────────────────

def save_blocked_log():
    log_path = Path(_state.cfg["log_file"])
    data = {
        "saved_at": datetime.now().isoformat(),
        "blocked": _state.blocked,
    }
    try:
        with open(log_path, "w") as f:
            json.dump(data, f, indent=2)
        _log(f"Blocked IP log saved → {log_path}")
    except Exception as e:
        _log(f"[ERROR] Could not save log: {e}")


def load_previous_blocks() -> dict:
    log_path = Path(_state.cfg["log_file"])
    if not log_path.exists():
        return {}
    try:
        with open(log_path) as f:
            data = json.load(f)
        prev = data.get("blocked", {})
        if prev:
            print(f"[*] Found {len(prev)} previously blocked IP(s) in {log_path}")
        return prev
    except Exception:
        return {}

# ─────────────────────────────────────────────
# Cleanup (atexit + signal)
# ─────────────────────────────────────────────

def cleanup(save_log=True):
    if _state is None:
        return
    print(f"\n[*] Removing {len(_state.blocked)} firewall rule(s)...")
    for ip in list(_state.blocked):
        unblock_ip(ip)
    if save_log:
        save_blocked_log()
        log_path = Path(_state.cfg["log_file"])
        print(f"[*] Blocked IP list saved to: {log_path}")
        print(f"    Re-block them manually or edit the file before next run.")
    print(f"[*] Done. Exiting.")


def _signal_handler(sig, frame):
    # Called on Ctrl+C / SIGTERM
    sys.exit(0)   # triggers atexit


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    global _state

    check_privileges()
    cfg = load_config()

    # ── Network profile selection ──
    profile_overrides = select_network_profile()
    cfg.update(profile_overrides)

    _state = State(cfg)

    # Register graceful exit
    atexit.register(cleanup)
    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Offer to re-block previously blocked IPs
    prev = load_previous_blocks()
    if prev:
        answer = input(f"  Re-block {len(prev)} previous IP(s)? [y/N]: ").strip().lower()
        if answer == "y":
            for ip, info in prev.items():
                if block_ip(ip, info.get("reason", "previous")):
                    _state.blocked[ip] = info
                    _state.log_event(f"Re-blocked {ip} (from log)")
            print(f"[+] Re-blocked {len(_state.blocked)} IP(s).")

    print(f"[*] Monitoring on {OS}  |  threshold: {cfg['threshold_pps']} pkt/s  |  burst: {cfg['burst_threshold']} in {cfg['burst_window']}s")
    print(f"[*] Whitelist: {', '.join(cfg['whitelist'])}")
    print("[*] Press Ctrl+C to stop and save log.\n")

    if HAS_RICH:
        with Live(build_dashboard(), refresh_per_second=int(1 / cfg["dashboard_refresh"]),
                  console=console, screen=False) as live:
            _state.log_event("Net Guard started.")

            def sniff_loop():
                sniff(filter="ip", prn=packet_callback, store=False)

            import threading
            t = threading.Thread(target=sniff_loop, daemon=True)
            t.start()

            while t.is_alive():
                live.update(build_dashboard())
                time.sleep(cfg["dashboard_refresh"])
    else:
        # Plain fallback
        sniff(filter="ip", prn=packet_callback, store=False)


if __name__ == "__main__":
    main()