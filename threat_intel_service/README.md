# Threat Intel Service

A personal threat intelligence pipeline: pulls free IOC feeds, stores them
in SQLite, and lets you (or your other tools — `net_guard.py`, `IDS_GUARD.py`,
`Ad_Blocker.py`) check IPs/domains/URLs/hashes against them. Includes a live
Rich terminal dashboard and a small local HTTP API.

## Setup

```bash
pip install -r requirements.txt
```

No API keys required for the default feeds.

## Feeds included (free, no key needed)

| Feed | What it gives you |
|---|---|
| **URLhaus** (Abuse.ch) | Recent malicious URLs |
| **ThreatFox** (Abuse.ch) | Mixed IOCs: IPs, domains, URLs, hashes tied to specific malware |
| **Feodo Tracker** (Abuse.ch) | Active botnet C2 IPs |
| **Spamhaus DROP** | Hijacked/malicious IP netblocks (CIDR ranges) |

Edit `config.py` to disable feeds or add your own (e.g. AlienVault OTX,
AbuseIPDB, VirusTotal — those need API keys, so you'd add a new fetcher in
`core/feeds.py` following the existing pattern).

## Usage

**Pull the feeds and populate the database:**
```bash
python ti_service.py update
python ti_service.py update --feed urlhaus   # just one feed
```
Run this on a schedule (cron / Windows Task Scheduler) — e.g. every hour —
to keep the database current.

**Check a single indicator:**
```bash
python ti_service.py check 185.220.101.5
python ti_service.py check evil-domain.example
```
IPs are also checked against stored CIDR ranges (e.g. Spamhaus DROP), so an
IP doesn't need to be individually listed to be caught if it falls inside a
known-bad netblock.

**Search indicators (substring match):**
```bash
python ti_service.py search malware-drop
```

**One-shot summary:**
```bash
python ti_service.py stats
```

**Live auto-refreshing dashboard (terminal):**
```bash
python ti_service.py dashboard
python ti_service.py dashboard --interval 10
```

**Web dashboard (Streamlit):**
```bash
streamlit run streamlit_app.py
```
Opens a browser tab with:
- KPI cards (total indicators, IPs/CIDRs, URLs/domains, hashes)
- Bar charts by type and by source
- Feed run health table
- A searchable/filterable indicator table (filter by type, source, or text
  search) with CSV export
- A sidebar "Pull Now" button to trigger feed updates without touching the CLI
- A sidebar quick IOC checker

It reads the same `threat_intel.db` as the CLI, so you can run
`ti_service.py update` on a cron job and just browse results here — data
refreshes automatically every 15 seconds, or immediately via the sidebar
"Refresh view" button.

**Run the query API** (so other tools/scripts can check IOCs over HTTP):
```bash
python ti_service.py serve
# then:
curl "http://127.0.0.1:8787/check?value=185.220.101.5"
curl "http://127.0.0.1:8787/search?q=example.com"
curl "http://127.0.0.1:8787/stats"
```

## Wiring it into your other tools

From `net_guard.py`, `IDS_GUARD.py`, or `Ad_Blocker.py`, you can either:

1. **Query the running API** with `requests.get("http://127.0.0.1:8787/check?value=" + ip)`
2. **Import directly** (if running on the same machine, no HTTP needed):

```python
from core.database import TIDatabase
from core.checker import verdict
import config

db = TIDatabase(config.DB_PATH)
result = verdict(some_ip_or_domain, db)
if result["malicious"]:
    print(f"Blocked: {result['matches']}")
```

3. **Feed your own detections back in** — when IDS_GUARD or net_guard flags
   something, insert it as a first-party indicator:

```python
db.upsert_indicator(
    value=flagged_ip,
    ioc_type="ip",
    source="ids_guard",         # mark it as your own detection
    threat_type="port_scan",
    confidence=70,
)
```

This turns your three tools into one connected defensive stack: each one's
findings enrich the shared intel store that the others query.

## Project layout

```
threat_intel_service/
├── ti_service.py       # CLI entry point (update/check/search/stats/dashboard/serve)
├── streamlit_app.py    # Web dashboard (charts, filterable table, quick check)
├── config.py           # feed list, DB path, API settings
├── core/
│   ├── database.py     # SQLite storage layer
│   ├── feeds.py        # feed fetchers + parsers
│   ├── checker.py       # IOC classification + lookup/verdict logic
│   ├── dashboard.py     # Rich terminal dashboard rendering
│   └── api.py           # stdlib HTTP query API
└── requirements.txt
```

## Notes

- All parsers fail soft: if abuse.ch tweaks a column layout, a malformed row
  is skipped and logged rather than crashing the whole ingestion run.
- The database dedupes on `(value, ioc_type, source)`, so re-running `update`
  just refreshes `last_seen`/confidence rather than creating duplicates.
- `threat_intel.db` is created next to `ti_service.py` on first run.
