"""
Configuration for the Threat Intelligence Service.
Edit FEEDS to enable/disable sources or add your own API-key-based feeds
(AlienVault OTX, AbuseIPDB, VirusTotal, etc).
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "threat_intel.db")

# How long (hours) before an indicator not seen again by a feed is considered "stale"
STALE_HOURS = 24 * 30  # 30 days

# Free, no-API-key-required feeds. Each fetcher lives in core/feeds.py
FEEDS = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Recent malicious URLs (Abuse.ch URLhaus)",
        "enabled": True,
    },
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "description": "Recent malware IOCs - IP/domain/URL/hash (Abuse.ch ThreatFox)",
        "enabled": True,
    },
    "feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "Active botnet C2 IPs (Abuse.ch Feodo Tracker)",
        "enabled": True,
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "description": "Hijacked/malicious netblocks (Spamhaus DROP)",
        "enabled": True,
    },
}

# HTTP request settings
REQUEST_TIMEOUT = 30
USER_AGENT = "threat-intel-service/1.0 (personal security tooling)"

# API server settings (used by `ti_service.py serve`)
API_HOST = "127.0.0.1"
API_PORT = 8787
