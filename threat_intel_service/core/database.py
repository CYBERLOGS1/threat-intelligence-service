"""
SQLite-backed storage for indicators of compromise (IOCs).

Schema
------
indicators:
    id, value, ioc_type, source, threat_type, confidence,
    first_seen, last_seen, tags, raw_ref

feed_runs:
    id, feed_name, run_time, records_pulled, status, message
"""

import sqlite3
import datetime
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,        -- ip, domain, url, hash, cidr
    source TEXT NOT NULL,
    threat_type TEXT,              -- e.g. botnet_cc, malware_download, phishing
    confidence INTEGER DEFAULT 50,
    first_seen TEXT,
    last_seen TEXT,
    tags TEXT,
    UNIQUE(value, ioc_type, source)
);

CREATE TABLE IF NOT EXISTS feed_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name TEXT,
    run_time TEXT,
    records_pulled INTEGER,
    status TEXT,
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(ioc_type);
"""


class TIDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def upsert_indicator(self, value, ioc_type, source, threat_type=None,
                          confidence=50, tags=None):
        now = datetime.datetime.utcnow().isoformat()
        tags_str = ",".join(tags) if isinstance(tags, (list, tuple)) else (tags or "")
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO indicators (value, ioc_type, source, threat_type,
                                         confidence, first_seen, last_seen, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value, ioc_type, source) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    confidence=excluded.confidence,
                    threat_type=excluded.threat_type,
                    tags=excluded.tags
                """,
                (value, ioc_type, source, threat_type, confidence, now, now, tags_str),
            )

    def bulk_upsert(self, records):
        """records: list of dicts with keys value, ioc_type, source,
        threat_type, confidence, tags"""
        count = 0
        for r in records:
            self.upsert_indicator(
                value=r["value"],
                ioc_type=r["ioc_type"],
                source=r["source"],
                threat_type=r.get("threat_type"),
                confidence=r.get("confidence", 50),
                tags=r.get("tags"),
            )
            count += 1
        return count

    def record_feed_run(self, feed_name, records_pulled, status, message=""):
        now = datetime.datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO feed_runs (feed_name, run_time, records_pulled, status, message)
                   VALUES (?, ?, ?, ?, ?)""",
                (feed_name, now, records_pulled, status, message),
            )

    def check(self, value):
        """Return all matching rows for an exact indicator value (case-insensitive)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM indicators WHERE lower(value) = lower(?)",
                (value,),
            ).fetchall()
            return [dict(r) for r in rows]

    def search(self, query, limit=50):
        """Substring search across indicator values."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM indicators WHERE value LIKE ? ORDER BY last_seen DESC LIMIT ?",
                (f"%{query}%", limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def recent(self, limit=20):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM indicators ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def all_indicators(self, limit=5000):
        """Return up to `limit` indicators, most recent first. Used by the
        Streamlit dashboard for client-side filtering/search."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM indicators ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def ingestion_history(self, limit=100):
        """Feed run history, oldest first, for charting ingestion volume over time."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM feed_runs ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]


    def stats(self):
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM indicators").fetchone()["c"]
            by_type = conn.execute(
                "SELECT ioc_type, COUNT(*) c FROM indicators GROUP BY ioc_type ORDER BY c DESC"
            ).fetchall()
            by_source = conn.execute(
                "SELECT source, COUNT(*) c FROM indicators GROUP BY source ORDER BY c DESC"
            ).fetchall()
            last_runs = conn.execute(
                "SELECT * FROM feed_runs ORDER BY id DESC LIMIT 10"
            ).fetchall()
            return {
                "total": total,
                "by_type": [dict(r) for r in by_type],
                "by_source": [dict(r) for r in by_source],
                "last_runs": [dict(r) for r in last_runs],
            }

    def cidr_indicators(self):
        """Return all stored CIDR-range indicators (used for IP-in-range checks)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM indicators WHERE ioc_type = 'cidr'"
            ).fetchall()
            return [dict(r) for r in rows]
