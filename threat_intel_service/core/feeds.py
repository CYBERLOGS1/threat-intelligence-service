"""
Fetchers + parsers for free, no-API-key threat intel feeds.

Each parse_* function takes raw response text and yields normalized
indicator dicts: {value, ioc_type, source, threat_type, confidence, tags}

These are designed to fail soft: a malformed/changed row is skipped and
counted, never crashes the whole ingestion run.
"""

import csv
import io
import re
import requests


from config import REQUEST_TIMEOUT, USER_AGENT

HEADERS = {"User-Agent": USER_AGENT}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def fetch_text(url):
    resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def _strip_comments(text, comment_chars=("#",)):
    """Return list of non-comment, non-blank lines."""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(c) for c in comment_chars):
            continue
        lines.append(line)
    return lines


def _dict_rows(text):
    """Strip comments, then parse remaining lines as CSV with the first
    remaining line treated as the header (DictReader). Robust to abuse.ch
    reordering columns, since we look up by name rather than position."""
    lines = _strip_comments(text)
    if not lines:
        return []
    reader = csv.DictReader(lines)
    return list(reader)


def parse_urlhaus(text):
    """Abuse.ch URLhaus recent URLs CSV."""
    records = []
    for row in _dict_rows(text):
        try:
            url = (row.get("url") or "").strip()
            threat = (row.get("threat") or "").strip() or "malware_url"
            tags = (row.get("tags") or "").strip()
            if not url:
                continue
            records.append({
                "value": url,
                "ioc_type": "url",
                "source": "urlhaus",
                "threat_type": threat,
                "confidence": 75,
                "tags": tags,
            })
        except (AttributeError, KeyError):
            continue
    return records


def parse_threatfox(text):
    """Abuse.ch ThreatFox recent IOC export CSV."""
    records = []
    for row in _dict_rows(text):
        try:
            value = (row.get("ioc_value") or "").strip()
            raw_type = (row.get("ioc_type") or "").strip().lower()
            threat_type = (row.get("threat_type") or "").strip() or "unknown"
            confidence = (row.get("confidence_level") or "").strip()
            tags = (row.get("tags") or "").strip()

            if not value:
                continue

            if "ip" in raw_type:
                # ThreatFox sometimes reports "ip:port" combined
                ioc_type = "ip"
                value = value.split(":")[0]
            elif "domain" in raw_type:
                ioc_type = "domain"
            elif "url" in raw_type:
                ioc_type = "url"
            elif any(h in raw_type for h in ("md5", "sha1", "sha256", "hash")):
                ioc_type = "hash"
            else:
                ioc_type = "other"

            try:
                conf = int(confidence)
            except ValueError:
                conf = 60

            records.append({
                "value": value,
                "ioc_type": ioc_type,
                "source": "threatfox",
                "threat_type": threat_type,
                "confidence": conf,
                "tags": tags,
            })
        except (AttributeError, KeyError):
            continue
    return records


def parse_feodotracker(text):
    """Abuse.ch Feodo Tracker active botnet C2 IP blocklist CSV."""
    records = []
    for row in _dict_rows(text):
        try:
            ip = (row.get("dst_ip") or "").strip()
            malware = (row.get("malware") or "").strip() or "botnet_c2"
            if not IPV4_RE.match(ip):
                continue
            records.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "feodotracker",
                "threat_type": f"botnet_c2:{malware}",
                "confidence": 85,
                "tags": malware,
            })
        except (AttributeError, KeyError):
            continue
    return records


def parse_spamhaus_drop(text):
    """Spamhaus DROP list: 'CIDR ; SBLxxxx' lines."""
    records = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        parts = stripped.split(";")
        cidr = parts[0].strip()
        ref = parts[1].strip() if len(parts) > 1 else ""
        if "/" not in cidr:
            continue
        records.append({
            "value": cidr,
            "ioc_type": "cidr",
            "source": "spamhaus_drop",
            "threat_type": "hijacked_netblock",
            "confidence": 90,
            "tags": ref,
        })
    return records


PARSERS = {
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "feodotracker": parse_feodotracker,
    "spamhaus_drop": parse_spamhaus_drop,
}


def fetch_and_parse(feed_name, url):
    """Returns (records, error_message). error_message is None on success."""
    parser = PARSERS.get(feed_name)
    if parser is None:
        return [], f"No parser registered for feed '{feed_name}'"
    try:
        text = fetch_text(url)
    except requests.RequestException as e:
        return [], f"Fetch failed: {e}"
    try:
        records = parser(text)
    except Exception as e:  # parser bugs shouldn't kill the whole run
        return [], f"Parse failed: {e}"
    return records, None
