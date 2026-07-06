"""
Lookup logic: classify an arbitrary string as ip/domain/url/hash, check it
against the indicator store (including CIDR-range containment for IPs),
and produce a verdict other tools (IDS_GUARD, net_guard, Ad_Blocker) can
consume directly.
"""

import ipaddress
import re

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def classify(value):
    value = value.strip()
    if URL_RE.match(value):
        return "url"
    if IPV4_RE.match(value):
        return "ip"
    if HASH_RE.match(value):
        return "hash"
    # crude domain check: has a dot, no spaces, not purely numeric
    if "." in value and " " not in value and not value.replace(".", "").isdigit():
        return "domain"
    return "unknown"


def check_ip_against_cidrs(ip_str, cidr_rows):
    """Return list of matching cidr indicator rows that contain ip_str."""
    matches = []
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return matches
    for row in cidr_rows:
        try:
            net = ipaddress.ip_network(row["value"], strict=False)
            if ip_obj in net:
                matches.append(row)
        except ValueError:
            continue
    return matches


def verdict(value, db):
    """
    Full check: exact match lookup + CIDR containment for IPs.
    Returns a dict:
        {
            "value": ...,
            "ioc_type_guess": ...,
            "malicious": bool,
            "matches": [ {source, threat_type, confidence, ...}, ... ],
            "max_confidence": int
        }
    """
    value = value.strip()
    ioc_type = classify(value)
    matches = db.check(value)

    if ioc_type == "ip":
        cidr_rows = db.cidr_indicators()
        matches += check_ip_against_cidrs(value, cidr_rows)

    max_conf = max((m.get("confidence", 0) for m in matches), default=0)

    return {
        "value": value,
        "ioc_type_guess": ioc_type,
        "malicious": len(matches) > 0,
        "matches": matches,
        "max_confidence": max_conf,
    }
