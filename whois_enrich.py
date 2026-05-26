"""
WHOIS enrichment via RDAP (Registration Data Access Protocol).
Uses each RIR's public RDAP endpoint — no system whois binary required.
"""

import time
import re
import requests
from pathlib import Path
from functools import lru_cache

# Guard rails
MAX_FIELD_LEN  = 200
QUERY_INTERVAL = 1.0   # seconds between requests (rate limiting)

RDAP_BASE = {
    "apnic":   "https://rdap.apnic.net",
    "ripencc": "https://rdap.db.ripe.net",
    "arin":    "https://rdap.arin.net/registry",
    "lacnic":  "https://rdap.lacnic.net/rdap",
    "afrinic": "https://rdap.afrinic.net/rdap",
}

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_ASN_RE  = re.compile(r"^\d{1,10}$")


def _validate_ip(ip: str) -> bool:
    if not _IPV4_RE.match(ip):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def _rdap_url(rtype: str, start: str, registry: str) -> str | None:
    base = RDAP_BASE.get(registry)
    if not base:
        return None
    if rtype == "ipv4" and _validate_ip(start):
        return f"{base}/ip/{start}"
    if rtype == "asn" and _ASN_RE.match(start):
        return f"{base}/autnum/{start}"
    return None


def _vcard_fn(vcard_array: list) -> str:
    """Extract 'fn' (full name) from a vCard array."""
    if len(vcard_array) < 2:
        return ""
    for item in vcard_array[1]:
        if isinstance(item, list) and item[0] == "fn":
            return str(item[3])[:MAX_FIELD_LEN]
    return ""


def _parse_rdap(data: dict) -> dict:
    name    = str(data.get("name", ""))[:MAX_FIELD_LEN]
    country = str(data.get("country", ""))[:8]

    # First remark as description
    descr = ""
    for remark in data.get("remarks", []):
        lines = remark.get("description", [])
        if lines:
            descr = str(lines[0])[:MAX_FIELD_LEN]
            break

    # Registrant fn from entities
    org = ""
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrant" in roles:
            vcard = entity.get("vcardArray", [])
            fn = _vcard_fn(vcard)
            if fn:
                org = fn
                break

    return {
        "name":    name,
        "descr":   org or descr,
        "country": country,
        "contact": "",
    }


@lru_cache(maxsize=256)
def _rdap_query(url: str) -> dict:
    try:
        resp = requests.get(url, timeout=10, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 200:
            return _parse_rdap(resp.json())
    except Exception:
        pass
    return {"name": "", "descr": "", "country": "", "contact": ""}


def load_opaque_resources(rir_data_dir: Path, opaque_ids: set) -> dict:
    """Return {opaque_id: {"ipv4": ..., "asn": ..., "registry": ...}}"""
    result = {oid: {"ipv4": None, "asn": None, "registry": None} for oid in opaque_ids}
    for txt in rir_data_dir.glob("delegated-*-latest.txt"):
        with open(txt, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("2|"):
                    continue
                parts = line.split("|")
                if len(parts) < 8:
                    continue
                oid = parts[7]
                if oid not in opaque_ids:
                    continue
                registry, rtype, start = parts[0], parts[2], parts[3]
                if rtype == "ipv4" and result[oid]["ipv4"] is None:
                    result[oid]["ipv4"]     = start
                    result[oid]["registry"] = registry
                elif rtype == "asn" and result[oid]["asn"] is None:
                    result[oid]["asn"]      = start
                    if result[oid]["registry"] is None:
                        result[oid]["registry"] = registry
    return result


def enrich(opaque_ids: set, rir_data_dir: Path) -> dict:
    """
    Returns {opaque_id: {"query": str, "name": str, "descr": str,
                          "contact": str, "country": str}}
    """
    resources = load_opaque_resources(rir_data_dir, opaque_ids)
    enriched  = {}
    first = True

    for oid, res in resources.items():
        registry = res.get("registry") or ""

        # Prefer IPv4 for lookup; fall back to ASN
        if res["ipv4"]:
            rtype, start = "ipv4", res["ipv4"]
        elif res["asn"]:
            rtype, start = "asn", res["asn"]
        else:
            enriched[oid] = {"query": "", "name": "", "descr": "", "contact": "", "country": ""}
            continue

        url = _rdap_url(rtype, start, registry)
        if not url:
            enriched[oid] = {"query": "", "name": "", "descr": "", "contact": "", "country": ""}
            continue

        if not first:
            time.sleep(QUERY_INTERVAL)
        first = False

        info = _rdap_query(url)
        info["query"] = start
        enriched[oid] = info

    return enriched
