"""
WHOIS enrichment for high-risk alert items.
Looks up the IPv4/ASN associated with each opaque_id and runs system whois.
"""

import subprocess
import re
import time
from pathlib import Path
from functools import lru_cache

# Guard rails
MAX_RESPONSE_BYTES = 64 * 1024       # 64 KB per WHOIS response
MAX_FIELD_LEN      = 200             # truncate any single parsed field
QUERY_INTERVAL     = 1.0             # seconds between whois calls (rate limiting)

WHOIS_FIELDS = [
    "netname", "as-name", "org-name", "orgname", "OrgName",
    "descr", "owner", "person", "role", "country", "Country",
]

SUMMARY_FIELDS = {
    "name":    ["netname", "as-name", "OrgName", "orgname", "org-name", "owner"],
    "descr":   ["descr"],
    "contact": ["person", "role"],
    "country": ["country", "Country"],
}

# Valid query targets only — prevents garbage from delegation files reaching whois
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_ASN_RE  = re.compile(r"^AS\d{1,10}$")


def _validate_target(target: str) -> bool:
    if _ASN_RE.match(target):
        return True
    if _IPV4_RE.match(target):
        octets = [int(o) for o in target.split(".")]
        return all(0 <= o <= 255 for o in octets)
    return False


@lru_cache(maxsize=256)
def _whois_raw(target: str) -> str:
    if not _validate_target(target):
        return ""
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True, timeout=10
        )
        # Decode only what we need, cap at MAX_RESPONSE_BYTES
        raw = result.stdout[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
        return raw
    except Exception:
        return ""


def _parse(raw: str) -> dict:
    parsed = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        m = re.match(r"^([^:]+):\s*(.+)$", line)
        if not m:
            continue
        key = m.group(1).strip()
        val = m.group(2).strip()[:MAX_FIELD_LEN]
        if key in WHOIS_FIELDS and key not in parsed:
            parsed[key] = val
    return parsed


def _summarise(parsed: dict) -> dict:
    out = {}
    for label, keys in SUMMARY_FIELDS.items():
        for k in keys:
            if k in parsed:
                out[label] = parsed[k]
                break
        else:
            out[label] = ""
    return out


def load_opaque_resources(rir_data_dir: Path, opaque_ids: set) -> dict:
    """Return {opaque_id: {"ipv4": ip_or_None, "asn": asn_or_None}}"""
    result = {oid: {"ipv4": None, "asn": None} for oid in opaque_ids}
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
                rtype, start = parts[2], parts[3]
                if rtype == "ipv4" and result[oid]["ipv4"] is None:
                    result[oid]["ipv4"] = start
                elif rtype == "asn" and result[oid]["asn"] is None:
                    result[oid]["asn"] = start
    return result


def enrich(opaque_ids: set, rir_data_dir: Path) -> dict:
    """
    Returns {opaque_id: {"query": str, "name": str, "descr": str,
                          "contact": str, "country": str}}
    """
    resources = load_opaque_resources(rir_data_dir, opaque_ids)
    enriched = {}
    first = True
    for oid, res in resources.items():
        raw_target = res["ipv4"] or (f"AS{res['asn']}" if res["asn"] else None)
        if not raw_target:
            enriched[oid] = {"query": "", "name": "", "descr": "", "contact": "", "country": ""}
            continue

        # Rate limit: pause between queries (cache hits skip this)
        cache_info = _whois_raw.cache_info()
        if not first:
            time.sleep(QUERY_INTERVAL)
        first = False

        raw = _whois_raw(raw_target)
        summary = _summarise(_parse(raw))
        summary["query"] = raw_target if _validate_target(raw_target) else ""
        enriched[oid] = summary
    return enriched
