"""
NVD CVE enrichment (Phase 1).

lookup_cve(cve_id) queries the free, keyless NVD REST API 2.0 and returns the
CVSS severity, description and published date for a single CVE.

API & cost safety (see brief Section "API & Cost Safety"):
  * The NVD API is rate-limited to 5 requests / 30s WITHOUT a key. This module
    therefore (a) caches every result in the local 'cve_cache' table so a CVE is
    only fetched once, and (b) enforces a minimum delay between live requests and
    backs off on 403/429 responses.
  * A NVD_API_KEY (config/env) raises the limit; if present it is sent and the
    inter-request delay is reduced.
  * 403/429 are treated as expected rate-limit conditions, NOT as bugs — the
    function returns a clean {"rate_limited": True, ...} dict instead of crashing.
"""

import os
import re
import time
import threading

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Optional API key (raises the rate limit).
try:
    from config.config import NVD_API_KEY as _CFG_NVD_KEY
except Exception:
    _CFG_NVD_KEY = ""
NVD_API_KEY = os.getenv("NVD_API_KEY", _CFG_NVD_KEY or "")

# Without a key: 5 req / 30s  -> ~6s spacing. With a key we can go much faster.
_MIN_INTERVAL = 1.5 if NVD_API_KEY else 6.5
_rate_lock = threading.Lock()
_last_request_ts = [0.0]


def extract_cve_ids(text):
    """Return a de-duplicated, upper-cased list of CVE ids found in free text."""
    if not text:
        return []
    seen, out = set(), []
    for m in CVE_RE.findall(str(text)):
        cid = m.upper()
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def _throttle():
    """Block until at least _MIN_INTERVAL has passed since the last live call."""
    with _rate_lock:
        wait = _MIN_INTERVAL - (time.time() - _last_request_ts[0])
        if wait > 0:
            time.sleep(wait)
        _last_request_ts[0] = time.time()


def _parse_cve(item):
    """Normalize one NVD 'vulnerabilities[].cve' object into a flat dict."""
    cve = item.get("cve", item)
    cve_id = cve.get("id", "N/A")

    desc = "N/A"
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "N/A")
            break

    score, severity, vector = None, "UNKNOWN", None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "UNKNOWN"
            vector = data.get("vectorString")
            break

    # CVSS v2 has no baseSeverity field; derive it from the score.
    if severity == "UNKNOWN" and score is not None:
        severity = severity_from_score(score)

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": score,
        "severity": (severity or "UNKNOWN").upper(),
        "vector": vector,
        "published": (cve.get("published", "") or "")[:10],
        "references": [r.get("url") for r in cve.get("references", [])][:5],
    }


def severity_from_score(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def lookup_cve(cve_id, db=None, timeout=12):
    """
    Look up a single CVE id. Returns a normalized dict:
        {cve_id, description, cvss_score, severity, vector, published, references}
    Uses the local cve_cache (when a db is given) before ever hitting the API.
    Returns {"cve_id":..., "rate_limited": True} on 403/429.
    """
    if not cve_id:
        return None
    cve_id = cve_id.upper().strip()
    if not CVE_RE.fullmatch(cve_id):
        return None

    # 1. Cache first — avoids repeat lookups and protects the rate limit.
    if db is not None:
        cached = db.get_cached_cve(cve_id)
        if cached:
            return cached

    # 2. Live NVD query (throttled).
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    _throttle()
    try:
        r = requests.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    except Exception as e:
        return {"cve_id": cve_id, "severity": "UNKNOWN", "error": str(e)}

    if r.status_code in (403, 429):
        # Expected rate-limit condition — not a code bug.
        return {"cve_id": cve_id, "severity": "UNKNOWN", "rate_limited": True,
                "note": "NVD rate limit hit (5 req/30s without a key). Cached results are reused."}

    if r.status_code != 200:
        return {"cve_id": cve_id, "severity": "UNKNOWN", "error": f"HTTP {r.status_code}"}

    try:
        data = r.json()
    except ValueError:
        return {"cve_id": cve_id, "severity": "UNKNOWN", "error": "bad JSON"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        result = {"cve_id": cve_id, "severity": "UNKNOWN", "description": "Not found in NVD"}
    else:
        result = _parse_cve(vulns[0])

    if db is not None:
        try:
            db.cache_cve(cve_id, result)
        except Exception:
            pass
    return result


if __name__ == "__main__":
    # Manual test (single lookup to respect the rate limit).
    import json as _json
    for cid in ["CVE-2021-44228"]:
        print(_json.dumps(lookup_cve(cid), indent=2))
