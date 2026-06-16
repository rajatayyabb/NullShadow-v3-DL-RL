"""
Shared RDAP (Registration Data Access Protocol) lookup helper.

RDAP is the modern, HTTPS-based replacement for legacy WHOIS (port 43).
This module is used by both modules/recon/recon_pipeline.py and
modules/osint/osint_tools.py so WHOIS behaviour stays consistent.

Lookup order (Phase 0.2 fix for non-generic TLDs like .edu.pk):
  1. IANA RDAP bootstrap  — fetch https://data.iana.org/rdap/dns.json,
     cache it locally (it changes rarely), find the correct RDAP base URL
     for the target's TLD, then query {base}/domain/{domain}.
  2. Hardcoded server dict — fast path for the common gTLDs.
  3. https://rdap.org/domain/{domain} — generic redirector fallback.

If every method fails (or the domain is unregistered), rdap_lookup() returns
None so callers can show a clean "not found" rather than crashing.
"""

import os
import json
import time

import requests

# Local cache for the IANA bootstrap file (changes rarely).
_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_BOOTSTRAP_CACHE = os.path.join(_DATA_DIR, "rdap_dns_bootstrap.json")
_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
# Refresh the cached bootstrap file at most once every 30 days.
_BOOTSTRAP_MAX_AGE = 30 * 24 * 3600

# Fast-path / offline fallback servers for common gTLDs.
_HARDCODED_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "io":  "https://rdap.nic.io/",
    "co":  "https://rdap.nic.co/",
    "uk":  "https://rdap.nominet.uk/uk/",
    "info": "https://rdap.identitydigital.services/rdap/",
}

# In-process cache of the parsed bootstrap services list.
_bootstrap_services = None


def _load_bootstrap(force=False):
    """Return the IANA bootstrap 'services' list, fetching/caching as needed."""
    global _bootstrap_services
    if _bootstrap_services is not None and not force:
        return _bootstrap_services

    # Try the local cache first (unless it is stale).
    if not force and os.path.exists(_BOOTSTRAP_CACHE):
        try:
            age = time.time() - os.path.getmtime(_BOOTSTRAP_CACHE)
            if age < _BOOTSTRAP_MAX_AGE:
                with open(_BOOTSTRAP_CACHE, "r", encoding="utf-8") as fh:
                    _bootstrap_services = json.load(fh).get("services", [])
                    return _bootstrap_services
        except Exception:
            pass

    # Fetch a fresh copy and cache it.
    try:
        r = requests.get(_BOOTSTRAP_URL, timeout=8,
                         headers={"Accept": "application/json"})
        if r.status_code == 200:
            data = r.json()
            try:
                os.makedirs(_DATA_DIR, exist_ok=True)
                with open(_BOOTSTRAP_CACHE, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
            except Exception:
                pass  # caching is best-effort
            _bootstrap_services = data.get("services", [])
            return _bootstrap_services
    except Exception:
        pass

    # Network failed — fall back to any stale cache we may still have.
    if os.path.exists(_BOOTSTRAP_CACHE):
        try:
            with open(_BOOTSTRAP_CACHE, "r", encoding="utf-8") as fh:
                _bootstrap_services = json.load(fh).get("services", [])
                return _bootstrap_services
        except Exception:
            pass

    _bootstrap_services = []
    return _bootstrap_services


def _base_url_for_tld(tld):
    """Find the RDAP base URL for a TLD via the IANA bootstrap (or None)."""
    tld = tld.lower()
    for entry in _load_bootstrap():
        # Each entry is [ [tld, ...], [base_url, ...] ].
        if len(entry) >= 2 and tld in [t.lower() for t in entry[0]]:
            for base in entry[1]:
                if base.startswith("https://"):
                    return base.rstrip("/") + "/"
            if entry[1]:
                return entry[1][0].rstrip("/") + "/"
    return None


def _candidate_urls(domain):
    """Build the ordered list of RDAP query URLs to try for a domain."""
    tld = domain.split(".")[-1].lower()
    urls = []

    base = _base_url_for_tld(tld)
    if base:
        urls.append(base + "domain/" + domain)

    if tld in _HARDCODED_SERVERS:
        hc = _HARDCODED_SERVERS[tld].rstrip("/") + "/domain/" + domain
        if hc not in urls:
            urls.append(hc)

    urls.append("https://rdap.org/domain/" + domain)
    return urls


def normalize_rdap(d, domain):
    """Convert a raw RDAP JSON response into a flat, display-friendly dict."""
    result = {}
    result["Domain Name"] = str(d.get("ldhName", domain)).upper()
    status = d.get("status", [])
    if status:
        result["Status"] = ", ".join(status)

    for event in d.get("events", []):
        action = event.get("eventAction", "")
        date = (event.get("eventDate", "") or "")[:10]
        if "registration" in action:
            result["Created"] = date
        elif "expiration" in action:
            result["Expires"] = date
        elif "last changed" in action:
            result["Updated"] = date

    for entity in d.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])
        vcard = vcard[1] if len(vcard) > 1 else []
        name = next((v[-1] for v in vcard if v and v[0] == "fn"), None) if vcard else None
        if "registrar" in roles and name:
            result["Registrar"] = name
        if "registrant" in roles and name:
            result["Registrant"] = name

    ns_list = [ns.get("ldhName", "") for ns in d.get("nameservers", []) if ns.get("ldhName")]
    if ns_list:
        result["Name Servers"] = ", ".join(ns_list)

    return result


def rdap_lookup(domain, timeout=8):
    """
    Resolve a domain via RDAP. Returns a normalized dict on success, or None
    if the domain could not be resolved by any method (e.g. unregistered).
    """
    domain = (domain or "").replace("www.", "").strip().lower()
    if not domain or "." not in domain:
        return None

    for url in _candidate_urls(domain):
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"Accept": "application/json"})
            if r.status_code == 200:
                try:
                    data = r.json()
                except ValueError:
                    continue
                normalized = normalize_rdap(data, domain)
                if normalized.get("Domain Name"):
                    return normalized
            # 404 here usually means "not registered at this server" — keep trying
            # the remaining candidates before giving up.
        except Exception:
            continue
    return None


if __name__ == "__main__":
    # Quick manual test: a .com, a .edu.pk, and an invalid domain.
    for d in ["example.com", "nu.edu.pk", "this-domain-should-not-exist-zzz.com"]:
        print(f"\n=== {d} ===")
        res = rdap_lookup(d)
        if res:
            for k, v in res.items():
                print(f"  {k}: {v}")
        else:
            print("  [not found / unavailable]")
