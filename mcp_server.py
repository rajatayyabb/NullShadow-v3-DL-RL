#!/usr/bin/env python3
"""
NullShadow v4.0 — MCP Server Layer (brief Section / Phase 4)

Exposes a focused subset of NullShadow's modules as MCP (Model Context Protocol)
tools so MCP-compatible AI clients (Claude Desktop, etc.) can call them directly.

This is an ADDITIONAL interface, not a replacement: `python3 main.py` remains a
fully functional standalone CLI. The tools below WRAP existing module functions
(they do not re-implement scanning logic) and return structured JSON in the
Phase 1 findings style so the calling agent receives consistent data.

Exposed tools:
  port_scan, vulnerability_scan, subdomain_enum, dns_recon,
  whois_lookup, hash_identify_crack, jwt_analyze

Run:
  pip install mcp            # or: pip install fastmcp
  python3 mcp_server.py      # stdio transport (what Claude Desktop expects)

Register with Claude Desktop using tools/claude_desktop_config.json.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from mcp.server.fastmcp import FastMCP
except Exception:  # pragma: no cover - import guard
    try:
        from fastmcp import FastMCP
    except Exception:
        sys.stderr.write(
            "[NullShadow MCP] The 'mcp' (FastMCP) package is not installed.\n"
            "Install it with:  pip install mcp   (or: pip install fastmcp)\n"
            "Then run:  python3 mcp_server.py\n"
        )
        sys.exit(1)

from modules.recon.recon_pipeline import ReconPipeline
from modules.pentesting.scanner import AdvancedPentestModules
from modules.pentesting.new_tools import NewPentestTools
from modules.intel.rdap_lookup import rdap_lookup
from modules.intel.nvd_lookup import extract_cve_ids, lookup_cve

mcp = FastMCP("nullshadow")

_recon = ReconPipeline()
_pentest = AdvancedPentestModules()
_newtools = NewPentestTools()


def _enrich_vuln_findings(vulns, target):
    """Convert recon vuln dicts into Phase 1 finding dicts, CVE-enriched."""
    findings = []
    for v in vulns or []:
        out = v.get("finding", "")
        cve_ids = extract_cve_ids(out)
        severity, cvss = "HIGH", None
        if cve_ids:
            info = lookup_cve(cve_ids[0])
            if info:
                severity = info.get("severity", severity) or severity
                cvss = info.get("cvss_score")
        findings.append({
            "target": target, "finding_type": "vulnerability", "severity": severity,
            "title": f"{v.get('script','vuln')} on port {v.get('port','')}"
                     + (f" ({cve_ids[0]})" if cve_ids else ""),
            "description": out[:500], "cve_ids": cve_ids,
            "raw_data": {"port": v.get("port"), "cvss_score": cvss},
        })
    return findings


@mcp.tool()
def port_scan(target: str) -> dict:
    """Scan a host for open TCP ports and detect service/version (nmap -sV).
    Returns {open_ports: [...], count: N}."""
    return _recon._port_scan(target)


@mcp.tool()
def vulnerability_scan(target: str) -> dict:
    """Run nmap vulnerability scripts against a target and return structured
    findings (Phase 1 format), each CVE-enriched with NVD severity/CVSS."""
    raw = _recon._vuln_scan(target)
    return {
        "target": target,
        "count": raw.get("count", 0),
        "findings": _enrich_vuln_findings(raw.get("vulnerabilities", []), target),
        "error": raw.get("error"),
    }


@mcp.tool()
def subdomain_enum(domain: str) -> dict:
    """Enumerate subdomains of a domain by resolving a wordlist.
    Returns {found: [{subdomain, ip}], count: N}."""
    return _recon._subdomains(domain)


@mcp.tool()
def dns_recon(domain: str) -> dict:
    """Collect DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA) and test for zone
    transfer. Returns {records: {...}, zone_transfer_vulnerable: bool}."""
    return _newtools.dns_recon_json(domain)


@mcp.tool()
def whois_lookup(domain: str) -> dict:
    """RDAP/WHOIS registration lookup for a domain (IANA bootstrap).
    Returns registrar, dates, status and name servers, or an error."""
    result = rdap_lookup(domain)
    return result if result else {"domain": domain, "error": "Not found / no RDAP data"}


@mcp.tool()
def hash_identify_crack(hash_value: str) -> dict:
    """Identify a hash type by length and try to crack it against a small
    built-in wordlist. Returns {detected_types, cracked, ...}."""
    return _pentest.hash_identify_crack_json(hash_value)


@mcp.tool()
def jwt_analyze(token: str) -> dict:
    """Decode a JWT and report header/payload plus security issues
    (alg=none, weak symmetric alg, expiry). Does not verify the signature."""
    return _pentest.jwt_analyze_json(token)


if __name__ == "__main__":
    mcp.run()
