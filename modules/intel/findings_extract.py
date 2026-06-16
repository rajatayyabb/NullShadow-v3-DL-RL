"""
Turn a recon-pipeline results dict (modules/recon/recon_pipeline.py) into a list
of normalized findings, and optionally persist them via ScanDatabase.add_finding().

Used by Phase 6 monitor mode and the Auto Full Recon option so that posture
scoring (risk_score), scan diffing (scan_diff) and the dashboard all have
structured per-finding data to work with.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def _is_phase(name, *keywords):
    n = name.lower()
    return any(k in n for k in keywords)


def extract_findings_from_recon(results, db=None):
    """
    Build a list of finding dicts from a recon results dict.
    If `db` is given, CVE ids found in vuln output are enriched via NVD (cached).
    """
    findings = []
    try:
        from modules.intel.nvd_lookup import extract_cve_ids, lookup_cve
    except Exception:
        extract_cve_ids = lambda *_: []
        lookup_cve = None

    target = results.get("target", "unknown")

    for phase, data in (results or {}).items():
        if phase in ("target", "timestamp") or not isinstance(data, dict):
            continue

        # Open ports → informational findings.
        if _is_phase(phase, "port scan") and data.get("open_ports"):
            for p in data["open_ports"]:
                svc = p.get("service", "")
                ver = (p.get("product", "") + " " + p.get("version", "")).strip()
                findings.append({
                    "target": target, "finding_type": "open_port", "severity": "INFO",
                    "title": f"Open port {p.get('port','')} ({svc or 'unknown'})",
                    "description": f"Service: {svc} {ver}".strip(),
                    "cve_ids": [], "raw_data": p,
                })

        # Vulnerability scan → HIGH findings, CVE-enriched.
        if _is_phase(phase, "vulnerability") and data.get("vulnerabilities"):
            for v in data["vulnerabilities"]:
                out = v.get("finding", "")
                cve_ids = extract_cve_ids(out)
                severity, cvss = "HIGH", None
                if cve_ids and lookup_cve and db is not None:
                    info = lookup_cve(cve_ids[0], db=db)
                    if info:
                        if info.get("severity") and info["severity"] != "UNKNOWN":
                            severity = info["severity"]
                        cvss = info.get("cvss_score")
                findings.append({
                    "target": target, "finding_type": "vulnerability", "severity": severity,
                    "title": f"{v.get('script','vuln')} on port {v.get('port','')}"
                             + (f" ({cve_ids[0]})" if cve_ids else ""),
                    "description": out[:500], "cve_ids": cve_ids,
                    "raw_data": {"port": v.get("port"), "cvss_score": cvss},
                })

        # SSL/TLS audit → flag weak TLS.
        if _is_phase(phase, "ssl", "tls"):
            tls = str(data.get("tls_version", ""))
            if any(weak in tls for weak in ("TLSv1.0", "TLSv1.1", "SSLv", "Weak")) or \
               (data.get("error") and "weak" in str(data.get("error")).lower()):
                findings.append({
                    "target": target, "finding_type": "ssl_audit", "severity": "MEDIUM",
                    "title": f"Weak TLS version ({tls or 'legacy'})",
                    "description": f"TLS/SSL audit reported: {tls}. {data.get('cipher','')}",
                    "cve_ids": [], "raw_data": data,
                })

        # Threat intel → flag bad reputation.
        if _is_phase(phase, "threat intel"):
            abuse = data.get("abuseipdb")
            if isinstance(abuse, dict) and (abuse.get("abuse_score") or 0) and abuse["abuse_score"] > 50:
                findings.append({
                    "target": target, "finding_type": "threat_intel", "severity": "HIGH",
                    "title": f"High abuse reputation (score {abuse['abuse_score']})",
                    "description": f"AbuseIPDB reports {abuse.get('total_reports','?')} reports.",
                    "cve_ids": [], "raw_data": abuse,
                })

    return findings


def persist_findings(db, scan_id, findings):
    """Write a list of finding dicts to the DB under scan_id. Returns count."""
    n = 0
    for f in findings or []:
        try:
            db.add_finding(
                target=f.get("target", "unknown"),
                finding_type=f.get("finding_type", "info"),
                title=f.get("title", "finding"),
                description=f.get("description", ""),
                severity=f.get("severity", "INFO"),
                cve_ids=f.get("cve_ids", []),
                raw_data=f.get("raw_data", {}),
                scan_id=scan_id,
            )
            n += 1
        except Exception:
            pass
    return n
