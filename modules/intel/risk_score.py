"""
Risk-weighted posture scoring (brief Section 6.2).

calculate_posture_score(findings_list) -> a single 0-100 score for a scan.
The score starts at 100 (perfect) and subtracts a weighted penalty per finding,
weighted by severity / CVSS (from Phase 1 NVD enrichment). A critical CVSS 9-10
finding subtracts far more than a low-severity header misconfiguration.

Higher score = better security posture.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Severity penalty when no CVSS score is available.
_SEVERITY_PENALTY = {
    "CRITICAL": 28.0,
    "HIGH":     16.0,
    "MEDIUM":    8.0,
    "LOW":       3.0,
    "INFO":      0.5,
    "NONE":      0.0,
    "UNKNOWN":   2.0,
}

# A new finding at/above this CVSS forces an ALERT regardless of delta.
HIGH_CVSS_ALERT = 7.0
# Posture drop (negative delta) at/below this forces an ALERT.
RISK_DELTA_ALERT = -5


def _finding_cvss(finding):
    raw = finding.get("raw_data") or {}
    score = finding.get("cvss_score")
    if score is None:
        score = raw.get("cvss_score")
    try:
        return float(score) if score is not None else None
    except (TypeError, ValueError):
        return None


def _finding_penalty(finding):
    """Weighted penalty for a single finding."""
    cvss = _finding_cvss(finding)
    if cvss is not None and cvss > 0:
        # Quadratic so 9-10 dominates: CVSS 10 -> 30, 7 -> ~14.7, 4 -> ~4.8.
        return round((cvss / 10.0) ** 2 * 30.0, 2)
    sev = (finding.get("severity") or "INFO").upper()
    return _SEVERITY_PENALTY.get(sev, 2.0)


def calculate_posture_score(findings_list):
    """Return an integer 0-100 posture score for a list of findings."""
    if not findings_list:
        return 100
    total_penalty = sum(_finding_penalty(f) for f in findings_list)
    return max(0, min(100, round(100 - total_penalty)))


def severity_breakdown(findings_list):
    """Count findings by severity bucket (for the dashboard bar chart)."""
    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings_list or []:
        cvss = _finding_cvss(f)
        if cvss is not None and cvss > 0:
            from modules.intel.nvd_lookup import severity_from_score
            sev = severity_from_score(cvss)
        else:
            sev = (f.get("severity") or "INFO").upper()
        if sev not in buckets:
            sev = "INFO"
        buckets[sev] += 1
    return buckets


def classify_alert(risk_delta, new_findings):
    """
    Decide whether a monitoring run is an ALERT or OK (brief Section 6.2).
      * ALERT if posture dropped by >= 5 points (risk_delta <= -5), OR
      * ALERT if any NEW finding has CVSS >= 7.0.
    """
    if risk_delta is not None and risk_delta <= RISK_DELTA_ALERT:
        return "ALERT"
    for f in new_findings or []:
        cvss = _finding_cvss(f)
        if cvss is not None and cvss >= HIGH_CVSS_ALERT:
            return "ALERT"
        if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"):
            return "ALERT"
    return "OK"


if __name__ == "__main__":
    sample = [
        {"severity": "CRITICAL", "cvss_score": 10.0, "title": "Log4Shell"},
        {"severity": "MEDIUM", "title": "Missing HSTS"},
        {"severity": "LOW", "title": "Server header disclosed"},
    ]
    print("posture:", calculate_posture_score(sample))
    print("breakdown:", severity_breakdown(sample))
    print("alert:", classify_alert(-8, sample))
