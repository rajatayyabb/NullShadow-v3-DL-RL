"""
Scan Diff module (brief Section 2).

diff_scans(target, scan_id_a, scan_id_b) compares two scans of the same target
(by their normalized findings, Phase 1) and reports:
  * new findings      — present in B but not A
  * resolved findings — present in A but not B
  * changed findings  — same identity but different severity/details
  * risk_delta        — posture(B) - posture(A)   (Phase 6 extension)

Output is a rich Table, consistent with the rest of NullShadow.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from rich.table import Table
from rich.console import Console

console = Console()


def _finding_key(f):
    """Identity of a finding: type + title (severity-independent)."""
    return (str(f.get("finding_type", "")).strip().lower(),
            str(f.get("title", "")).strip().lower())


def _severity_of(f):
    return (f.get("severity") or "INFO").upper()


def diff_scans(target, scan_id_a, scan_id_b, db=None):
    """
    Compare two scans' findings. Returns a dict:
      { target, scan_id_a, scan_id_b,
        new: [...], resolved: [...], changed: [...],
        score_a, score_b, risk_delta }
    `db` is a ScanDatabase; if None one is created.
    """
    own_db = False
    if db is None:
        from null_db.db import ScanDatabase
        db = ScanDatabase()
        own_db = True

    try:
        findings_a = db.get_findings(scan_id=scan_id_a)
        findings_b = db.get_findings(scan_id=scan_id_b)

        map_a = {_finding_key(f): f for f in findings_a}
        map_b = {_finding_key(f): f for f in findings_b}

        new = [f for k, f in map_b.items() if k not in map_a]
        resolved = [f for k, f in map_a.items() if k not in map_b]

        changed = []
        for k in set(map_a) & set(map_b):
            fa, fb = map_a[k], map_b[k]
            if _severity_of(fa) != _severity_of(fb) or \
               (fa.get("description") or "") != (fb.get("description") or ""):
                changed.append({
                    "title": fb.get("title"),
                    "finding_type": fb.get("finding_type"),
                    "old_severity": _severity_of(fa),
                    "new_severity": _severity_of(fb),
                })

        # Phase 6: posture delta between the two scans.
        from modules.intel.risk_score import calculate_posture_score
        score_a = calculate_posture_score(findings_a)
        score_b = calculate_posture_score(findings_b)
        risk_delta = score_b - score_a

        return {
            "target": target,
            "scan_id_a": scan_id_a,
            "scan_id_b": scan_id_b,
            "new": new,
            "resolved": resolved,
            "changed": changed,
            "score_a": score_a,
            "score_b": score_b,
            "risk_delta": risk_delta,
        }
    finally:
        if own_db:
            db.close()


def _exploit_note(cve_ids):
    try:
        from modules.intel.exploit_refs import format_ref_line
        for c in cve_ids or []:
            line = format_ref_line(c)
            if line:
                return line
    except Exception:
        pass
    return ""


def render_diff(diff, console=None):
    """Print a scan diff as a rich Table."""
    console = console or globals()["console"]

    delta = diff["risk_delta"]
    delta_color = "green" if delta > 0 else "red" if delta < 0 else "yellow"
    sign = "+" if delta > 0 else ""
    console.print(
        f"\n[bold]Scan Diff for [cyan]{diff['target']}[/cyan][/bold]  "
        f"(scan #{diff['scan_id_a']} → #{diff['scan_id_b']})\n"
        f"Posture: [white]{diff['score_a']}[/white] → [white]{diff['score_b']}[/white]  "
        f"Risk delta: [{delta_color}]{sign}{delta}[/{delta_color}]"
    )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Change", width=10)
    table.add_column("Severity", width=14)
    table.add_column("Finding", style="white")
    table.add_column("Exploit Ref", style="yellow")

    for f in diff["new"]:
        table.add_row("[red]NEW[/red]", _severity_of(f),
                      str(f.get("title", "")), _exploit_note(f.get("cve_ids")))
    for f in diff["resolved"]:
        table.add_row("[green]RESOLVED[/green]", _severity_of(f),
                      str(f.get("title", "")), "")
    for c in diff["changed"]:
        table.add_row("[yellow]CHANGED[/yellow]",
                      f"{c['old_severity']}→{c['new_severity']}",
                      str(c.get("title", "")), "")

    if not (diff["new"] or diff["resolved"] or diff["changed"]):
        table.add_row("—", "—", "No differences between these scans", "")

    console.print(table)


if __name__ == "__main__":
    # Minimal self-test using an in-memory-style temp DB.
    from null_db.db import ScanDatabase
    db = ScanDatabase()
    a = db.save_scan("difftest.local", "Test", {})
    b = db.save_scan("difftest.local", "Test", {})
    db.add_finding("difftest.local", "ssl_audit", "TLS 1.0 supported", severity="MEDIUM", scan_id=a)
    db.add_finding("difftest.local", "ssl_audit", "TLS 1.0 supported", severity="HIGH", scan_id=b)
    db.add_finding("difftest.local", "vuln", "Log4Shell", severity="CRITICAL",
                   cve_ids=["CVE-2021-44228"], raw_data={"cvss_score": 10.0}, scan_id=b)
    d = diff_scans("difftest.local", a, b, db=db)
    render_diff(d)
    db.delete_scan(a); db.delete_scan(b)
    db.close()
