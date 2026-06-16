import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import sqlite3
import json
from datetime import datetime
from rich.table import Table
from rich.console import Console
from config.config import DB_PATH

console = Console()


class ScanDatabase:

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                results TEXT,
                ai_analysis TEXT,
                report_path TEXT,
                threat_score INTEGER DEFAULT 0
            )
        ''')

        # Phase 1: normalized per-finding records (alongside the scans blob).
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                target TEXT,
                finding_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                cve_ids TEXT,
                raw_data TEXT,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')

        # Phase 1: local cache of NVD CVE lookups (respects NVD rate limits).
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT,
                fetched_at TEXT
            )
        ''')

        # Phase 6: monitoring columns on scans (additive migration).
        for col, ddl in (
            ("posture_score", "INTEGER"),
            ("alert_status",  "TEXT"),
            ("risk_delta",    "INTEGER"),
        ):
            try:
                self.conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError:
                pass  # column already exists

        self.conn.commit()

    # ── Scans ──────────────────────────────────────────────────
    def save_scan(self, target, scan_type, results, ai_analysis="", report_path="", threat_score=0):
        try:
            cur = self.conn.execute('''
                INSERT INTO scans (target, scan_type, timestamp, results, ai_analysis, report_path, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (target, scan_type, datetime.now().isoformat(),
                  json.dumps(results, default=str), ai_analysis, report_path, threat_score))
            self.conn.commit()
            return cur.lastrowid
        except Exception as e:
            # A DB write failure (e.g. disk full / locked) must not crash the app.
            console.print(f"[yellow]⚠ Could not save scan to DB: {e}[/yellow]")
            return None

    def update_scan_monitor(self, scan_id, posture_score=None, alert_status=None, risk_delta=None):
        """Record Phase 6 monitoring outcome for a scan."""
        if scan_id is None:
            return
        try:
            self.conn.execute(
                'UPDATE scans SET posture_score = ?, alert_status = ?, risk_delta = ? WHERE id = ?',
                (posture_score, alert_status, risk_delta, scan_id)
            )
            self.conn.commit()
        except Exception as e:
            console.print(f"[yellow]⚠ Could not update monitor result: {e}[/yellow]")

    def get_history(self, limit=20):
        cur = self.conn.execute(
            'SELECT id, target, scan_type, timestamp, threat_score, report_path FROM scans ORDER BY id DESC LIMIT ?',
            (limit,)
        )
        return cur.fetchall()

    def get_scan(self, scan_id):
        cur = self.conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        return cur.fetchone()

    def get_scans_for_target(self, target, limit=50):
        """All scans for one target, newest first (used by Scan Diff)."""
        cur = self.conn.execute(
            'SELECT id, target, scan_type, timestamp, threat_score, posture_score '
            'FROM scans WHERE target = ? ORDER BY id DESC LIMIT ?',
            (target, limit)
        )
        return cur.fetchall()

    def get_monitor_runs(self, limit=50):
        """Recent scans that have a monitoring outcome (Phase 6 dashboard)."""
        cur = self.conn.execute(
            'SELECT id, target, scan_type, timestamp, posture_score, alert_status, risk_delta '
            'FROM scans WHERE alert_status IS NOT NULL ORDER BY id DESC LIMIT ?',
            (limit,)
        )
        return cur.fetchall()

    def get_posture_history(self, target, limit=100):
        """Posture score over time for one target (ascending), for charting."""
        cur = self.conn.execute(
            'SELECT id, timestamp, posture_score FROM scans '
            'WHERE target = ? AND posture_score IS NOT NULL ORDER BY id ASC LIMIT ?',
            (target, limit)
        )
        return cur.fetchall()

    def display_history(self):
        rows = self.get_history()
        table = Table(title="[bold cyan]Scan History[/bold cyan]", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="white", width=5)
        table.add_column("Target", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Date", style="white")
        table.add_column("Threat Score", style="red")
        table.add_column("Report", style="green")

        for row in rows:
            score = str(row["threat_score"]) if row["threat_score"] else "N/A"
            report = "✓" if row["report_path"] else "—"
            table.add_row(str(row["id"]), row["target"], row["scan_type"],
                          str(row["timestamp"])[:16], score, report)

        console.print(table)
        return rows

    def delete_scan(self, scan_id):
        self.conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        self.conn.execute('DELETE FROM findings WHERE scan_id = ?', (scan_id,))
        self.conn.commit()

    # ── Findings (Phase 1) ─────────────────────────────────────
    def add_finding(self, target, finding_type, title, description="",
                    severity="INFO", cve_ids=None, raw_data=None, scan_id=None):
        """Insert one normalized finding. Returns the new finding id (or None)."""
        try:
            cur = self.conn.execute('''
                INSERT INTO findings
                    (scan_id, target, finding_type, severity, title, description, cve_ids, raw_data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id, target, finding_type, severity, title, description,
                json.dumps(cve_ids or [], default=str),
                json.dumps(raw_data or {}, default=str),
                datetime.now().isoformat(),
            ))
            self.conn.commit()
            return cur.lastrowid
        except Exception as e:
            console.print(f"[yellow]⚠ Could not save finding to DB: {e}[/yellow]")
            return None

    def _row_to_finding(self, row):
        d = dict(row)
        try:
            d["cve_ids"] = json.loads(d.get("cve_ids") or "[]")
        except Exception:
            d["cve_ids"] = []
        try:
            d["raw_data"] = json.loads(d.get("raw_data") or "{}")
        except Exception:
            d["raw_data"] = {}
        return d

    def get_findings(self, target=None, scan_id=None):
        """Fetch findings, optionally filtered by target and/or scan_id."""
        q = 'SELECT * FROM findings'
        clauses, params = [], []
        if target is not None:
            clauses.append('target = ?'); params.append(target)
        if scan_id is not None:
            clauses.append('scan_id = ?'); params.append(scan_id)
        if clauses:
            q += ' WHERE ' + ' AND '.join(clauses)
        q += ' ORDER BY id ASC'
        cur = self.conn.execute(q, params)
        return [self._row_to_finding(r) for r in cur.fetchall()]

    def get_findings_by_cve(self, cve_id):
        """Every finding that references the given CVE id."""
        cve_id = (cve_id or "").upper()
        cur = self.conn.execute('SELECT * FROM findings ORDER BY id ASC')
        out = []
        for r in cur.fetchall():
            f = self._row_to_finding(r)
            if cve_id in [c.upper() for c in f.get("cve_ids", [])]:
                out.append(f)
        return out

    # ── CVE cache (Phase 1) ────────────────────────────────────
    def get_cached_cve(self, cve_id):
        cur = self.conn.execute('SELECT data FROM cve_cache WHERE cve_id = ?', (cve_id.upper(),))
        row = cur.fetchone()
        if row and row["data"]:
            try:
                return json.loads(row["data"])
            except Exception:
                return None
        return None

    def cache_cve(self, cve_id, data):
        self.conn.execute(
            'INSERT OR REPLACE INTO cve_cache (cve_id, data, fetched_at) VALUES (?, ?, ?)',
            (cve_id.upper(), json.dumps(data, default=str), datetime.now().isoformat())
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
