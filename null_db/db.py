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
        self.conn.commit()

    def save_scan(self, target, scan_type, results, ai_analysis="", report_path="", threat_score=0):
        self.conn.execute('''
            INSERT INTO scans (target, scan_type, timestamp, results, ai_analysis, report_path, threat_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (target, scan_type, datetime.now().isoformat(),
              json.dumps(results, default=str), ai_analysis, report_path, threat_score))
        self.conn.commit()

    def get_history(self, limit=20):
        cur = self.conn.execute(
            'SELECT id, target, scan_type, timestamp, threat_score, report_path FROM scans ORDER BY id DESC LIMIT ?',
            (limit,)
        )
        return cur.fetchall()

    def get_scan(self, scan_id):
        cur = self.conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        return cur.fetchone()

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
            score = str(row[4]) if row[4] else "N/A"
            report = "✓" if row[5] else "—"
            table.add_row(str(row[0]), row[1], row[2], row[3][:16], score, report)

        console.print(table)
        return rows

    def delete_scan(self, scan_id):
        self.conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        self.conn.commit()

    def close(self):
        self.conn.close()
