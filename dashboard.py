#!/usr/bin/env python3
"""
NullShadow v4.0 — Defensive Monitoring Dashboard (brief Section 6.3)

A lightweight, READ-ONLY web dashboard over the existing SQLite database.
It does NOT run scans or duplicate scanning logic — it is purely a reporting
layer on top of data produced by the CLI (`python3 main.py --monitor <target>`).

Run separately:   python3 dashboard.py
Then open:        http://127.0.0.1:8077   (binds to localhost only)

Views:
  1. Posture score over time per target  (line chart, Chart.js via CDN)
  2. Findings count by severity           (bar chart)
  3. Recent monitoring runs               (table with ALERT/OK + risk_delta)
  4. Drill-down into a finding            (/finding/<id> shows its remediation block)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, request, render_template_string, abort

from null_db.db import ScanDatabase
from modules.intel.risk_score import severity_breakdown, calculate_posture_score

app = Flask(__name__)

# Bind to localhost only — this is a local reporting layer, not a control plane.
HOST = "127.0.0.1"
PORT = int(os.getenv("NULLSHADOW_DASHBOARD_PORT", "8077"))


def _db():
    # One short-lived connection per request (read-only usage).
    return ScanDatabase()


def _distinct_targets(db):
    cur = db.conn.execute(
        "SELECT DISTINCT target FROM scans WHERE target IS NOT NULL ORDER BY target")
    return [r["target"] for r in cur.fetchall()]


INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NullShadow — Defensive Monitoring Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    body { background:#0d0d0f; color:#e6e6e6; font-family:-apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:0 0 40px; }
    header { background:linear-gradient(90deg,#1a0000,#000); padding:18px 28px; border-bottom:2px solid #ff2222; }
    h1 { margin:0; font-size:20px; color:#ff4444; letter-spacing:2px; }
    .sub { color:#888; font-size:12px; }
    .wrap { max-width:1100px; margin:0 auto; padding:20px 28px; }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:22px; }
    .card { background:#16161a; border:1px solid #262630; border-radius:10px; padding:18px; }
    .card h2 { font-size:14px; color:#00aaff; margin:0 0 12px; text-transform:uppercase; letter-spacing:1px; }
    form { margin:0 0 16px; }
    select, button { background:#16161a; color:#e6e6e6; border:1px solid #333; border-radius:6px; padding:7px 10px; font-size:13px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #24242c; }
    th { color:#888; font-weight:600; }
    .alert { color:#ff4444; font-weight:700; }
    .ok { color:#33cc66; font-weight:700; }
    .pill { padding:2px 8px; border-radius:10px; font-size:11px; }
    a { color:#00aaff; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .muted { color:#777; font-size:12px; }
    .score { font-size:30px; font-weight:800; }
  </style>
</head>
<body>
  <header>
    <h1>🛡 NULLSHADOW · DEFENSIVE MONITORING</h1>
    <div class="sub">Read-only reporting layer · localhost only · data from <code>main.py --monitor</code></div>
  </header>
  <div class="wrap">
    <form method="get" action="/">
      <label class="muted">Target:&nbsp;</label>
      <select name="target" onchange="this.form.submit()">
        {% for t in targets %}
          <option value="{{t}}" {% if t==target %}selected{% endif %}>{{t}}</option>
        {% endfor %}
      </select>
      <noscript><button type="submit">Go</button></noscript>
    </form>

    {% if target %}
    <div class="card" style="margin-bottom:22px;">
      <h2>Current posture — {{target}}</h2>
      <span class="score" style="color:{{ '#33cc66' if latest_score>=70 else '#ffaa00' if latest_score>=40 else '#ff4444' }}">{{latest_score}}</span>
      <span class="muted">/ 100 &nbsp;({{ findings|length }} findings)</span>
    </div>
    {% endif %}

    <div class="grid">
      <div class="card">
        <h2>Posture over time</h2>
        <canvas id="postureChart" height="180"></canvas>
      </div>
      <div class="card">
        <h2>Findings by severity</h2>
        <canvas id="sevChart" height="180"></canvas>
      </div>
    </div>

    <div class="card" style="margin-top:22px;">
      <h2>Recent monitoring runs</h2>
      <table>
        <thead><tr><th>Scan</th><th>Target</th><th>Date</th><th>Posture</th><th>Δ Risk</th><th>Status</th></tr></thead>
        <tbody>
        {% for r in runs %}
          <tr>
            <td>#{{r['id']}}</td>
            <td>{{r['target']}}</td>
            <td class="muted">{{r['timestamp'][:16]}}</td>
            <td>{{r['posture_score']}}</td>
            <td>{{ ('+' ~ r['risk_delta']) if (r['risk_delta'] is not none and r['risk_delta']>0) else (r['risk_delta'] if r['risk_delta'] is not none else '—') }}</td>
            <td class="{{ 'alert' if r['alert_status']=='ALERT' else 'ok' }}">{{r['alert_status'] or '—'}}</td>
          </tr>
        {% endfor %}
        {% if not runs %}
          <tr><td colspan="6" class="muted">No monitoring runs yet. Run <code>python3 main.py --monitor &lt;target&gt;</code>.</td></tr>
        {% endif %}
        </tbody>
      </table>
    </div>

    <div class="card" style="margin-top:22px;">
      <h2>Findings {{ ('— ' ~ target) if target else '' }}</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Type</th><th>Title</th><th>CVE</th><th></th></tr></thead>
        <tbody>
        {% for f in findings[-40:] %}
          <tr>
            <td>{{f['id']}}</td>
            <td>{{f['severity']}}</td>
            <td class="muted">{{f['finding_type']}}</td>
            <td>{{f['title'][:60]}}</td>
            <td class="muted">{{ ', '.join(f['cve_ids']) }}</td>
            <td><a href="/finding/{{f['id']}}">remediation →</a></td>
          </tr>
        {% endfor %}
        {% if not findings %}
          <tr><td colspan="6" class="muted">No findings stored for this target yet.</td></tr>
        {% endif %}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    const postureData = {{ posture_json|safe }};
    const sevData = {{ sev_json|safe }};
    new Chart(document.getElementById('postureChart'), {
      type:'line',
      data:{ labels: postureData.labels,
        datasets:[{ label:'Posture score', data: postureData.scores,
          borderColor:'#00aaff', backgroundColor:'rgba(0,170,255,.15)', tension:.25, fill:true }] },
      options:{ scales:{ y:{ min:0, max:100, ticks:{color:'#888'} }, x:{ ticks:{color:'#888'} } },
        plugins:{ legend:{ labels:{ color:'#ccc' } } } }
    });
    new Chart(document.getElementById('sevChart'), {
      type:'bar',
      data:{ labels: Object.keys(sevData),
        datasets:[{ label:'Findings', data: Object.values(sevData),
          backgroundColor:['#ff2222','#ff7711','#ffcc00','#33aaff','#777'] }] },
      options:{ scales:{ y:{ beginAtZero:true, ticks:{color:'#888'} }, x:{ ticks:{color:'#888'} } },
        plugins:{ legend:{ display:false } } }
    });
  </script>
</body>
</html>
"""

FINDING_HTML = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Remediation — {{block.title}}</title>
<style>
  body { background:#0d0d0f; color:#e6e6e6; font-family:-apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:820px; margin:0 auto; padding:30px; }
  h1 { color:#33cc66; font-size:20px; }
  h2 { color:#00aaff; font-size:14px; text-transform:uppercase; letter-spacing:1px; margin-top:22px; }
  pre { background:#101014; border:1px solid #262630; border-radius:8px; padding:14px; overflow:auto; color:#7CFC9B; }
  .meta { color:#aaa; }
  a { color:#00aaff; } li { margin:4px 0; }
  .ref { color:#ffaa00; }
</style></head><body><div class="wrap">
  <a href="/">← back to dashboard</a>
  <h1>🛡 Guided Remediation</h1>
  <p><b>{{block.title}}</b></p>
  <p class="meta">{{block.severity_context}}<br>{{block.cwe}} · {{block.owasp}}</p>
  <h2>Explanation</h2><p>{{block.explanation}}</p>
  {% if block.ai_explanation %}<h2>AI analysis</h2><p>{{block.ai_explanation}}</p>{% endif %}
  <h2>Remediation steps</h2>
  <ol>{% for s in block.remediation_steps %}<li>{{s}}</li>{% endfor %}</ol>
  <h2>Secure pattern (generic)</h2>
  <pre>{{block.secure_snippet}}</pre>
  {% if block.exploit_reference %}<p class="ref">{{block.exploit_reference}}</p>{% endif %}
</div></body></html>
"""


@app.route("/")
def index():
    db = _db()
    try:
        targets = _distinct_targets(db)
        target = request.args.get("target") or (targets[0] if targets else None)

        findings = db.get_findings(target=target) if target else []
        posture_rows = db.get_posture_history(target) if target else []
        posture_json = {
            "labels": [str(r["timestamp"])[:16] for r in posture_rows],
            "scores": [r["posture_score"] for r in posture_rows],
        }
        sev_json = severity_breakdown(findings)
        latest_score = calculate_posture_score(findings) if findings else 100
        runs = [dict(r) for r in db.get_monitor_runs()]

        import json as _json
        return render_template_string(
            INDEX_HTML, targets=targets, target=target, findings=findings,
            runs=runs, latest_score=latest_score,
            posture_json=_json.dumps(posture_json), sev_json=_json.dumps(sev_json))
    finally:
        db.close()


@app.route("/finding/<int:finding_id>")
def finding(finding_id):
    db = _db()
    try:
        cur = db.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        if not row:
            abort(404)
        f = db._row_to_finding(row)
        from modules.intel.remediation import generate_remediation
        block = generate_remediation(f, use_ai=False)
        return render_template_string(FINDING_HTML, block=block)
    finally:
        db.close()


if __name__ == "__main__":
    print(f"NullShadow dashboard (read-only) → http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
