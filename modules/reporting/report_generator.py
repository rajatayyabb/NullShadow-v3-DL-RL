import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class ReportGenerator:

    def __init__(self):
        # Always save to ~/NullShadow/reports/ — never use relative paths
        self.report_dir = os.path.join(os.path.expanduser("~"), "NullShadow", "reports")
        os.makedirs(self.report_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.title_style = ParagraphStyle(
            'NSTitle', parent=self.styles['Title'],
            fontSize=22, textColor=colors.HexColor('#FF2222'),
            spaceAfter=10, alignment=TA_CENTER, fontName='Helvetica-Bold'
        )
        self.heading_style = ParagraphStyle(
            'NSHeading', parent=self.styles['Heading1'],
            fontSize=13, textColor=colors.HexColor('#00AAFF'),
            spaceBefore=14, spaceAfter=6, fontName='Helvetica-Bold'
        )
        self.subheading_style = ParagraphStyle(
            'NSSubHeading', parent=self.styles['Heading2'],
            fontSize=10, textColor=colors.HexColor('#FFAA00'),
            spaceBefore=8, spaceAfter=4, fontName='Helvetica-Bold'
        )
        self.body_style = ParagraphStyle(
            'NSBody', parent=self.styles['Normal'],
            fontSize=9, textColor=colors.HexColor('#222222'),
            spaceAfter=3, leading=13
        )
        self.code_style = ParagraphStyle(
            'NSCode', parent=self.styles['Normal'],
            fontSize=8, fontName='Courier',
            textColor=colors.HexColor('#005500'),
            backColor=colors.HexColor('#F0F0F0'),
            spaceAfter=3, leading=11, leftIndent=8
        )

    def generate(self, recon_results, ai_analysis="", target=""):
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name  = (target or "scan").replace(".", "_").replace("/", "_").replace(":", "_")
        filename   = f"NullShadow_{safe_name}_{timestamp}.pdf"
        filepath   = os.path.join(self.report_dir, filename)

        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            rightMargin=0.7*inch, leftMargin=0.7*inch,
            topMargin=0.9*inch, bottomMargin=0.7*inch
        )
        story = []

        # ── Cover Page ────────────────────────────────────────
        story.append(Spacer(1, 0.4*inch))
        story.append(Paragraph("NULLSHADOW", self.title_style))
        story.append(Paragraph("Autonomous Penetration Testing Report", self.styles['Heading2']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#FF2222')))
        story.append(Spacer(1, 0.15*inch))

        meta = [
            ["Target",        target or recon_results.get("target", "N/A")],
            ["Scan Date",     recon_results.get("timestamp", datetime.now().isoformat())[:19]],
            ["Generated",     datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Classification","CONFIDENTIAL — Authorized Testing Only"],
            ["Framework",     "NullShadow v2.0 by Tayyab"],
        ]
        mt = Table(meta, colWidths=[1.8*inch, 4.2*inch])
        mt.setStyle(TableStyle([
            ('BACKGROUND',  (0,0),(0,-1), colors.HexColor('#1A1A1A')),
            ('TEXTCOLOR',   (0,0),(0,-1), colors.white),
            ('BACKGROUND',  (1,0),(1,-1), colors.HexColor('#F7F7F7')),
            ('FONTNAME',    (0,0),(-1,-1),'Helvetica'),
            ('FONTSIZE',    (0,0),(-1,-1), 9),
            ('GRID',        (0,0),(-1,-1), 0.4, colors.grey),
            ('PADDING',     (0,0),(-1,-1), 7),
            ('FONTNAME',    (0,0),(0,-1), 'Helvetica-Bold'),
        ]))
        story.append(mt)
        story.append(PageBreak())

        # ── Executive Summary ─────────────────────────────────
        story.append(Paragraph("Executive Summary", self.heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00AAFF')))
        story.append(Spacer(1, 0.08*inch))

        # Count findings
        ports = recon_results.get("🔌 Port Scan", {})
        port_count = ports.get("count", 0) if isinstance(ports, dict) else 0
        vulns = recon_results.get("💀 Vulnerability Scan", {})
        vuln_count = vulns.get("count", 0) if isinstance(vulns, dict) else 0
        subs = recon_results.get("🌐 Subdomain Enum", {})
        sub_count = subs.get("count", 0) if isinstance(subs, dict) else 0

        summary = (
            f"This report presents the results of an autonomous security assessment conducted against "
            f"<b>{target}</b> using NullShadow v2.0. The assessment identified <b>{port_count} open ports</b>, "
            f"<b>{vuln_count} potential vulnerabilities</b>, and <b>{sub_count} subdomains</b>. "
            f"Findings are detailed in the sections below with AI-generated analysis and remediation recommendations."
        )
        story.append(Paragraph(summary, self.body_style))
        story.append(Spacer(1, 0.1*inch))

        # ── AI Analysis ───────────────────────────────────────
        if ai_analysis and ai_analysis != "No AI key configured.":
            story.append(Paragraph("AI-Powered Analysis & Recommendations", self.heading_style))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00AAFF')))
            story.append(Spacer(1, 0.08*inch))
            for line in ai_analysis.split('\n'):
                line = line.strip()
                if not line:
                    story.append(Spacer(1, 3))
                    continue
                line_safe = line.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                if line.startswith('## ') or line.startswith('# '):
                    story.append(Paragraph(line.lstrip('#').strip(), self.subheading_style))
                elif line.startswith('- ') or line.startswith('* ') or line.startswith('• '):
                    story.append(Paragraph(f"• {line[2:]}", self.body_style))
                elif line.startswith('**') and line.endswith('**'):
                    story.append(Paragraph(f"<b>{line[2:-2]}</b>", self.body_style))
                else:
                    story.append(Paragraph(line_safe, self.body_style))
            story.append(PageBreak())

        # ── Recon Results ─────────────────────────────────────
        story.append(Paragraph("Detailed Scan Results", self.heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00AAFF')))

        for phase, data in recon_results.items():
            if phase in ("target", "timestamp"):
                continue
            story.append(Spacer(1, 0.12*inch))
            story.append(Paragraph(str(phase), self.subheading_style))

            if isinstance(data, dict):
                if data.get("error"):
                    story.append(Paragraph(f"Error: {data['error'][:100]}", self.body_style))
                    continue

                # Open ports table
                if "open_ports" in data and data["open_ports"]:
                    rows = [["Port", "Service", "Product", "Version"]]
                    for p in data["open_ports"]:
                        rows.append([str(p.get("port","")), p.get("service",""),
                                     p.get("product","")[:30], p.get("version","")[:30]])
                    t = Table(rows, colWidths=[0.7*inch,1.2*inch,2.2*inch,1.9*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1A1A1A')),
                        ('TEXTCOLOR', (0,0),(-1,0),colors.white),
                        ('FONTSIZE',  (0,0),(-1,-1),8),
                        ('GRID',      (0,0),(-1,-1),0.4,colors.grey),
                        ('PADDING',   (0,0),(-1,-1),5),
                        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#F5F5F5')]),
                        ('FONTNAME',  (0,0),(-1,0),'Helvetica-Bold'),
                    ]))
                    story.append(t)

                # Subdomains table
                elif "found" in data and data["found"]:
                    rows = [["Subdomain", "IP Address"]]
                    for s in data["found"]:
                        rows.append([s.get("subdomain",""), s.get("ip","")])
                    t = Table(rows, colWidths=[4*inch,2*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1A1A1A')),
                        ('TEXTCOLOR', (0,0),(-1,0),colors.white),
                        ('FONTSIZE',  (0,0),(-1,-1),8),
                        ('GRID',      (0,0),(-1,-1),0.4,colors.grey),
                        ('PADDING',   (0,0),(-1,-1),5),
                    ]))
                    story.append(t)

                # Vulnerabilities
                elif "vulnerabilities" in data and data["vulnerabilities"]:
                    rows = [["Port", "Script", "Finding"]]
                    for v in data["vulnerabilities"]:
                        rows.append([str(v.get("port","")), v.get("script",""), v.get("finding","")[:80]])
                    t = Table(rows, colWidths=[0.7*inch,1.5*inch,3.8*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#8B0000')),
                        ('TEXTCOLOR', (0,0),(-1,0),colors.white),
                        ('FONTSIZE',  (0,0),(-1,-1),8),
                        ('GRID',      (0,0),(-1,-1),0.4,colors.grey),
                        ('PADDING',   (0,0),(-1,-1),5),
                    ]))
                    story.append(t)

                # Generic key-value
                else:
                    dump = json.dumps(data, indent=2, default=str)
                    for line in dump.split('\n')[:25]:
                        safe = line.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                        story.append(Paragraph(safe, self.code_style))
            else:
                story.append(Paragraph(str(data)[:300], self.body_style))

        # ── Footer note ───────────────────────────────────────
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Paragraph(
            "This report was generated by NullShadow v2.0 — For authorized testing only. "
            "Developed by Tayyab | github.com/rajatayyabb",
            ParagraphStyle('footer', parent=self.styles['Normal'],
                           fontSize=7, textColor=colors.grey, alignment=TA_CENTER)
        ))

        doc.build(story)
        return filepath
