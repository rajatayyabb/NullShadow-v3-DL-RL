import sys
import os
import time
import argparse

# Robust path detection for the project root
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.columns import Columns

# Use absolute imports from the project root
try:
    from modules.pentesting.scanner import AdvancedPentestModules
    from modules.pentesting.new_tools import NewPentestTools
    from modules.osint.osint_tools import OSINTModules
    from modules.utilities.util_tools import UtilityModules
    from modules.ai.ai_engine import AIEngine, get_active_ai_engine
    from modules.recon.recon_pipeline import ReconPipeline
    from modules.ai.orchestrator import AutonomousOrchestrator
    from modules.pentesting.iot_sec import IoTSecurityModules
    from modules.reporting.report_generator import ReportGenerator
    from null_db.db import ScanDatabase
except ImportError as e:
    # Fallback/Debug for import issues
    print(f"Error importing modules: {e}")
    print(f"Current sys.path: {sys.path}")
    sys.exit(1)

console  = Console()
pentest  = AdvancedPentestModules()
newtools = NewPentestTools()
osint    = OSINTModules()
utils    = UtilityModules()
ai       = get_active_ai_engine()   # local by default; never errors without a cloud key
recon    = ReconPipeline()
orchestrator = AutonomousOrchestrator()
iot_sec  = IoTSecurityModules()
reporter = ReportGenerator()
db       = ScanDatabase()


def display_banner():
    banner = """
  ███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ████╗  ██║██║   ██║██║     ██║         ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ██╔██╗ ██║██║   ██║██║     ██║         ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ██║╚██╗██║██║   ██║██║     ██║         ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ██║ ╚████║╚██████╔╝███████╗███████╗    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
          [ AI-POWERED AUTONOMOUS PENETRATION TESTING FRAMEWORK ]
                  [ Developed by Tayyab  |  github.com/rajatayyabb ]
    """
    console.print(Text(banner, style="bold red"))
    # Show whether the local AI server is reachable (health endpoint)
    try:
        server_up = False
        if hasattr(ai, 'local_ai') and getattr(ai.local_ai, '_is_server_available', None):
            server_up = ai.local_ai._is_server_available()
        server_status = "[green]● Local AI server[/green]" if server_up else "[yellow]● Local fallback[/yellow]"
    except Exception:
        server_status = "[yellow]● Local fallback[/yellow]"

    # Default AI indicator shows LOCAL when no cloud key/engine is active (Phase 0.3).
    is_cloud = getattr(ai, "is_cloud", lambda: False)()
    ai_label = (ai.active_ai or "local").upper() if is_cloud else "LOCAL"
    ai_status = f"[green]●[/green] {ai_label}"
    console.print(f"  AI Engine: {ai_status}   {server_status}     DB: [green]●[/green] Connected     Version: [cyan]v4.0 (DL/RL + Defensive Monitoring)[/cyan]  Tools: [yellow]26[/yellow]\n", justify="center")


def display_menu():
    t1 = Table(show_header=True, header_style="bold red", box=None, padding=(0,1))
    t1.add_column("💀 PENTESTING", style="cyan")
    t1.add_row("[01] Port Scanner")
    t1.add_row("[02] Vulnerability Scanner")
    t1.add_row("[03] Host Discovery")
    t1.add_row("[04] IP Pinger")
    t1.add_row("[05] Dir Bruteforcer")
    t1.add_row("[06] SSL/TLS Auditor")
    t1.add_row("[07] Hash ID & Cracker")
    t1.add_row("[08] JWT Analyzer")
    t1.add_row("[09] Subdomain Enumerator")
    t1.add_row("[10] DNS Recon")
    t1.add_row("[11] HTTP Header Analyzer")

    t2 = Table(show_header=True, header_style="bold yellow", box=None, padding=(0,1))
    t2.add_column("👁  OSINT", style="yellow")
    t2.add_row("[12] Domain WHOIS")
    t2.add_row("[13] Username Tracker")
    t2.add_row("[14] IP Geolocation")
    t2.add_row("[15] Phone Lookup")
    t2.add_row("[16] Email Harvester")
    t2.add_row("[17] CVE Search")
    t2.add_row("")
    t2.add_row("")
    t2.add_row("")
    t2.add_row("")
    t2.add_row("")

    t3 = Table(show_header=True, header_style="bold magenta", box=None, padding=(0,1))
    t3.add_column("🤖 AI & UTILITIES", style="magenta")
    t3.add_row("[18] URL Phishing Analyzer")
    t3.add_row("[19] Website Cloner")
    t3.add_row("[20] Cookie Auditor")
    t3.add_row("[21] Network Info")
    t3.add_row("[22] Password Generator")
    t3.add_row("[23] 🧠 DL Firmware Analysis")
    t3.add_row("[24] 💡 Neural Fuzz IoT")
    t3.add_row("[31] 🔄 RL Simulation")
    t3.add_row("[32] 🎭 Deception Demo")
    t3.add_row("[33] 🔄 Self-Correcting Loop")
    t3.add_row("──────────────────────")
    t3.add_row("[25] 🤖 AI Chat Mode")
    t3.add_row("[26] 🚀 AUTO FULL RECON")
    t3.add_row("[27] 📄 Generate PDF Report")
    t3.add_row("[28] 📊 Scan History")
    t3.add_row("[30] 🚀 AUTO PENTEST (DL/RL)")
    t3.add_row("──────────────────────")
    t3.add_row("[34] 🔀 Scan Diff")
    t3.add_row("[35] 🛡  Guided Remediation")
    t3.add_row("[36] 🧬 Findings + CVE Enrich")

    console.print(Panel(Columns([t1, t2, t3]),
                        title="[bold white]━━━  N U L L S H A D O W   v4.0  ━━━  [ 26 TOOLS ]  ━━━[/bold white]",
                        border_style="red"))


def switch_ai():
    console.print("\n[cyan]Local-only AI mode is active. No cloud API switching is available.[/cyan]")
    ai.set_ai("local")


# ── v4.0 helper menus ──────────────────────────────────────────
def scan_diff_menu():
    """[34] List previous scans for a target and diff two of them (Phase 2)."""
    from modules.intel.scan_diff import diff_scans, render_diff
    target = Prompt.ask("Target to compare scans for (e.g. example.com)")
    rows = db.get_scans_for_target(target)
    if len(rows) < 2:
        console.print(f"[yellow]Need at least 2 scans for '{target}'. Found {len(rows)}. "
                      "Run some scans (e.g. option 02/17/26 or --monitor) first.[/yellow]")
        return

    t = Table(title=f"Scans for {target}", header_style="bold cyan")
    t.add_column("ID", style="white"); t.add_column("Type", style="yellow")
    t.add_column("Date", style="white"); t.add_column("Posture", style="green")
    for r in rows:
        posture = str(r["posture_score"]) if r["posture_score"] is not None else "—"
        t.add_row(str(r["id"]), r["scan_type"], str(r["timestamp"])[:16], posture)
    console.print(t)

    try:
        a = int(Prompt.ask("Older scan ID (A)"))
        b = int(Prompt.ask("Newer scan ID (B)"))
    except ValueError:
        console.print("[red]Invalid scan IDs.[/red]")
        return
    diff = diff_scans(target, a, b, db=db)
    render_diff(diff, console)


def findings_menu():
    """[36] Browse stored findings with CVE/exploit enrichment (Phase 1 + 3)."""
    from modules.intel.exploit_refs import format_ref_line
    from modules.intel.risk_score import calculate_posture_score
    target = Prompt.ask("Filter by target (blank = all)", default="").strip()
    findings = db.get_findings(target=target or None)
    if not findings:
        console.print("[yellow]No findings stored yet. Run option 02/17/26 or --monitor first.[/yellow]")
        return

    t = Table(title=f"Stored Findings{f' — {target}' if target else ''}",
              header_style="bold red")
    t.add_column("ID", width=5); t.add_column("Severity", width=10)
    t.add_column("Type", width=14); t.add_column("Title", style="white")
    t.add_column("CVE / Exploit Ref", style="yellow")
    for f in findings[-40:]:
        cves = ", ".join(f.get("cve_ids", []))
        ref = ""
        for c in f.get("cve_ids", []):
            ref = format_ref_line(c)
            if ref:
                break
        sev = (f.get("severity") or "INFO").upper()
        color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "green"
        t.add_row(str(f["id"]), f"[{color}]{sev}[/{color}]", f.get("finding_type", ""),
                  str(f.get("title", ""))[:50], (cves + ("  " + ref if ref else "")).strip())
    console.print(t)
    console.print(f"\n[bold]Posture score for these findings:[/bold] "
                  f"[cyan]{calculate_posture_score(findings)}/100[/cyan]")


def run_monitor(target):
    """
    Phase 6 monitor mode: run a full recon pass, persist findings, score the
    security posture, compare against the previous run, and flag ALERT/OK.
    Invoked via:  python3 main.py --monitor <target>
    Schedule it with cron/systemd (see README) for continuous monitoring.
    """
    from modules.intel.findings_extract import extract_findings_from_recon, persist_findings
    from modules.intel.risk_score import calculate_posture_score, classify_alert
    from modules.intel.scan_diff import diff_scans
    from modules.intel.remediation import generate_remediation, render_block

    console.print(Panel(f"[bold cyan]🛡  NullShadow Monitor[/bold cyan]\nTarget: {target}",
                        border_style="cyan"))

    results = recon.run_full_recon(target)
    recon.display_summary()

    scan_id = db.save_scan(target, "Monitor", results)
    findings = extract_findings_from_recon(results, db=db)
    persist_findings(db, scan_id, findings)
    posture = calculate_posture_score(findings)

    # Previous run for this target (the row before the one we just inserted).
    prior = [r for r in db.get_scans_for_target(target) if r["id"] != scan_id]
    risk_delta, new_findings = None, findings
    if prior:
        prev_id = prior[0]["id"]
        prev_score = prior[0]["posture_score"]
        if prev_score is None:
            prev_score = calculate_posture_score(db.get_findings(scan_id=prev_id))
        risk_delta = posture - prev_score
        try:
            d = diff_scans(target, prev_id, scan_id, db=db)
            new_findings = d["new"]
        except Exception:
            pass

    status = classify_alert(risk_delta, new_findings)
    db.update_scan_monitor(scan_id, posture_score=posture, alert_status=status,
                           risk_delta=risk_delta)

    delta_txt = "n/a (first run)" if risk_delta is None else f"{'+' if risk_delta > 0 else ''}{risk_delta}"
    status_style = "bold red" if status == "ALERT" else "bold green"
    console.print(Panel(
        f"Posture score: [cyan]{posture}/100[/cyan]\n"
        f"Risk delta vs previous run: {delta_txt}\n"
        f"Status: [{status_style}]{status}[/{status_style}]   (scan #{scan_id})",
        title="[bold]Monitoring Result[/bold]",
        border_style="red" if status == "ALERT" else "green"))

    # Each ALERT-worthy new finding gets a Guided Remediation block (Section 6.2).
    if status == "ALERT" and new_findings:
        console.print("\n[bold red]ALERT — remediation guidance for new/changed findings:[/bold red]")
        for f in new_findings[:10]:
            try:
                block = generate_remediation(f, use_ai=False)
                render_block(block, console)
            except Exception:
                continue

    return {"scan_id": scan_id, "posture": posture, "risk_delta": risk_delta, "status": status}


def handle_choice(choice, state):
    """Dispatch a single menu choice. `state` carries the last recon results and
    AI analysis between iterations. Raises SystemExit on exit/quit."""
    # ── Pentesting ─────────────────────────────────────────
    if choice == '01':
        t = Prompt.ask("Target IP/Domain")
        console.print(pentest.port_scanner(t))
        db.save_scan(t, "Port Scan", {})

    elif choice == '02':
        t = Prompt.ask("Target IP/Domain")
        scan_id = db.save_scan(t, "Vuln Scan", {})
        console.print(pentest.vulnerability_scanner(t, db=db, scan_id=scan_id))

    elif choice == '03':
        n = Prompt.ask("Network (e.g. 192.168.1.0/24)")
        console.print(pentest.host_discovery(n))

    elif choice == '04':
        t = Prompt.ask("Target IP")
        console.print(pentest.ip_pinger(t))

    elif choice == '05':
        u = Prompt.ask("Target URL (e.g. http://example.com)")
        console.print(pentest.dir_bruteforce(u))
        db.save_scan(u, "Dir Bruteforce", {})

    elif choice == '06':
        t = Prompt.ask("Target domain (e.g. example.com)")
        console.print(pentest.ssl_scanner(t))

    elif choice == '07':
        h = Prompt.ask("Enter hash to crack")
        console.print(pentest.hash_identifier_cracker(h))

    elif choice == '08':
        j = Prompt.ask("Paste JWT token")
        console.print(pentest.jwt_analyzer(j))

    elif choice == '09':
        d = Prompt.ask("Target domain (e.g. example.com)")
        console.print(newtools.subdomain_enumerator(d))
        db.save_scan(d, "Subdomain Enum", {})

    elif choice == '10':
        d = Prompt.ask("Target domain")
        console.print(newtools.dns_recon(d))

    elif choice == '11':
        u = Prompt.ask("Target URL (e.g. https://example.com)")
        console.print(newtools.http_header_analyzer(u))

    # ── OSINT ──────────────────────────────────────────────
    elif choice == '12':
        d = Prompt.ask("Domain")
        console.print(osint.domain_whois(d))

    elif choice == '13':
        u = Prompt.ask("Username")
        console.print(osint.username_tracker(u))

    elif choice == '14':
        ip = Prompt.ask("IP Address")
        console.print(osint.ip_lookup(ip))

    elif choice == '15':
        n = Prompt.ask("Phone number (+country code, e.g. +923001234567)")
        console.print(osint.phone_lookup(n))

    elif choice == '16':
        d = Prompt.ask("Domain (e.g. example.com)")
        console.print(newtools.email_harvester(d))

    elif choice == '17':
        q = Prompt.ask("Search CVE (e.g. apache, openssl, log4j, ms17-010)")
        scan_id = db.save_scan(q, "CVE Search", {})
        console.print(newtools.cve_search(q, db=db, scan_id=scan_id))

    # ── Utilities ──────────────────────────────────────────
    elif choice == '18':
        u = Prompt.ask("URL to analyze")
        console.print(utils.url_phishing_analyzer(u))

    elif choice == '19':
        u = Prompt.ask("URL to clone")
        console.print(utils.website_cloner(u))

    elif choice == '20':
        u = Prompt.ask("URL to audit cookies")
        console.print(utils.cookie_security_auditor(u))

    elif choice == '21':
        console.print(newtools.network_info())

    elif choice == '22':
        length = Prompt.ask("Password length", default="16")
        count  = Prompt.ask("How many passwords", default="10")
        try:
            console.print(newtools.password_generator(int(length), int(count)))
        except ValueError:
            console.print("[red]Enter valid numbers[/red]")

    elif choice == '23':
        firmware_path = Prompt.ask("Path to firmware image (e.g., /tmp/iot_firmware.bin)")
        results = iot_sec.analyze_firmware_dl(firmware_path)
        console.print(results)
        db.save_scan(firmware_path, "DL Firmware Analysis", results)

    elif choice == '24':
        target_ip = Prompt.ask("Target IoT Device IP")
        protocol = Prompt.ask("Protocol to fuzz (e.g., MQTT, CoAP, Zigbee)")
        results = iot_sec.neural_fuzz_iot_protocol(target_ip, protocol)
        console.print(results)
        db.save_scan(target_ip, f"Neural Fuzz {protocol}", results)

    # ── AI & Automation ────────────────────────────────────
    elif choice == '25':
        import json
        ctx_str = json.dumps(state['recon'], default=str) if state['recon'] else ""
        ai.interactive_chat(ctx_str)

    elif choice == '26':
        target = Prompt.ask("Enter target domain/IP for full autonomous recon")
        results = recon.run_full_recon(target)
        state['recon'] = results
        recon.display_summary()
        run_ai = Prompt.ask("\n[cyan]Run AI analysis on results?[/cyan] (y/n)", default="y")
        if run_ai.lower() == 'y':
            import json
            analysis = ai.analyze(
                f"Analyze these penetration testing results:\n"
                f"1. Critical findings\n2. Attack vectors\n3. CVE references\n"
                f"4. Risk score (0-100)\n5. Remediation steps\n\nResults:\n"
                f"{json.dumps(results, indent=2, default=str)}"
            )
            state['analysis'] = analysis
        # Persist a Full Auto Recon scan + normalized findings (for diff/dashboard).
        scan_id = db.save_scan(target, "Full Auto Recon", results, state.get('analysis', ""))
        try:
            from modules.intel.findings_extract import extract_findings_from_recon, persist_findings
            persist_findings(db, scan_id, extract_findings_from_recon(results, db=db))
        except Exception:
            pass

    elif choice == '27':
        if not state['recon']:
            console.print("[red]No recon results. Run option 26 first.[/red]")
        else:
            target = state['recon'].get("target", "unknown")
            console.print("[cyan]Generating PDF report...[/cyan]")
            path = reporter.generate(state['recon'], state['analysis'], target)
            console.print(f"[green]✓ Report saved: {path}[/green]")

    elif choice == '28':
        db.display_history()

    elif choice == '29':
        console.print("[yellow]Local-only AI mode is already active.[/yellow]")

    elif choice == '30':
        target = Prompt.ask("Enter target domain/IP for autonomous pentest (DL/RL)")
        results = orchestrator.run_autonomous_pentest(target)
        console.print(results)

    elif choice == '31':
        orchestrator.rl_engine.run_simulation()
        Prompt.ask("\nPress Enter to continue", default="")

    elif choice == '32':
        orchestrator.deception_engine.run_deception_demo()
        Prompt.ask("\nPress Enter to continue", default="")

    elif choice == '33':
        target = Prompt.ask("Enter target for Self-Correcting Loop")
        orchestrator.self_correcting_loop(target)
        Prompt.ask("\nPress Enter to continue", default="")

    # ── v4.0 additions ─────────────────────────────────────
    elif choice == '34':
        scan_diff_menu()

    elif choice == '35':
        from modules.intel.remediation import generate_remediation_for_text, render_block
        console.print("[cyan]Paste a finding description or a CVE id (e.g. CVE-2021-44228):[/cyan]")
        text = Prompt.ask("Finding / CVE")
        if text.strip():
            block = generate_remediation_for_text(text)
            render_block(block, console)

    elif choice == '36':
        findings_menu()

    elif choice.lower() in ['exit', 'quit']:
        console.print("\n[bold red][ NullShadow signing off... ][/bold red]")
        db.close()
        sys.exit(0)

    else:
        console.print("[red]Invalid choice.[/red]")
        time.sleep(1)


def main():
    state = {'recon': {}, 'analysis': ""}

    while True:
        os.system("clear")
        display_banner()
        display_menu()
        try:
            choice = Prompt.ask("[bold red]nullshadow[/bold red][white] > [/white]")
        except EOFError:
            console.print("\n[red]Input stream closed. Exiting NullShadow.[/red]")
            db.close()
            sys.exit(0)

        # A single option failing (DB hiccup, network error, bad input, etc.) must
        # never crash the whole session — log it and return to the menu.
        try:
            handle_choice(choice, state)
        except SystemExit:
            raise
        except KeyboardInterrupt:
            console.print("\n[yellow]↩ Interrupted — returning to menu.[/yellow]")
        except Exception as e:
            console.print(f"[red]✗ Error while handling option '{choice}': {e}[/red]")

        # Pause after handling a choice so output remains visible before menu redraw
        try:
            Prompt.ask("\nPress Enter to return to menu", default="")
        except EOFError:
            console.print("\n[red]Input stream closed. Exiting NullShadow.[/red]")
            db.close()
            sys.exit(0)

def cli():
    parser = argparse.ArgumentParser(
        description="NullShadow v4.0 — AI-powered pentest & defensive monitoring framework")
    parser.add_argument("--monitor", metavar="TARGET",
                        help="Run one defensive monitoring pass against TARGET "
                             "(recon + posture score + ALERT/OK), then exit. "
                             "Schedule with cron/systemd for continuous monitoring.")
    args = parser.parse_args()

    if args.monitor:
        try:
            run_monitor(args.monitor)
        finally:
            db.close()
        sys.exit(0)

    main()


if __name__ == "__main__":
    cli()
