import sys
import os
import time

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
    from modules.ai.ai_engine import AIEngine
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
ai       = AIEngine()
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

    ai_status = f"[green]●[/green] {ai.active_ai.upper()}" if ai.active_ai else "[red]● NO AI KEY[/red]"
    console.print(f"  AI Engine: {ai_status}   {server_status}     DB: [green]●[/green] Connected     Version: [cyan]v3.0 (DL/RL Enhanced)[/cyan]  Tools: [yellow]23[/yellow]\n", justify="center")


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
    t3.add_row("──────────────────────")
    t3.add_row("[30] 🚀 AUTO PENTEST (DL/RL)")

    console.print(Panel(Columns([t1, t2, t3]),
                        title="[bold white]━━━  N U L L S H A D O W  ━━━  [ 23 TOOLS ]  ━━━[/bold white]",
                        border_style="red"))


def switch_ai():
    console.print("\n[cyan]Local-only AI mode is active. No cloud API switching is available.[/cyan]")
    ai.set_ai("local")


def main():
    last_recon_results = {}
    last_ai_analysis   = ""

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

        # ── Pentesting ─────────────────────────────────────────
        if choice == '01':
            t = Prompt.ask("Target IP/Domain")
            console.print(pentest.port_scanner(t))
            db.save_scan(t, "Port Scan", {})

        elif choice == '02':
            t = Prompt.ask("Target IP/Domain")
            console.print(pentest.vulnerability_scanner(t))
            db.save_scan(t, "Vuln Scan", {})

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
            console.print(newtools.cve_search(q))

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
            ctx_str = json.dumps(last_recon_results, default=str) if last_recon_results else ""
            ai.interactive_chat(ctx_str)

        elif choice == '26':
            target = Prompt.ask("Enter target domain/IP for full autonomous recon")
            results = recon.run_full_recon(target)
            last_recon_results = results
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
                last_ai_analysis = analysis
                db.save_scan(target, "Full Auto Recon", results, analysis)

        elif choice == '27':
            if not last_recon_results:
                console.print("[red]No recon results. Run option 26 first.[/red]")
            else:
                target = last_recon_results.get("target", "unknown")
                console.print("[cyan]Generating PDF report...[/cyan]")
                path = reporter.generate(last_recon_results, last_ai_analysis, target)
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

        elif choice.lower() in ['exit', 'quit']:
            console.print("\n[bold red][ NullShadow signing off... ][/bold red]")
            db.close()
            sys.exit(0)

        else:
            console.print("[red]Invalid choice.[/red]")
            time.sleep(1)

        # Pause after handling a choice so output remains visible before menu redraw
        try:
            Prompt.ask("\nPress Enter to return to menu", default="")
        except EOFError:
            console.print("\n[red]Input stream closed. Exiting NullShadow.[/red]")
            db.close()
            sys.exit(0)

if __name__ == "__main__":
    main()
