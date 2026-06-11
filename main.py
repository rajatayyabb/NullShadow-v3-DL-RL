import sys
import os

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
    ai_status = f"[green]●[/green] {ai.active_ai.upper()}" if ai.active_ai else "[red]● NO AI KEY[/red]"
    console.print(f"  AI Engine: {ai_status}     DB: [green]●[/green] Connected     Version: [cyan]v3.0 (DL/RL Enhanced)[/cyan]  Tools: [yellow]23[/yellow]\n", justify="center")


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
    t3.add_row("──────────────────────")
    t3.add_row("[25] 🤖 AI Chat Mode")
    t3.add_row("[26] 🚀 AUTO FULL RECON")
    t3.add_row("[27] 📄 Generate PDF Report")
    t3.add_row("[28] 📊 Scan History")
    t3.add_row("[29] ⚙️  Switch AI Engine")
    t3.add_row("──────────────────────")
    t3.add_row("[30] 🚀 AUTO PENTEST (DL/RL)")

    console.print(Panel(Columns([t1, t2, t3]),
                        title="[bold white]━━━  N U L L S H A D O W  ━━━  [ 23 TOOLS ]  ━━━[/bold white]",
                        border_style="red"))


def switch_ai():
    from config import config as _cfg

    def _key_status(key):
        return "[green]✓ Key set[/green]" if key and key.strip() else "[red]✗ No key[/red]"

    console.print("\n[cyan]Available AI engines:[/cyan]")
    console.print(f"  [1] Claude (Anthropic)  — ANTHROPIC_API_KEY  {_key_status(_cfg.ANTHROPIC_API_KEY)}")
    console.print(f"  [2] GPT-4 (OpenAI)      — OPENAI_API_KEY     {_key_status(_cfg.OPENAI_API_KEY)}")
    console.print(f"  [3] Gemini (Google)     — GEMINI_API_KEY     {_key_status(_cfg.GEMINI_API_KEY)}")
    console.print("\n  [bold yellow]Tip:[/bold yellow] To set a key now, choose [4] and enter it.")
    choice = Prompt.ask("Select AI (1/2/3/4)")
    mapping = {"1": "claude", "2": "openai", "3": "gemini"}

    if choice == "4":
        console.print("[cyan]Which key do you want to set?[/cyan]")
        console.print("  [1] ANTHROPIC_API_KEY\n  [2] OPENAI_API_KEY\n  [3] GEMINI_API_KEY")
        kc = Prompt.ask("Key")
        key_map = {"1": "ANTHROPIC_API_KEY", "2": "OPENAI_API_KEY", "3": "GEMINI_API_KEY"}
        ai_map  = {"1": "claude",            "2": "openai",         "3": "gemini"}
        if kc in key_map:
            new_key = Prompt.ask(f"Paste your {key_map[kc]}", password=True)
            # Inject into the live config module and environment
            setattr(_cfg, key_map[kc], new_key)
            import os
            os.environ[key_map[kc]] = new_key
            # Reload the key in the AI engine module
            import modules.ai.ai_engine as _ae
            setattr(_ae, key_map[kc].replace("ANTHROPIC_", "ANTHROPIC_").replace("OPENAI_", "OPENAI_").replace("GEMINI_", "GEMINI_"), new_key)
            _ae.ANTHROPIC_API_KEY = _cfg.ANTHROPIC_API_KEY
            _ae.OPENAI_API_KEY    = _cfg.OPENAI_API_KEY
            _ae.GEMINI_API_KEY    = _cfg.GEMINI_API_KEY
            ai.set_ai(ai_map[kc])
            ai.gemini_model = None  # force re-detection
            console.print(f"[green]✓ Key saved and switched to {ai_map[kc].upper()}[/green]")
        return

    if choice in mapping:
        selected = mapping[choice]
        key_check = {
            "claude": _cfg.ANTHROPIC_API_KEY,
            "openai": _cfg.OPENAI_API_KEY,
            "gemini": _cfg.GEMINI_API_KEY,
        }
        if not key_check[selected] or not key_check[selected].strip() or "paste-your" in key_check[selected]:
            if ai._prompt_for_api_key(selected):
                # Reload the keys from the config module after prompting
                import config.config as _cfg
                ai.set_ai(selected)
            else:
                return
        ai.set_ai(selected)
        if selected == "gemini":
            ai.gemini_model = None  # force model re-detection


def main():
    last_recon_results = {}
    last_ai_analysis   = ""

    while True:
        os.system("clear")
        display_banner()
        display_menu()
        choice = Prompt.ask("[bold red]nullshadow[/bold red][white] > [/white]")

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
            switch_ai()

        elif choice == '30':
            target = Prompt.ask("Enter target domain/IP for autonomous pentest (DL/RL)")
            results = orchestrator.run_autonomous_pentest(target)
            console.print(Panel(
                f"[bold green]Autonomous Pentest (DL/RL) Complete for {target}[/bold green]",
                border_style="green"
            ))
            console.print(results)

        elif choice.lower() == 'exit':
            console.print("\n[bold red][ NullShadow signing off... ][/bold red]")
            db.close()
            break
        else:
            console.print("[red]Invalid choice.[/red]")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
