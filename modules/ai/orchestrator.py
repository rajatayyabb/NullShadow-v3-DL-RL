import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from modules.recon.recon_pipeline import ReconPipeline
from modules.pentesting.scanner import AdvancedPentestModules
from modules.pentesting.new_tools import NewPentestTools
from modules.ai.ai_engine import AIEngine
from modules.ai.deep_learning_engine import DeepLearningEngine
from database.db import ScanDatabase

console = Console()

class AutonomousOrchestrator:
    def __init__(self):
        self.recon_pipeline = ReconPipeline()
        self.pentest_modules = AdvancedPentestModules()
        self.new_pentest_tools = NewPentestTools()
        self.ai_engine = AIEngine()
        self.dl_engine = DeepLearningEngine()
        self.db = ScanDatabase()
        self.target = None
        self.current_state = {}
        self.action_history = []

    def _update_state(self, new_findings: dict):
        """Updates the current state with new findings."""
        self.current_state.update(new_findings)
        self.action_history.append({"timestamp": time.time(), "findings": new_findings})

    def _decide_next_action(self) -> str:
        """Agentic logic to decide the next best action based on current state and DL insights.
        This is a simplified decision-making process. A full RL agent would be more complex.
        """
        console.print("[dim cyan]Orchestrator deciding next action...[/dim cyan]")

        # Prioritize actions based on potential impact and current findings
        if not self.current_state.get("WHOIS Lookup"):
            return "whois"
        if not self.current_state.get("Subdomain Enum"):
            return "subdomain_enum"
        if not self.current_state.get("Port Scan"):
            return "port_scan"
        
        # If ports are open, check for vulnerabilities
        if self.current_state.get("Port Scan", {}).get("open_ports") and not self.current_state.get("Vulnerability Scan"):
            return "vuln_scan"

        # If vulnerabilities found, try to find CVEs
        if self.current_state.get("Vulnerability Scan", {}).get("vulnerabilities") and not self.current_state.get("CVE Search"):
            # Extract potential keywords for CVE search
            vuln_findings = self.current_state["Vulnerability Scan"]["vulnerabilities"]
            keywords = set()
            for vuln in vuln_findings:
                keywords.add(vuln.get("service", "").split(" ")[0])
                keywords.add(vuln.get("product", "").split(" ")[0])
            if keywords: # Prioritize the first keyword for simplicity
                self.current_state["CVE Search_query"] = list(keywords)[0]
                return "cve_search"

        # If web server detected, try directory bruteforce or HTTP header analysis
        if any(p.get("service") in ["http", "https"] for p in self.current_state.get("Port Scan", {}).get("open_ports", [])):
            if not self.current_state.get("Dir Bruteforce"):
                return "dir_bruteforce"
            if not self.current_state.get("HTTP Header Analysis"):
                return "http_header_analysis"

        # If OSINT data is missing, gather it
        if not self.current_state.get("Domain WHOIS"):
            return "domain_whois"
        if not self.current_state.get("IP Geolocation"):
            return "ip_geolocation"
        if not self.current_state.get("Email Harvester"):
            return "email_harvester"

        # Use DL engine for contextual scoring if enough data is gathered
        if len(self.current_state) > 5 and not self.current_state.get("DL_Contextual_Score"):
            score = self.dl_engine.score_vulnerability_context(self.current_state)
            self._update_state({"DL_Contextual_Score": score})
            console.print(f"[bold magenta]Deep Learning Contextual Score: {score:.2f}%[/bold magenta]")
            # If score is high, suggest deeper analysis or exploitation
            if score > 70:
                return "suggest_exploitation"
            return "ai_chat_analysis"

        # Default to AI chat for further analysis or if no clear next step
        return "ai_chat_analysis"

    def run_autonomous_pentest(self, target):
        self.target = target
        self.current_state = {"target": target}
        self.action_history = []
        self.dl_engine.load_model() # Load DL model at the start

        console.print(Panel(
            f"[bold blue]🤖 Autonomous Orchestrator Started[/bold blue]\n[cyan]Target: {target}[/cyan]",
            border_style="blue"
        ))

        while True:
            action = self._decide_next_action()
            console.print(f"[bold yellow]Executing action: {action}[/bold yellow]")

            if action == "whois":
                result = self.recon_pipeline._whois(self.target)
                self._update_state({"WHOIS Lookup": result})
            elif action == "subdomain_enum":
                result = self.recon_pipeline._subdomains(self.target)
                self._update_state({"Subdomain Enum": result})
            elif action == "port_scan":
                result = self.recon_pipeline._port_scan(self.target)
                self._update_state({"Port Scan": result})
            elif action == "vuln_scan":
                result = self.recon_pipeline._vuln_scan(self.target)
                self._update_state({"Vulnerability Scan": result})
            elif action == "cve_search":
                query = self.current_state.get("CVE Search_query", self.target)
                result = self.new_pentest_tools.cve_search(query)
                self._update_state({"CVE Search": result})
            elif action == "dir_bruteforce":
                # Assume HTTPS for now, need to refine with port scan results
                url = f"https://{self.target}"
                result = self.pentest_modules.dir_bruteforce(url)
                self._update_state({"Dir Bruteforce": result})
            elif action == "http_header_analysis":
                url = f"https://{self.target}"
                result = self.new_pentest_tools.http_header_analyzer(url)
                self._update_state({"HTTP Header Analysis": result})
            elif action == "domain_whois":
                result = self.recon_pipeline._whois(self.target)
                self._update_state({"Domain WHOIS": result})
            elif action == "ip_geolocation":
                result = self.recon_pipeline._geoip(self.target)
                self._update_state({"IP Geolocation": result})
            elif action == "email_harvester":
                result = self.new_pentest_tools.email_harvester(self.target)
                self._update_state({"Email Harvester": result})
            elif action == "suggest_exploitation":
                console.print(Panel(
                    "[bold red]🔥 Orchestrator suggests potential exploitation due to high threat score![/bold red]\n"
                    "[yellow]Further manual analysis or specialized exploitation modules are recommended.[/yellow]",
                    border_style="red"
                ))
                break # End autonomous run for now, suggest manual intervention
            elif action == "ai_chat_analysis":
                console.print("[dim]No clear automated action. Passing to AI Chat for human-guided analysis.[/dim]")
                # This would typically trigger an interactive chat with the AI engine
                # For now, we'll just break after a few steps to avoid infinite loops
                if len(self.action_history) > 10: # Limit actions for this simulation
                    break
                else:
                    # In a real scenario, the AI engine would process self.current_state
                    # and ask follow-up questions or suggest actions.
                    # For this 50% completion, we'll simulate an AI response.
                    simulated_ai_response = self.ai_engine.analyze(f"Analyze the current state: {json.dumps(self.current_state, indent=2)}", show_output=False)
                    console.print(Panel(
                        f"[bold green]🤖 AI Engine Suggestion:[/bold green]\n{simulated_ai_response[:500]}...",
                        border_style="green"
                    ))
                    # Based on AI suggestion, a real orchestrator would adapt.
                    # For now, we'll just break to show the flow.
                    break
            else:
                console.print(f"[red]Unknown action: {action}[/red]")
                break

            console.print("\n" + "-"*80 + "\n")
            time.sleep(1) # Simulate work

        console.print(Panel(
            f"[bold blue]Autonomous Orchestrator Finished for {self.target}[/bold blue]",
            border_style="blue"
        ))
        self.db.save_scan(self.target, "Autonomous Pentest", self.current_state, 
                           ai_analysis=json.dumps(self.current_state.get("AI Chat Analysis", {})),
                           threat_score=self.current_state.get("DL_Contextual_Score", 0))
        return self.current_state

    def analyze_firmware_with_dl(self, firmware_path: str) -> dict:
        """Analyzes a firmware image using the Deep Learning Engine.
        This is a placeholder for the actual binary analysis pipeline.
        """
        console.print(f"[bold magenta]Analyzing firmware: {firmware_path} with Deep Learning Engine...[/bold magenta]")
        # Simulate feature extraction from firmware
        # In reality, this would involve tools like Ghidra, Radare2, or Angr
        simulated_binary_features = {
            "file_size": os.path.getsize(firmware_path) if os.path.exists(firmware_path) else 0,
            "architecture": "ARM", # Simulated
            "function_count": 150, # Simulated
            "string_literals": ["admin_password", "debug_mode_enabled"], # Simulated
            "external_libs": ["libc", "unsafe_lib"], # Simulated
        }
        dl_results = self.dl_engine.analyze_binary_for_vulnerabilities(simulated_binary_features)
        return dl_results
