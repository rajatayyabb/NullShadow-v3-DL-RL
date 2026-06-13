import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from modules.ai.local_ai_engine import NullShadowAIEngine

console = Console()


class AIEngine:

    def __init__(self):
        self.conversation_history = []
        self.local_ai = NullShadowAIEngine()
        self.active_ai = "local"

    def set_ai(self, ai_name):
        self.active_ai = "local"
        self.conversation_history = []
        console.print(f"[green]✓ Switched to LOCAL AI mode[/green]")

    def reset_conversation(self):
        self.conversation_history = []

    def analyze(self, prompt, system_prompt=None, show_output=True):
        if system_prompt is None:
            system_prompt = (
                "You are an expert cybersecurity analyst for NullShadow penetration testing framework. "
                "Analyze scan results, identify vulnerabilities, suggest attack vectors, "
                "recommend CVEs, provide risk scores, and give remediation steps. "
                "Be precise, technical, and actionable."
            )

        response = self.local_ai.chat_unlimited(prompt, system_prompt)

        if show_output:
            console.print(Panel(
                Markdown(response),
                title=f"[bold green]🤖 NullShadow AI  (LOCAL)[/bold green]",
                border_style="green"
            ))
        return response

    def interactive_chat(self, context=""):
        console.print(Panel(
            f"[cyan]AI Chat — {self.active_ai.upper()}\n"
            "[yellow]Ask anything. Type 'exit' to go back.[/yellow]",
            title="[bold green]🤖 NullShadow AI Chat[/bold green]",
            border_style="green"
        ))

        if context:
            self.analyze(f"Analyze these scan results:\n\n{context}", show_output=True)

        while True:
            try:
                user_input = console.input("\n[bold cyan]You → [/bold cyan]").strip()
                if user_input.lower() in ("exit", "quit", "back"):
                    self.reset_conversation()
                    break
                if not user_input:
                    continue
                self.analyze(user_input)
            except (KeyboardInterrupt, EOFError):
                break
