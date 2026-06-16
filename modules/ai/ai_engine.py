import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from modules.ai.local_ai_engine import NullShadowAIEngine

console = Console()

# Shared, lazily-created active engine (Phase 0.3 / Phase 5).
_active_engine = None


def get_active_ai_engine():
    """
    Return the AI engine NullShadow should use right now.

    Selection logic (brief Phase 0.3 / Phase 5):
      * If a cloud API key is configured AND the user has explicitly selected a
        cloud engine, return that cloud engine.
      * Otherwise return the LOCAL engine (Ollama, or the rule-based fallback).

    This build ships local-only, so this always returns the local AIEngine and
    therefore NEVER raises an authentication error when no key is configured.
    """
    global _active_engine
    if _active_engine is None:
        _active_engine = AIEngine()
    return _active_engine


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

    def is_cloud(self):
        """True only if a cloud engine is actually active. Always False here:
        this build is local-only, so AI features never require a paid key."""
        return False

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
