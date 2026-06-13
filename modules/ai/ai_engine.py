import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import requests
import json
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt
from config.config import ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY
from modules.ai.local_ai_engine import NullShadowAIEngine

console = Console()

# Updated Gemini models — latest first (2025)
GEMINI_MODELS = [
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
    "gemini-1.5-pro",
]


class AIEngine:

    def __init__(self):
        self.conversation_history = []
        self.active_ai = "openai"
        self.local_ai = NullShadowAIEngine()
        self.gemini_model = None  # will be auto-detected on first use

    def _detect_available_ai(self):
        """Detect first available AI by checking key is non-empty and not a placeholder."""
        def is_valid(key, env_name=None):
            if not key:
                if env_name:
                    key = os.getenv(env_name)
                if not key: return False
            k = key.strip().lower()
            placeholders = ["", "paste-your", "your-", "key-here", "sk-...", "insert"]
            return not any(p in k for p in placeholders) and (len(k) > 15 or env_name == "OPENAI_API_KEY")

        if is_valid(ANTHROPIC_API_KEY, "ANTHROPIC_API_KEY"): return "claude"
        if is_valid(GEMINI_API_KEY, "GEMINI_API_KEY"): return "gemini"
        if is_valid(OPENAI_API_KEY, "OPENAI_API_KEY"): return "openai"
        return None

    def set_ai(self, ai_name):
        self.active_ai = ai_name.lower()
        self.conversation_history = []
        console.print(f"[green]✓ Switched to {ai_name.upper()}[/green]")

    def reset_conversation(self):
        self.conversation_history = []

    def _find_working_gemini_model(self):
        """Auto-detect a working Gemini model by probing the API."""
        if self.gemini_model:
            return self.gemini_model

        console.print("[dim cyan][ Auto-detecting Gemini model... ][/dim cyan]")
        for model in GEMINI_MODELS:
            try:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models"
                    f"/{model}:generateContent?key={GEMINI_API_KEY}"
                )
                r = requests.post(
                    url,
                    json={"contents": [{"parts": [{"text": "hi"}]}]},
                    timeout=12,
                )
                if r.status_code == 200:
                    self.gemini_model = model
                    console.print(f"[dim green]✓ Using Gemini model: {model}[/dim green]")
                    return model
                elif r.status_code in (400, 429):
                    # Model exists — 400 = bad request (still usable), 429 = quota
                    self.gemini_model = model
                    console.print(f"[dim yellow]Using Gemini model: {model} (status {r.status_code})[/dim yellow]")
                    return model
                # 404 = model not found, try next
            except requests.exceptions.Timeout:
                console.print(f"[dim red]Timeout on {model}, trying next...[/dim red]")
                continue
            except Exception:
                continue

        # Hard fallback — just pick the newest and let the error surface
        self.gemini_model = "gemini-2.0-flash"
        console.print(f"[yellow]Could not confirm model. Defaulting to {self.gemini_model}[/yellow]")
        return self.gemini_model

    def _prompt_for_api_key(self, provider):
        """Prompts the user for an API key and saves it to the local config file."""
        console.print(Panel(
            f"[bold yellow]⚠️ MISSING API KEY FOR {provider.upper()}[/bold yellow]\n"
            f"[dim]To use AI features, please provide your private API key.\n"
            f"This key will be saved locally in config/config.py and will not be shared.[/dim]",
            border_style="yellow"
        ))
        key_name = {
            "claude": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY"
        }.get(provider)
        
        new_key = Prompt.ask(f"Paste your {provider.upper()} API Key", password=True)
        if new_key and len(new_key) > 10:
            # Update the live module
            import config.config as _cfg
            setattr(_cfg, key_name, new_key)
            os.environ[key_name] = new_key
            
            # Update the physical file config/config.py
            config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'config.py')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    lines = f.readlines()
                with open(config_path, 'w') as f:
                    for line in lines:
                        if line.startswith(f"{key_name} ="):
                            f.write(f"{key_name} = \"{new_key}\"\n")
                        else:
                            f.write(line)
            
            # Reload global keys in this module
            global ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY
            if provider == "claude": ANTHROPIC_API_KEY = new_key
            elif provider == "openai": OPENAI_API_KEY = new_key
            elif provider == "gemini": GEMINI_API_KEY = new_key
            
            self.active_ai = provider
            console.print(f"[green]✓ {provider.upper()} API Key saved and activated![/green]")
            return True
        return False

    def analyze(self, prompt, system_prompt=None, show_output=True):
        if not self.active_ai:
            console.print("[yellow]No AI engine active. Which one would you like to use?[/yellow]")
            console.print("  [1] Claude (Anthropic)\n  [2] GPT-4 (OpenAI)\n  [3] Gemini (Google)")
            choice = Prompt.ask("Select", choices=["1", "2", "3"])
            provider = {"1": "claude", "2": "openai", "3": "gemini"}[choice]
            if not self._prompt_for_api_key(provider):
                return "AI analysis cancelled: No API key provided."

        if system_prompt is None:
            system_prompt = (
                "You are an expert cybersecurity analyst for NullShadow penetration testing framework. "
                "Analyze scan results, identify vulnerabilities, suggest attack vectors, "
                "recommend CVEs, provide risk scores, and give remediation steps. "
                "Be precise, technical, and actionable."
            )

        self.conversation_history.append({"role": "user", "content": prompt})
        console.print(f"\n[dim cyan][ Thinking... ({self.active_ai.upper()}) ][/dim cyan]")

        try:
            if self.active_ai == "claude":
                response = self._claude(system_prompt)
            elif self.active_ai == "openai":
                response = self._openai(system_prompt)
            elif self.active_ai == "gemini":
                response = self._gemini(system_prompt)
            elif self.active_ai == "local":
                response = self.local_ai.chat_unlimited(prompt, system_prompt)
            else:
                response = "Unknown AI provider."
        except Exception as e:
            response = f"[AI Error] {e}"

        self.conversation_history.append({"role": "assistant", "content": response})

        if show_output:
            console.print(Panel(
                Markdown(response),
                title=f"[bold green]🤖 NullShadow AI  ({self.active_ai.upper()})[/bold green]",
                border_style="green"
            ))
        return response

    def _claude(self, system_prompt):
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": self.conversation_history
                },
                timeout=60
            )
            if r.status_code != 200:
                return f"Claude error {r.status_code}: {r.text[:300]}"
            return r.json()["content"][0]["text"]
        except Exception as e:
            return f"Claude error: {e}"

    def _openai(self, system_prompt):
        try:
            api_key = OPENAI_API_KEY or os.getenv("OPENAI_API_KEY")
            api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
            r = requests.post(
                f"{api_base}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "gpt-4.1-mini",
                    "messages": [{"role": "system", "content": system_prompt}] + self.conversation_history,
                    "max_tokens": 2048
                },
                timeout=60
            )
            if r.status_code != 200:
                return f"OpenAI error {r.status_code}: {r.text[:300]}"
            data = r.json()
            if "choices" in data:
                return data["choices"][0]["message"]["content"]
            return f"OpenAI unexpected response: {json.dumps(data)}"
        except Exception as e:
            return f"OpenAI error: {e}"

    def _gemini(self, system_prompt):
        model = self._find_working_gemini_model()
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models"
            f"/{model}:generateContent?key={GEMINI_API_KEY}"
        )

        # Build a single text blob: system prompt + conversation history
        history_text = f"{system_prompt}\n\n"
        for msg in self.conversation_history:
            role = "User" if msg["role"] == "user" else "Assistant"
            history_text += f"{role}: {msg['content']}\n\n"

        payload = {
            "contents": [{"parts": [{"text": history_text}]}],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 2048,
            }
        }

        try:
            r = requests.post(url, json=payload, timeout=60)

            if r.status_code == 404:
                # Model gone — reset and try next available
                self.gemini_model = None
                idx = GEMINI_MODELS.index(model) if model in GEMINI_MODELS else -1
                for fallback in GEMINI_MODELS[idx + 1:]:
                    url2 = (
                        f"https://generativelanguage.googleapis.com/v1beta/models"
                        f"/{fallback}:generateContent?key={GEMINI_API_KEY}"
                    )
                    r2 = requests.post(url2, json=payload, timeout=60)
                    if r2.status_code == 200:
                        self.gemini_model = fallback
                        data = r2.json()
                        return data["candidates"][0]["content"]["parts"][0]["text"]
                return "No working Gemini model found. Check: https://aistudio.google.com"

            if r.status_code == 400:
                err = r.json()
                return f"Gemini API key error or bad request: {err.get('error', {}).get('message', r.text[:200])}"

            if r.status_code == 403:
                return ("Gemini API key is invalid or not enabled. "
                        "Make sure you created your key at https://aistudio.google.com/app/apikey "
                        "and that the Generative Language API is enabled in your Google Cloud project.")

            if r.status_code != 200:
                return f"Gemini error {r.status_code}: {r.text[:300]}"

            data = r.json()
            candidates = data.get("candidates", [])
            if not candidates:
                finish = data.get("promptFeedback", {})
                return f"Gemini returned empty response. Prompt feedback: {finish}"
            return candidates[0]["content"]["parts"][0]["text"]

        except requests.exceptions.Timeout:
            return "Gemini request timed out (60s). Check your internet connection."
        except Exception as e:
            return f"Gemini error: {e}"

    def interactive_chat(self, context=""):
        if not self.active_ai:
            console.print("[yellow]No AI engine active for chat. Which one would you like to use?[/yellow]")
            console.print("  [1] Claude (Anthropic)\n  [2] GPT-4 (OpenAI)\n  [3] Gemini (Google)")
            choice = Prompt.ask("Select", choices=["1", "2", "3"])
            provider = {"1": "claude", "2": "openai", "3": "gemini"}[choice]
            if not self._prompt_for_api_key(provider):
                return
            self.active_ai = provider

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
            except KeyboardInterrupt:
                break
