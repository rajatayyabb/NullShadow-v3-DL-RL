import requests
import json

class NullShadowAIEngine:
    def __init__(self, model_name="deepseek-coder:6.7b"):
        self.url = "http://localhost:11434/api/chat"
        self.model_name = model_name

    def chat_unlimited(self, user_prompt, system_context="You are the core AI brain of NullShadow."):
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_context},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False
        }

        try:
            response = requests.post(self.url, json=payload, timeout=8)
            if response.status_code == 200:
                return response.json().get('message', {}).get('content', '[!] Local AI returned an empty response.')
            return self._fallback_response(user_prompt, system_context, error=f"Local AI Error: Code {response.status_code}")
        except requests.exceptions.RequestException:
            return self._fallback_response(user_prompt, system_context, error="Local AI server unavailable. Using fallback local chat.")

    def _fallback_response(self, user_prompt, system_context, error=None):
        user_prompt_lower = user_prompt.lower()

        if error:
            return f"[Local fallback] {error}"

        if any(greet in user_prompt_lower for greet in ["hello", "hi", "hey", "greetings"]):
            return "[Local fallback] Hello! I am NullShadow local chat. Ask me about scans, vulnerabilities, or remediation."

        if "scan results" in user_prompt_lower or "analyze these scan results" in user_prompt_lower:
            return (
                "[Local fallback] I analyzed the provided scan results. "
                "Focus on open ports, known vulnerabilities, and insecure services. "
                "Prioritize patching exposed services, closing unused ports, and hardening SSL/TLS."
            )

        if any(term in user_prompt_lower for term in ["vulnerability", "cve", "risk", "threat", "attack"]):
            return (
                "[Local fallback] I can provide high-level security guidance without external APIs. "
                "Review your scan for open ports, weak crypto, and exposed services. "
                "Address findings with patching, configuration hardening, and network segmentation."
            )

        return (
            "[Local fallback] Local NullShadow AI is running without external APIs. "
            "Ask about scan data, port findings, CVEs, or remediation."
        )
