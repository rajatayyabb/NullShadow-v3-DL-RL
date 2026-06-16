import os
import time
import json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class NullShadowAIEngine:
    def __init__(self, model_name=None):
        # Configurable endpoint, model and token for production (Ollama/Deepseek).
        # Pull defaults from config.config when available, then env, then a sane default.
        cfg_url = None
        cfg_model = None
        cfg_token = None
        try:
            from config.config import LOCAL_AI_URL as _CFG_URL
            cfg_url = _CFG_URL
        except Exception:
            pass
        try:
            from config.config import LOCAL_AI_MODEL as _CFG_MODEL
            cfg_model = _CFG_MODEL
        except Exception:
            pass
        try:
            from config.config import LOCAL_AI_TOKEN as _CFG_TOKEN
            cfg_token = _CFG_TOKEN
        except Exception:
            pass

        self.model_name = model_name or os.getenv("LOCAL_AI_MODEL", cfg_model or "deepseek-coder:6.7b")
        self.base_url = os.getenv("LOCAL_AI_URL", cfg_url or "http://localhost:11434")
        self.chat_url = self.base_url.rstrip("/") + "/api/chat"
        # Ollama's real liveness endpoints are GET /api/tags and GET / ; the bundled
        # mock server (scripts/local_ai_server.py) uses /api/health. Probe all three.
        base = self.base_url.rstrip("/")
        self.health_urls = [base + "/api/tags", base + "/", base + "/api/health"]
        self.token = os.getenv("LOCAL_AI_TOKEN", cfg_token or "")
        # Larger local models (e.g. 14B) can take well over 10s on a cold start,
        # so use a generous, configurable timeout for the chat call.
        try:
            self.chat_timeout = int(os.getenv("LOCAL_AI_TIMEOUT", "120"))
        except ValueError:
            self.chat_timeout = 120
        self.server_available = None

        # Requests session with retries
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=(502, 503, 504))
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _resolve_model(self):
        """If the configured model isn't installed in Ollama, fall back to the
        first model that IS installed. Lets NullShadow work with whatever the
        user already has pulled, without editing config."""
        try:
            r = self.session.get(self.health_urls[0], headers=self._headers(), timeout=3)
            if r.status_code == 200:
                models = [m.get("name") for m in r.json().get("models", []) if m.get("name")]
                if models and self.model_name not in models:
                    self.model_name = models[0]
        except Exception:
            pass
        return self.model_name

    def chat_unlimited(self, user_prompt, system_context="You are the core AI brain of NullShadow."):
        # Prefer real local model server when available
        if self._is_server_available():
            self._resolve_model()
            payload = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": system_context},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False
            }

            # Try twice: the FIRST request to a large local model often cold-starts
            # it (loading a 14B model into memory), which can fail/stall transiently.
            # A single retry makes the first real question reliable instead of
            # silently dropping to the canned fallback.
            for attempt in range(2):
                try:
                    r = self.session.post(self.chat_url, json=payload,
                                          headers=self._headers(), timeout=self.chat_timeout)
                    if r.status_code == 200:
                        j = r.json()
                        # Support multiple response shapes
                        if isinstance(j, dict):
                            if 'message' in j and isinstance(j['message'], dict):
                                return j['message'].get('content', '[!] Local AI returned empty content')
                            if 'candidates' in j and isinstance(j['candidates'], list) and j['candidates']:
                                return j['candidates'][0].get('content', {}).get('parts', [''])[0]
                        return str(j)
                    # non-200: retry once (model may still be loading), then fall back.
                    if attempt == 0:
                        time.sleep(1.5)
                        continue
                    # Don't permanently latch: reset to None so the NEXT call
                    # re-probes (a transient cold-start failure must not disable
                    # AI for the whole session).
                    self.server_available = None
                except Exception:
                    if attempt == 0:
                        time.sleep(1.5)
                        continue
                    self.server_available = None

        # Fallback: local rule-based guidance
        return self._fallback_response(user_prompt, system_context)

    def _is_server_available(self):
        if self.server_available is not None:
            return self.server_available
        # Probe each candidate liveness endpoint; the first 200 wins. This makes
        # the check work against a real Ollama server (/api/tags or /) as well as
        # the bundled mock (/api/health), instead of always failing on /api/health.
        for url in self.health_urls:
            try:
                r = self.session.get(url, headers=self._headers(), timeout=3)
                if r.status_code == 200:
                    self.server_available = True
                    return True
            except Exception:
                continue
        self.server_available = False
        return self.server_available

    def _fallback_response(self, user_prompt, system_context, error=None):
        user_prompt_lower = (user_prompt or "").lower()

        if error and "server unavailable" not in str(error).lower():
            return f"[Local fallback] {error}"

        if user_prompt_lower.strip() in ["h", "help", "?", "hi", "hello", "hey"]:
            return (
                "[Local fallback] Local AI is available. Ask me about scan summaries, "
                "vulnerabilities, remediation advice, or security recommendations."
            )

        if any(term in user_prompt_lower for term in ["scan results", "analyze", "open ports", "ports", "vulnerability", "cve", "risk", "threat", "attack", "remediation"]):
            return (
                "[Local fallback] As a local security assistant, I can help with basic analysis. "
                "Review open ports for exposed services, identify weak ciphers in SSL/TLS, and look for common CVE patterns on exposed software. "
                "Patch vulnerable services, disable unnecessary ports, enforce strong authentication, and use network segmentation to reduce risk."
            )

        if any(term in user_prompt_lower for term in ["recommend", "suggest", "how do i", "what should i", "help me", "advice"]):
            return (
                "[Local fallback] I can help with practical security guidance. "
                "Start by confirming asset scope, enumerating open services, and validating firewall rules. "
                "Then prioritize fixing critical issues, improve logging and monitoring, and harden exposed endpoints."
            )

        return (
            "[Local fallback] Local NullShadow AI is available in fallback mode. "
            "Ask about scan summaries, vulnerability guidance, CVEs, remediation steps, or security posture."
        )
