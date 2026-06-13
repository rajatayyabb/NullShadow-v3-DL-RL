import requests
import json

class NullShadowAIEngine:
    def __init__(self, model_name="deepseek-coder:6.7b"):
        self.url = "http://localhost:11434/api/chat"
        self.model_name = model_name
        self.server_available = None

    def chat_unlimited(self, user_prompt, system_context="You are the core AI brain of NullShadow."):
        if self._is_server_available():
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
                self.server_available = False
                return self._fallback_response(user_prompt, system_context)
            except requests.exceptions.RequestException:
                self.server_available = False
                return self._fallback_response(user_prompt, system_context)

        return self._fallback_response(user_prompt, system_context)

    def _is_server_available(self):
        if self.server_available is not None:
            import os
            import time
            import json
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry


            class NullShadowAIEngine:
                def __init__(self, model_name="deepseek-coder:6.7b"):
                    # Configurable endpoint and token for production (Ollama/Deepseek)
                    self.model_name = model_name
                    self.base_url = os.getenv("LOCAL_AI_URL", "http://localhost:11434")
                    self.chat_url = self.base_url.rstrip("/") + "/api/chat"
                    self.health_url = self.base_url.rstrip("/") + "/api/health"
                    self.token = os.getenv("LOCAL_AI_TOKEN", "")
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

                def chat_unlimited(self, user_prompt, system_context="You are the core AI brain of NullShadow."):
                    # Prefer real local model server when available
                    if self._is_server_available():
                        payload = {
                            "model": self.model_name,
                            "messages": [
                                {"role": "system", "content": system_context},
                                {"role": "user", "content": user_prompt}
                            ],
                            "stream": False
                        }

                        try:
                            r = self.session.post(self.chat_url, json=payload, headers=self._headers(), timeout=10)
                            if r.status_code == 200:
                                j = r.json()
                                # Support multiple response shapes
                                if isinstance(j, dict):
                                    if 'message' in j and isinstance(j['message'], dict):
                                        return j['message'].get('content', '[!] Local AI returned empty content')
                                    if 'candidates' in j and isinstance(j['candidates'], list) and j['candidates']:
                                        return j['candidates'][0].get('content', {}).get('parts', [''])[0]
                                return str(j)
                            # non-200 -> mark unavailable and fallback
                            self.server_available = False
                        except Exception:
                            self.server_available = False

                    # Fallback: local rule-based guidance
                    return self._fallback_response(user_prompt, system_context)

                def _is_server_available(self):
                    if self.server_available is not None:
                        return self.server_available
                    try:
                        r = self.session.get(self.health_url, headers=self._headers(), timeout=3)
                        self.server_available = (r.status_code == 200)
                    except Exception:
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
