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
            response = requests.post(self.url, json=payload)
            if response.status_code == 200:
                return response.json()['message']['content']
            return f"[!] Local AI Error: Code {response.status_code}"
        except requests.exceptions.ConnectionError:
            return "[!] Error: Run 'ollama serve' in your terminal first."
