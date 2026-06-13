#!/usr/bin/env python3
"""
Simple forwarding proxy for OpenAI. Exposes /api/health and /api/chat so
NullShadow can point to this proxy via LOCAL_AI_URL. Keeps your provider key
on the host and never checks it into git.

Environment variables:
- PROXY_PROVIDER (default: openai)
- OPENAI_API_KEY

Usage:
    python3 scripts/local_ai_proxy.py

This is intentionally minimal. For production use, add auth, rate-limiting,
request validation, and logging.
"""
import os
import sys
from flask import Flask, request, jsonify

app = Flask(__name__)

PROVIDER = os.getenv("PROXY_PROVIDER", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

try:
    import openai
    openai.api_key = OPENAI_API_KEY
except Exception:
    openai = None


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "provider": PROVIDER, "proxy": True}), 200


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "invalid json body"}), 400

    model = data.get("model")
    messages = data.get("messages")

    if PROVIDER == "openai":
        if not OPENAI_API_KEY or openai is None:
            return jsonify({"error": "OPENAI_API_KEY not configured on proxy host"}), 502

        # Try ChatCompletion first, fall back to Completion
        try:
            # new ChatCompletion API
            resp = openai.ChatCompletion.create(model=model, messages=messages)
            # Typical shape: resp.choices[0].message.content
            choice = resp.choices[0]
            text = None
            if hasattr(choice, 'message') and isinstance(choice.message, dict):
                text = choice.message.get('content')
            elif hasattr(choice, 'text'):
                text = choice.text
            else:
                # attempt to str()
                text = str(choice)
            return jsonify({"message": {"content": text}})
        except Exception as e:
            # As a fallback, return raw error
            return jsonify({"error": "provider error", "detail": str(e)}), 502

    return jsonify({"error": "provider not supported by proxy"}), 400


if __name__ == '__main__':
    port = int(os.getenv("PORT", 11434))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting local AI proxy (provider={PROVIDER}) on {host}:{port}")
    app.run(host=host, port=port)
