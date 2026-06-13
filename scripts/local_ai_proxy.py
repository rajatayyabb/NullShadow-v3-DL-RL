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
import time
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configuration
PROVIDER = os.getenv("PROXY_PROVIDER", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
PROXY_TOKEN = os.getenv("PROXY_TOKEN", "")
ALLOWED_MODELS = [m.strip() for m in os.getenv("ALLOWED_MODELS", "").split(",") if m.strip()]
MAX_MSG_LENGTH = int(os.getenv("MAX_MSG_LENGTH", "2000"))
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))

# Logging
logger = logging.getLogger("local_ai_proxy")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("local_ai_proxy.log")
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(fh)

try:
    import openai
    openai.api_key = OPENAI_API_KEY
except Exception:
    openai = None

# Simple in-memory rate limiter per token
# Structure: { token_or_ip: { 'count': int, 'window_start': epoch_seconds } }
_rate_state = {}


def _check_rate(key):
    now = int(time.time())
    window = 60
    state = _rate_state.get(key)
    if not state or now - state['window_start'] >= window:
        _rate_state[key] = {'count': 1, 'window_start': now}
        return True
    if state['count'] >= RATE_LIMIT_PER_MIN:
        return False
    state['count'] += 1
    return True


def _extract_token(req):
    # Priority: Authorization: Bearer <token> then X-Proxy-Token
    auth = req.headers.get('Authorization', '')
    if auth.lower().startswith('bearer '):
        return auth.split(None, 1)[1].strip()
    header = req.headers.get('X-Proxy-Token', '')
    if header:
        return header.strip()
    return None


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "provider": PROVIDER, "proxy": True}), 200


@app.route("/api/chat", methods=["POST"])
def chat():
    token = _extract_token(request)
    if PROXY_TOKEN and token != PROXY_TOKEN:
        logger.warning("unauthorized access attempt, token=%s, ip=%s", token, request.remote_addr)
        return jsonify({"error": "unauthorized"}), 401

    rate_key = token or request.remote_addr or 'anon'
    if not _check_rate(rate_key):
        logger.warning("rate limit exceeded for %s", rate_key)
        return jsonify({"error": "rate limit exceeded"}), 429

    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "invalid json body"}), 400

    model = data.get("model")
    messages = data.get("messages")

    # Basic validation
    if not isinstance(messages, list) or not messages:
        return jsonify({"error": "messages must be a non-empty list"}), 400

    total_len = 0
    for m in messages:
        if not isinstance(m, dict) or 'role' not in m or 'content' not in m:
            return jsonify({"error": "each message must be an object with role and content"}), 400
        total_len += len(str(m.get('content', '')))
        if total_len > MAX_MSG_LENGTH:
            return jsonify({"error": "messages exceed allowed length"}), 413

    if ALLOWED_MODELS and model not in ALLOWED_MODELS:
        return jsonify({"error": "model not allowed"}), 403

    logger.info("proxy chat request: model=%s, from=%s", model, request.remote_addr)

    if PROVIDER == "openai":
        if not OPENAI_API_KEY or openai is None:
            logger.error("OPENAI_API_KEY not configured on proxy host")
            return jsonify({"error": "OPENAI_API_KEY not configured on proxy host"}), 502

        try:
            resp = openai.ChatCompletion.create(model=model, messages=messages)
            choice = resp.choices[0]
            text = None
            if hasattr(choice, 'message') and isinstance(choice.message, dict):
                text = choice.message.get('content')
            elif hasattr(choice, 'text'):
                text = choice.text
            else:
                text = str(choice)
            return jsonify({"message": {"content": text}})
        except Exception as e:
            logger.exception("provider error")
            return jsonify({"error": "provider error", "detail": str(e)}), 502

    logger.error("provider not supported: %s", PROVIDER)
    return jsonify({"error": "provider not supported by proxy"}), 400


if __name__ == '__main__':
    port = int(os.getenv("PORT", 11434))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting hardened local AI proxy (provider={PROVIDER}) on {host}:{port}")
    logger.info("starting proxy, provider=%s", PROVIDER)
    app.run(host=host, port=port)
