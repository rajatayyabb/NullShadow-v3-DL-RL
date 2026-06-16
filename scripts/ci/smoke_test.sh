#!/usr/bin/env bash
set -euo pipefail

BASE=${LOCAL_AI_URL:-http://localhost:11434}
HEALTH="$BASE/api/health"
CHAT="$BASE/api/chat"

echo "Checking AI health at $HEALTH"
status=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH")
if [ "$status" != "200" ]; then
  echo "Health check failed with code $status"
  exit 2
fi

echo "Health OK"

resp=$(curl -s -X POST "$CHAT" -H "Content-Type: application/json" -d '{"model":"test","messages":[{"role":"user","content":"smoke test"}]}')
if [ -z "$resp" ]; then
  echo "Empty chat response"
  exit 3
fi

echo "Chat response: $resp"

echo "Smoke test passed"
exit 0
