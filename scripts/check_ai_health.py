#!/usr/bin/env python3
"""
Check health of configured LOCAL_AI_URL or fallback to default mock.
Usage:
    LOCAL_AI_URL=http://localhost:11434 PROXY_TOKEN=testtoken python3 scripts/check_ai_health.py
"""
import os
import sys
import requests

BASE = os.getenv('LOCAL_AI_URL', 'http://localhost:11434').rstrip('/')
HEALTH = BASE + '/api/health'
TOKEN = os.getenv('PROXY_TOKEN') or os.getenv('LOCAL_AI_TOKEN')

headers = {}
if TOKEN:
    headers['Authorization'] = f'Bearer {TOKEN}'

try:
    r = requests.get(HEALTH, headers=headers, timeout=5)
    print('health_url=', HEALTH)
    print('status_code=', r.status_code)
    try:
        print('body=', r.json())
    except Exception:
        print('body=', r.text)
    sys.exit(0 if r.status_code==200 else 2)
except Exception as e:
    print('error=', str(e))
    sys.exit(3)
