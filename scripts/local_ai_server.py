#!/usr/bin/env python3
"""
Lightweight mock local AI server used for development and testing.
Implements two simple endpoints expected by NullShadow:
- GET /api/health  -> {"status": "ok"}
- POST /api/chat   -> {"message": {"content": "..."}}

No external dependencies required.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

HOST = '0.0.0.0'
PORT = 11434

class Handler(BaseHTTPRequestHandler):
    def _set_json(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/health'):
            self._set_json(200)
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path.startswith('/api/chat'):
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length else b''
            try:
                data = json.loads(raw.decode()) if raw else {}
            except Exception:
                data = {}

            # Build a simple reply: echo user last message with a canned prefix
            messages = data.get('messages') or []
            last_user = ''
            for m in reversed(messages):
                if m.get('role') == 'user':
                    last_user = m.get('content', '')
                    break
            if not last_user:
                last_user = data.get('prompt', '') or 'Hello from local AI!'

            reply_text = f"[LocalMock] I received: {last_user}"
            resp = {'message': {'content': reply_text}}
            self._set_json(200)
            self.wfile.write(json.dumps(resp).encode())
            return

        self.send_response(404)
        self.end_headers()

if __name__ == '__main__':
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Local mock AI server starting on http://{HOST}:{PORT} ...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down')
        server.shutdown()
