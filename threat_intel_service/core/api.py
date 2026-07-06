"""
Minimal dependency-free HTTP API so other tools (IDS_GUARD, net_guard,
Ad_Blocker) can query the indicator store over the network.

Endpoints:
    GET /check?value=<ioc>          -> verdict JSON
    GET /search?q=<substring>       -> list of matches
    GET /stats                      -> summary stats
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from core.checker import verdict as get_verdict


def make_handler(db):
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, obj, status=200):
            body = json.dumps(obj, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            if parsed.path == "/check":
                value = qs.get("value", [None])[0]
                if not value:
                    self._send_json({"error": "missing 'value' param"}, 400)
                    return
                self._send_json(get_verdict(value, db))

            elif parsed.path == "/search":
                q = qs.get("q", [None])[0]
                if not q:
                    self._send_json({"error": "missing 'q' param"}, 400)
                    return
                self._send_json({"results": db.search(q)})

            elif parsed.path == "/stats":
                self._send_json(db.stats())

            else:
                self._send_json({"error": "not found. Use /check, /search, or /stats"}, 404)

        def log_message(self, fmt, *args):
            pass  # silence default stderr request logging

    return Handler


def run_server(db, host, port):
    handler = make_handler(db)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Threat Intel API listening on http://{host}:{port}")
    print("  GET /check?value=1.2.3.4")
    print("  GET /search?q=example.com")
    print("  GET /stats")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()
