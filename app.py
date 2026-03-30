"""
Network Security Scanner - Zero dependencies web server
Solo usa librería estándar de Python 3. Sin Flask, sin pip.
Run: python3 app.py
Open: http://localhost:5000
"""
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from scanner import full_scan

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "index.html")


class ScannerHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} - {fmt % args}")

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(TEMPLATE_PATH, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", len(body))
                self.end_headers()
                self.wfile.write(body)
            except FileNotFoundError:
                self.send_error(404, "index.html not found")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
            target = str(body.get("target", "127.0.0.1")).strip() or "127.0.0.1"
            try:
                result = full_scan(target)
                self.send_json({"ok": True, "data": result})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    server = HTTPServer(("0.0.0.0", port), ScannerHandler)
    print(f"\n  🛡️  Network Security Scanner")
    print(f"  ─────────────────────────────")
    print(f"  ▶  http://localhost:{port}")
    print(f"  Presiona Ctrl+C para detener\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  ⏹  Servidor detenido.")
