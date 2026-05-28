"""
HTTP server — serves static files + JSON API.
"""

import os
import json
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

from ...shared import colors
from .data import build_api_payload


_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

_MIME_MAP = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
}


class _DashboardHandler(BaseHTTPRequestHandler):
    """
    Routes:
      GET /           → static/index.html
      GET /styles.css → static/styles.css
      GET /app.js     → static/app.js
      GET /api/data   → JSON payload
    """

    user_dir: str = ""

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query string

        if path == "/api/data":
            self._serve_json()
        elif path == "/":
            self._serve_static("index.html")
        elif path in ("/styles.css", "/app.js"):
            self._serve_static(path.lstrip("/"))
        else:
            self.send_error(404)

    def _serve_static(self, filename: str):
        fpath = os.path.join(_STATIC_DIR, filename)
        if not os.path.isfile(fpath):
            self.send_error(404)
            return
        ext = os.path.splitext(filename)[1]
        mime = _MIME_MAP.get(ext, "application/octet-stream")
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _serve_json(self):
        payload = json.dumps(build_api_payload(self.user_dir)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass  # silence per-request logs


class WebDashboard:
    """Launch a local web dashboard to display scan results."""

    def __init__(self, user_dir: str):
        self.user_dir = user_dir

    def start(self, port: int = 8443) -> None:
        handler = type(
            "Handler",
            (_DashboardHandler,),
            {"user_dir": self.user_dir},
        )

        try:
            server = HTTPServer(("127.0.0.1", port), handler)
        except OSError:
            print(colors.error(
                f"Port {port} is already in use. "
                f"Try a different port with -web <PORT>"
            ))
            return

        url = f"http://127.0.0.1:{port}"
        print(colors.info(f"Dashboard running at {colors.CYAN}{url}{colors.RESET}"))
        print(colors.info(f"Data directory: {colors.CYAN}{self.user_dir}{colors.RESET}"))
        print(f"  {colors.DIM}Press Ctrl+C to stop{colors.RESET}\n")

        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{colors.info('Dashboard stopped.')}")
            server.server_close()
