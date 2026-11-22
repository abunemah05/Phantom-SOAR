"""The shipped Wazuh integratord forwarder delivers an alert file with the ingest-token header."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ENV = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
ENV["no_proxy"] = ENV["NO_PROXY"] = "127.0.0.1"
SCRIPT = Path(__file__).resolve().parents[2] / "wazuh" / "manager" / "custom-phantom"


def _serve(status, received):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received["token"] = self.headers.get("X-Phantom-Ingest-Token")
            received["path"] = self.path
            received["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_forwarder_posts_alert_with_token(tmp_path):
    alert = {"rule": {"id": "5710", "level": 5}, "agent": {"id": "001"}}
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps(alert))
    received = {}
    server = _serve(201, received)
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/webhooks/wazuh"
        done = subprocess.run([sys.executable, str(SCRIPT), str(alert_file), "tok-123", url], capture_output=True, timeout=60, env=ENV)
    finally:
        server.shutdown()
    assert done.returncode == 0, done.stderr
    assert received["token"] == "tok-123" and received["path"] == "/api/webhooks/wazuh" and received["body"] == alert


def test_forwarder_fails_loudly_on_rejected_token(tmp_path):
    alert_file = tmp_path / "alert.json"
    alert_file.write_text("{}")
    server = _serve(401, {})
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/webhooks/wazuh"
        done = subprocess.run([sys.executable, str(SCRIPT), str(alert_file), "bad", url], capture_output=True, timeout=60, env=ENV)
    finally:
        server.shutdown()
    assert done.returncode == 1 and b"HTTP 401" in done.stderr


def test_forwarder_refuses_redirects_and_does_not_leak_the_token(tmp_path):
    alert_file = tmp_path / "alert.json"
    alert_file.write_text("{}")
    leaked = {}

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            leaked["token"] = self.headers.get("X-Phantom-Ingest-Token")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    target = HTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/landing")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector = HTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=redirector.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{redirector.server_port}/api/webhooks/wazuh"
        done = subprocess.run([sys.executable, str(SCRIPT), str(alert_file), "secret-token", url], capture_output=True, timeout=60, env=ENV)
    finally:
        redirector.shutdown()
        target.shutdown()
    assert done.returncode == 1 and b"HTTP 302" in done.stderr
    assert leaked == {}  # the redirect target was never contacted
