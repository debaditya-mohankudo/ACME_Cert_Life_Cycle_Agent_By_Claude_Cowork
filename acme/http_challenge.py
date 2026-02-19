"""
HTTP-01 challenge responder.

Two modes:
  1. Standalone — spins up a minimal HTTP server on a configurable port
     (default 80).  Requires the process to be able to bind that port
     (use authbind on Linux, or run as root / with CAP_NET_BIND_SERVICE).
  2. Webroot — writes the token file into an existing web-server root so
     an already-running nginx/apache can serve it.
"""
from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional


# ─── Standalone mode ──────────────────────────────────────────────────────────


class _ChallengeHandler(BaseHTTPRequestHandler):
    """Serves only the ACME HTTP-01 challenge path; 404 for everything else."""

    # Injected by StandaloneHttpChallenge before binding
    token: str = ""
    key_authorization: str = ""

    def do_GET(self) -> None:
        expected = f"/.well-known/acme-challenge/{self.token}"
        if self.path == expected:
            body = self.key_authorization.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # Silence default access log to avoid cluttering agent output


class StandaloneHttpChallenge:
    """
    Minimal HTTP server that serves exactly one ACME HTTP-01 challenge.

    Usage:
        srv = StandaloneHttpChallenge(port=80)
        srv.start(token, key_authorization)
        # ... tell ACME CA to verify ...
        srv.stop()
    """

    def __init__(self, port: int = 80) -> None:
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, token: str, key_authorization: str) -> None:
        """Start the HTTP server in a background thread."""
        if self._server is not None:
            raise RuntimeError("Challenge server is already running")

        # Patch class-level attributes before instantiating the server
        _ChallengeHandler.token = token
        _ChallengeHandler.key_authorization = key_authorization

        self._server = HTTPServer(("0.0.0.0", self.port), _ChallengeHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shut down the HTTP server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "StandaloneHttpChallenge":
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


# ─── Webroot mode ─────────────────────────────────────────────────────────────


def write_webroot_challenge(
    webroot_path: str, token: str, key_authorization: str
) -> Path:
    """
    Write the key-authorization to the correct path under *webroot_path*.

    The file will be at:
      <webroot_path>/.well-known/acme-challenge/<token>

    Returns the Path of the written file.
    """
    challenge_dir = Path(webroot_path) / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True, exist_ok=True)
    token_path = challenge_dir / token
    token_path.write_text(key_authorization, encoding="utf-8")
    return token_path


def remove_webroot_challenge(webroot_path: str, token: str) -> None:
    """Remove the challenge token file after verification."""
    token_path = Path(webroot_path) / ".well-known" / "acme-challenge" / token
    try:
        os.remove(token_path)
    except FileNotFoundError:
        pass
