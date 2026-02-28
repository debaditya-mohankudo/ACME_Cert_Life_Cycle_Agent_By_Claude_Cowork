"""
HTTP-01 challenge responder (RFC 8555 §8.3).

The CA verifies domain ownership by making an unauthenticated HTTP GET to
http://<domain>/.well-known/acme-challenge/<token> and checking the response
body exactly matches the key-authorization string: "{token}.{jwk_thumbprint}"
(thumbprint per RFC 7638 §3).

Two modes:
  1. Standalone — spins up a minimal HTTP server on a configurable port
     (default 80).  Requires the process to be able to bind that port
     (use authbind on Linux, or run as root / with CAP_NET_BIND_SERVICE).
  2. Webroot — writes the token file into an existing web-server root so
     an already-running nginx/apache can serve it.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from functools import partial


# ─── Standalone mode ──────────────────────────────────────────────────────────


class _ChallengeHandler(BaseHTTPRequestHandler):
    """Serves only the ACME HTTP-01 challenge path; 404 for everything else."""

    def __init__(self, token: str, key_authorization: str, *args, **kwargs):
        self.token = token
        self.key_authorization = key_authorization
        super().__init__(*args, **kwargs)

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
        with StandaloneHttpChallenge(port=80) as srv:
            srv.start(token, key_authorization)
            # ... tell ACME CA to verify ...
        # server stops automatically
    """

    def __init__(self, port: int = 80) -> None:
        self.port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, token: str, key_authorization: str) -> None:
        """Start the HTTP server in a background thread."""
        if self._server is not None:
            raise RuntimeError("Challenge server is already running")

        handler = partial(_ChallengeHandler, token, key_authorization)
        self._server = HTTPServer(("0.0.0.0", self.port), handler)
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
    token_path.unlink(missing_ok=True)


# ─── Refactoring notes (2026-02-28) ───────────────────────────────────────────
#
# Three behaviour-preserving changes were applied to this module:
#
# 1. Removed ContextDecorator base class from StandaloneHttpChallenge.
#    __enter__ and __exit__ were already manually implemented, making the
#    inherited mixin dead code. The class is used only as a context manager,
#    never as a @decorator, so ContextDecorator served no purpose.
#    Removed: `from contextlib import ContextDecorator`
#
# 2. Replaced Optional[X] annotations with X | None (Python 3.12 native union
#    syntax). `from __future__ import annotations` is already present so the
#    | operator is valid in type hints regardless of runtime Python version.
#    Removed: `from typing import Optional`
#
# 3. Replaced os.remove() + bare try/except FileNotFoundError in
#    remove_webroot_challenge() with Path.unlink(missing_ok=True). Available
#    since Python 3.8; consistent with the Path-based API used throughout
#    write_webroot_challenge(). Eliminates the try/except block entirely.
#    Removed: `import os`
#
# Net import reduction: 3 imports removed (os, Optional, ContextDecorator).
# Zero behaviour changes. All existing tests continue to pass.
if __name__ == "__main__":
    pass
