"""
Unit tests for HTTP-01 challenge responder (acme/http_challenge.py).

Tests cover:
  - write_webroot_challenge() — correct path, content, directory creation, return value
  - remove_webroot_challenge() — removes file, silent when missing
  - StandaloneHttpChallenge — correct 200/404 responses, double-start guard,
    idempotent stop, context manager cleanup

No Pebble or external services required. Standalone tests use port 0 so the
OS picks a free ephemeral port; real HTTP requests are made over loopback.
"""
from __future__ import annotations

import http.client

import pytest

from acme.http_challenge import (
    StandaloneHttpChallenge,
    remove_webroot_challenge,
    write_webroot_challenge,
)


# ─── write_webroot_challenge ──────────────────────────────────────────────────


class TestWriteWebrootChallenge:
    """Tests for write_webroot_challenge()."""

    def test_creates_file_at_correct_path(self, tmp_path):
        """File is written to <webroot>/.well-known/acme-challenge/<token>."""
        write_webroot_challenge(str(tmp_path), "mytoken", "mytoken.thumbprint")
        expected = tmp_path / ".well-known" / "acme-challenge" / "mytoken"
        assert expected.exists()

    def test_file_content_matches_key_authorization(self, tmp_path):
        """File content exactly matches the key_authorization string."""
        key_auth = "abc123.thumbprintXYZ"
        write_webroot_challenge(str(tmp_path), "tok", key_auth)
        token_path = tmp_path / ".well-known" / "acme-challenge" / "tok"
        assert token_path.read_text(encoding="utf-8") == key_auth

    def test_creates_parent_directories(self, tmp_path):
        """Creates .well-known/acme-challenge/ hierarchy if it does not exist."""
        webroot = tmp_path / "new_webroot"
        # webroot itself does not exist yet
        write_webroot_challenge(str(webroot), "tok", "tok.fp")
        assert (webroot / ".well-known" / "acme-challenge" / "tok").exists()

    def test_returns_path_of_written_file(self, tmp_path):
        """Return value is the Path of the token file."""
        result = write_webroot_challenge(str(tmp_path), "mytoken", "mytoken.fp")
        expected = tmp_path / ".well-known" / "acme-challenge" / "mytoken"
        assert result == expected


# ─── remove_webroot_challenge ─────────────────────────────────────────────────


class TestRemoveWebrootChallenge:
    """Tests for remove_webroot_challenge()."""

    def test_removes_existing_file(self, tmp_path):
        """Token file is deleted after removal."""
        write_webroot_challenge(str(tmp_path), "tok", "tok.fp")
        token_path = tmp_path / ".well-known" / "acme-challenge" / "tok"
        assert token_path.exists()

        remove_webroot_challenge(str(tmp_path), "tok")
        assert not token_path.exists()

    def test_silent_when_file_missing(self, tmp_path):
        """No exception is raised when the token file does not exist."""
        remove_webroot_challenge(str(tmp_path), "nonexistent-token")


# ─── StandaloneHttpChallenge ──────────────────────────────────────────────────


class TestStandaloneHttpChallenge:
    """Tests for StandaloneHttpChallenge.

    All tests use port=0 so the OS assigns a free ephemeral port.
    The actual port is read from srv._server.server_address[1] after start().
    """

    def test_challenge_path_returns_200_with_correct_body(self):
        """GET /.well-known/acme-challenge/<token> returns 200 + key_authorization."""
        token = "testtoken"
        key_auth = "testtoken.somethumbprint"

        with StandaloneHttpChallenge(port=0) as srv:
            srv.start(token, key_auth)
            port = srv._server.server_address[1]

            conn = http.client.HTTPConnection("127.0.0.1", port)
            conn.request("GET", f"/.well-known/acme-challenge/{token}")
            resp = conn.getresponse()

            assert resp.status == 200
            assert resp.read() == key_auth.encode()

    def test_wrong_path_returns_404(self):
        """GET to any path other than the challenge token returns 404."""
        with StandaloneHttpChallenge(port=0) as srv:
            srv.start("tok", "tok.fp")
            port = srv._server.server_address[1]

            conn = http.client.HTTPConnection("127.0.0.1", port)
            conn.request("GET", "/wrong/path")
            resp = conn.getresponse()

            assert resp.status == 404

    def test_start_raises_if_already_running(self):
        """Calling start() a second time raises RuntimeError."""
        with StandaloneHttpChallenge(port=0) as srv:
            srv.start("tok", "tok.fp")
            with pytest.raises(RuntimeError, match="already running"):
                srv.start("tok2", "tok2.fp")

    def test_stop_is_idempotent(self):
        """stop() can be called multiple times without raising."""
        srv = StandaloneHttpChallenge(port=0)
        srv.start("tok", "tok.fp")
        srv.stop()
        srv.stop()  # must not raise

    def test_context_manager_stops_server_on_exit(self):
        """Server is unreachable after the with-block exits."""
        with StandaloneHttpChallenge(port=0) as srv:
            srv.start("tok", "tok.fp")
            port = srv._server.server_address[1]

        # After __exit__, connections must be refused
        with pytest.raises(ConnectionRefusedError):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/")
            conn.getresponse()
