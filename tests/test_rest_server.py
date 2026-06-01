"""
REST server endpoint tests.

All tests use FastAPI's TestClient — no real Uvicorn process, no network calls.
LangGraph and main.py functions are mocked at the boundary so we test routing,
request/response shaping, and error propagation without running the ACME graph.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.main import app

client = TestClient(app, raise_server_exceptions=False)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_settings(**kwargs):
    defaults = dict(
        CA_PROVIDER="letsencrypt_staging",
        ACME_DIRECTORY_URL="https://acme-staging-v02.api.letsencrypt.org/directory",
        LLM_PROVIDER="anthropic",
        ANTHROPIC_API_KEY="test-key",
        OPENAI_API_KEY="",
        HTTP_CHALLENGE_MODE="webroot",
        HTTP_CHALLENGE_PORT=80,
        MANAGED_DOMAINS=["example.com", "api.example.com"],
        CERT_STORE_PATH="/tmp/certs",
        ACME_INSECURE=False,
        LLM_DISABLED=False,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


_RENEW_SUCCESS = {
    "completed_renewals": ["example.com"],
    "failed_renewals": [],
    "error_log": [],
}

_REVOKE_SUCCESS = {
    "revoked_domains": ["example.com"],
    "failed_revocations": [],
    "error_log": [],
}


# ── GET /health ───────────────────────────────────────────────────────────────

class TestHealth:
    def test_ok_when_fully_configured(self):
        with patch("config.settings", _mock_settings()):
            r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["warnings"] == []
        assert body["provider"] == "letsencrypt_staging"
        assert body["managed_domain_count"] == 2

    def test_warns_when_managed_domains_empty(self):
        with patch("config.settings", _mock_settings(MANAGED_DOMAINS=[])):
            r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False
        assert any("MANAGED_DOMAINS" in w for w in body["warnings"])

    def test_warns_when_api_key_missing(self):
        with patch("config.settings", _mock_settings(ANTHROPIC_API_KEY="")):
            r = client.get("/health")
        body = r.json()
        assert body["ok"] is False
        assert any("ANTHROPIC" in w for w in body["warnings"])

    def test_warns_on_acme_insecure(self):
        with patch("config.settings", _mock_settings(ACME_INSECURE=True)):
            r = client.get("/health")
        body = r.json()
        assert any("ACME_INSECURE" in w for w in body["warnings"])


# ── GET /domains ──────────────────────────────────────────────────────────────

class TestListDomains:
    def test_returns_managed_domains(self):
        with patch("config.settings", _mock_settings()):
            r = client.get("/domains")
        assert r.status_code == 200
        body = r.json()
        assert set(body["managed_domains"]) == {"example.com", "api.example.com"}
        assert body["count"] == 2

    def test_empty_managed_domains(self):
        with patch("config.settings", _mock_settings(MANAGED_DOMAINS=[])):
            r = client.get("/domains")
        body = r.json()
        assert body["managed_domains"] == []
        assert body["count"] == 0


# ── GET /domains/expiring ──────────────────────────────────────────────────────

class TestExpiringDomains:
    def test_returns_expiring_list(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.list_domains_expiring_within", return_value=["example.com"]):
                r = client.get("/domains/expiring?days=30")
        assert r.status_code == 200
        body = r.json()
        assert body["window_days"] == 30
        assert "example.com" in body["expiring_domains"]

    def test_default_days_is_30(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.list_domains_expiring_within", return_value=[]) as mock_fn:
                client.get("/domains/expiring")
        mock_fn.assert_called_once_with(days=30)

    def test_custom_days_parameter(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.list_domains_expiring_within", return_value=[]) as mock_fn:
                r = client.get("/domains/expiring?days=60")
        assert r.status_code == 200
        mock_fn.assert_called_once_with(days=60)

    def test_days_below_minimum_rejected(self):
        r = client.get("/domains/expiring?days=0")
        assert r.status_code == 422

    def test_days_above_maximum_rejected(self):
        r = client.get("/domains/expiring?days=9999")
        assert r.status_code == 422


# ── GET /domains/{domain}/status ──────────────────────────────────────────────

class TestDomainStatus:
    def test_returns_status_for_known_domain(self):
        status = {"domain": "example.com", "status": "valid", "days_remaining": 45}
        with patch("config.settings", _mock_settings()):
            with patch("main.get_domain_statuses", return_value=[status]):
                r = client.get("/domains/example.com/status")
        assert r.status_code == 200
        assert r.json()["domain"] == "example.com"

    def test_404_when_domain_not_found(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.get_domain_statuses", return_value=[]):
                r = client.get("/domains/unknown.com/status")
        assert r.status_code == 404


# ── POST /domains/{domain}/renew ──────────────────────────────────────────────

class TestRenewDomain:
    def test_successful_renewal(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_once", return_value=_RENEW_SUCCESS):
                with patch("logger.set_domain"):
                    r = client.post("/domains/example.com/renew")
        assert r.status_code == 200
        body = r.json()
        assert body["domain"] == "example.com"
        assert body["status"] == "success"
        assert "example.com" in body["completed_renewals"]

    def test_checkpoint_flag_forwarded(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_once", return_value=_RENEW_SUCCESS) as mock_run:
                with patch("logger.set_domain"):
                    client.post("/domains/example.com/renew", json={"checkpoint": True})
        mock_run.assert_called_once_with(domains=["example.com"], use_checkpoint=True)

    def test_session_absorbs_state(self):
        from server.session import session
        with patch("config.settings", _mock_settings()):
            state = {**_RENEW_SUCCESS, "acme_account_url": "https://acme.example.com/acct/1"}
            with patch("main.run_once", return_value=state):
                with patch("logger.set_domain"):
                    client.post("/domains/example.com/renew")
        assert session.acme_account_url == "https://acme.example.com/acct/1"

    def test_set_domain_called_with_domain(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_once", return_value=_RENEW_SUCCESS):
                with patch("logger.set_domain") as mock_set:
                    client.post("/domains/example.com/renew")
        mock_set.assert_called_once_with("example.com")

    def test_500_on_agent_exception(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_once", side_effect=RuntimeError("ACME error")):
                with patch("logger.set_domain"):
                    r = client.post("/domains/example.com/renew")
        assert r.status_code == 500
        assert "ACME error" in r.json()["detail"]


# ── DELETE /domains/{domain}/cert ─────────────────────────────────────────────

class TestRevokeDomainCert:
    def test_successful_revocation(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_revocation", return_value=_REVOKE_SUCCESS):
                with patch("logger.set_domain"):
                    r = client.delete("/domains/example.com/cert")
        assert r.status_code == 200
        body = r.json()
        assert body["domain"] == "example.com"
        assert body["status"] == "success"
        assert "example.com" in body["revoked_domains"]

    def test_reason_and_checkpoint_forwarded(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_revocation", return_value=_REVOKE_SUCCESS) as mock_rev:
                with patch("logger.set_domain"):
                    client.request(
                        "DELETE", "/domains/example.com/cert",
                        json={"reason": 1, "checkpoint": True},
                    )
        mock_rev.assert_called_once_with(domains=["example.com"], reason=1, use_checkpoint=True)

    def test_invalid_reason_rejected(self):
        with patch("config.settings", _mock_settings()):
            with patch("logger.set_domain"):
                r = client.request(
                    "DELETE", "/domains/example.com/cert",
                    json={"reason": 99},
                )
        assert r.status_code == 422

    def test_set_domain_called_with_domain(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_revocation", return_value=_REVOKE_SUCCESS):
                with patch("logger.set_domain") as mock_set:
                    client.delete("/domains/example.com/cert")
        mock_set.assert_called_once_with("example.com")

    def test_500_on_agent_exception(self):
        with patch("config.settings", _mock_settings()):
            with patch("main.run_revocation", side_effect=RuntimeError("revocation failed")):
                with patch("logger.set_domain"):
                    r = client.delete("/domains/example.com/cert")
        assert r.status_code == 500


# ── GET /domains/{domain}/cert ────────────────────────────────────────────────

class TestReadCertDetails:
    def test_returns_cert_details(self):
        details = {
            "domain": "example.com",
            "cert_found": True,
            "subject_cn": "example.com",
            "issuer_org": "Let's Encrypt",
            "days_remaining": 45,
        }
        with patch("config.settings", _mock_settings()):
            with patch("storage.filesystem.read_cert_pem", return_value="-----BEGIN CERTIFICATE-----\n..."):
                with patch("mcp_server._extract_cert_details", return_value=details, create=True):
                    r = client.get("/domains/example.com/cert")
        assert r.status_code == 200
        assert r.json()["domain"] == "example.com"

    def test_404_when_no_cert(self):
        with patch("config.settings", _mock_settings()):
            with patch("storage.filesystem.read_cert_pem", return_value=None):
                r = client.get("/domains/example.com/cert")
        assert r.status_code == 404


# ── GET /logs ──────────────────────────────────────────────────────────────────

class TestLogs:
    def test_returns_empty_when_no_db(self, tmp_path):
        # Point log router at a non-existent db path
        import server.routers.logs as logs_router
        original = logs_router._LOG_DB
        logs_router._LOG_DB = tmp_path / "nonexistent.db"
        try:
            r = client.get("/logs?domain=example.com")
        finally:
            logs_router._LOG_DB = original
        assert r.status_code == 200
        body = r.json()
        assert body["logs"] == []
        assert body["count"] == 0

    def test_requires_domain_param(self):
        r = client.get("/logs")
        assert r.status_code == 422

    def test_queries_by_domain(self, tmp_path):
        import sqlite3
        import server.routers.logs as logs_router

        db_path = tmp_path / "logs.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE agent_logs (id INTEGER PRIMARY KEY, domain TEXT, level TEXT, message TEXT, ts TIMESTAMP)"
            )
            conn.execute(
                "INSERT INTO agent_logs (domain, level, message, ts) VALUES (?, ?, ?, ?)",
                ("example.com", "INFO", "Starting renewal", "2026-06-01T10:00:00"),
            )
            conn.execute(
                "INSERT INTO agent_logs (domain, level, message, ts) VALUES (?, ?, ?, ?)",
                ("other.com", "INFO", "Other domain log", "2026-06-01T10:00:01"),
            )

        original = logs_router._LOG_DB
        logs_router._LOG_DB = db_path
        try:
            r = client.get("/logs?domain=example.com")
        finally:
            logs_router._LOG_DB = original

        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["logs"][0]["message"] == "Starting renewal"

    def test_level_filter(self, tmp_path):
        import sqlite3
        import server.routers.logs as logs_router

        db_path = tmp_path / "logs.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE agent_logs (id INTEGER PRIMARY KEY, domain TEXT, level TEXT, message TEXT, ts TIMESTAMP)"
            )
            conn.executemany(
                "INSERT INTO agent_logs (domain, level, message, ts) VALUES (?, ?, ?, ?)",
                [
                    ("example.com", "INFO", "info msg", "2026-06-01T10:00:00"),
                    ("example.com", "ERROR", "error msg", "2026-06-01T10:00:01"),
                ],
            )

        original = logs_router._LOG_DB
        logs_router._LOG_DB = db_path
        try:
            r = client.get("/logs?domain=example.com&level=ERROR")
        finally:
            logs_router._LOG_DB = original

        body = r.json()
        assert body["count"] == 1
        assert body["logs"][0]["level"] == "ERROR"

    def test_limit_parameter(self, tmp_path):
        import sqlite3
        import server.routers.logs as logs_router

        db_path = tmp_path / "logs.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE agent_logs (id INTEGER PRIMARY KEY, domain TEXT, level TEXT, message TEXT, ts TIMESTAMP)"
            )
            conn.executemany(
                "INSERT INTO agent_logs (domain, level, message, ts) VALUES (?, ?, ?, ?)",
                [("example.com", "INFO", f"msg {i}", f"2026-06-01T10:00:{i:02d}") for i in range(10)],
            )

        original = logs_router._LOG_DB
        logs_router._LOG_DB = db_path
        try:
            r = client.get("/logs?domain=example.com&limit=3")
        finally:
            logs_router._LOG_DB = original

        assert r.json()["count"] == 3
