"""
MCP server dispatch tests.

The MCP server is now a thin HTTP dispatch layer. These tests verify:
  - Each MCP tool calls the correct FastAPI endpoint
  - Domains are iterated sequentially (no concurrency)
  - Validation (CA inputs, reason codes, domain names) is enforced before HTTP
  - HTTP errors from FastAPI are surfaced cleanly
  - generate_test_cert and query_context remain in the MCP layer (no FastAPI)

No real Uvicorn process is started. urllib calls are patched at the boundary.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

import mcp_server


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_http_response(body: dict, status: int = 200) -> MagicMock:
    """Return a mock that behaves like urllib's response context manager."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    resp.status = status
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _patch_urlopen(body: dict, status: int = 200):
    return patch(
        "urllib.request.urlopen",
        return_value=_make_http_response(body, status),
    )


# ── health ────────────────────────────────────────────────────────────────────

class TestHealthTool:
    def test_calls_get_health(self):
        expected = {"ok": True, "provider": "letsencrypt_staging", "warnings": []}
        with _patch_urlopen(expected) as mock_open:
            result = asyncio.run(mcp_server.health(ca_input_mode="config"))
        assert result["ok"] is True
        called_url = mock_open.call_args[0][0]
        assert called_url.endswith("/health")

    def test_invalid_ca_input_mode_returns_error(self):
        result = asyncio.run(mcp_server.health(ca_input_mode="invalid"))
        assert result["ok"] is False
        assert result["status"] == "failed"
        assert "error" in result

    def test_custom_mode_missing_args_returns_error(self):
        result = asyncio.run(mcp_server.health(ca_input_mode="custom", ca_provider=None))
        assert result["status"] == "failed"

    def test_exception_surfaced_as_error_dict(self):
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            result = asyncio.run(mcp_server.health(ca_input_mode="config"))
        assert result["status"] == "failed"
        assert "error" in result


# ── renew_once ────────────────────────────────────────────────────────────────

class TestRenewOnceTool:
    def test_posts_to_renew_endpoint_per_domain(self):
        renewal = {"completed_renewals": ["example.com"], "failed_renewals": [], "error_log": []}
        with _patch_urlopen(renewal) as mock_open:
            result = asyncio.run(
                mcp_server.renew_once(ca_input_mode="config", domains=["example.com"])
            )
        assert result["status"] == "success"
        assert "example.com" in result["completed_renewals"]
        req = mock_open.call_args[0][0]
        assert "/domains/example.com/renew" in req.full_url

    def test_iterates_domains_sequentially(self):
        renewal_a = {"completed_renewals": ["a.com"], "failed_renewals": [], "error_log": []}
        renewal_b = {"completed_renewals": ["b.com"], "failed_renewals": [], "error_log": []}
        responses = [
            _make_http_response(renewal_a),
            _make_http_response(renewal_b),
        ]
        with patch("urllib.request.urlopen", side_effect=responses):
            result = asyncio.run(
                mcp_server.renew_once(ca_input_mode="config", domains=["a.com", "b.com"])
            )
        assert set(result["completed_renewals"]) == {"a.com", "b.com"}

    def test_falls_back_to_managed_domains_when_none_given(self):
        import config
        from types import SimpleNamespace
        renewal = {"completed_renewals": ["managed.com"], "failed_renewals": [], "error_log": []}
        original = config.settings
        try:
            config.settings = SimpleNamespace(MANAGED_DOMAINS=["managed.com"])
            with _patch_urlopen(renewal) as mock_open:
                result = asyncio.run(mcp_server.renew_once(ca_input_mode="config", domains=None))
        finally:
            config.settings = original
        req = mock_open.call_args[0][0]
        assert "/domains/managed.com/renew" in req.full_url

    def test_invalid_ca_mode_returns_failed(self):
        result = asyncio.run(mcp_server.renew_once(ca_input_mode="bad"))
        assert result["status"] == "failed"

    def test_http_error_surfaced(self):
        import urllib.error
        err = urllib.error.HTTPError(
            url="http://x", code=500, msg="Internal Server Error",
            hdrs=None, fp=None,
        )
        err.read = lambda: b'{"detail": "ACME nonce error"}'
        with patch("urllib.request.urlopen", side_effect=err):
            result = asyncio.run(
                mcp_server.renew_once(ca_input_mode="config", domains=["example.com"])
            )
        assert result["status"] == "failed"
        assert "error" in result


# ── revoke_cert ───────────────────────────────────────────────────────────────

class TestRevokeCertTool:
    def test_posts_delete_to_cert_endpoint(self):
        revoke = {"revoked_domains": ["example.com"], "failed_revocations": [], "error_log": []}
        with _patch_urlopen(revoke) as mock_open:
            result = asyncio.run(
                mcp_server.revoke_cert(
                    ca_input_mode="config", domains=["example.com"], reason=0
                )
            )
        assert result["status"] == "success"
        req = mock_open.call_args[0][0]
        assert "/domains/example.com/cert" in req.full_url

    def test_empty_domains_returns_failed(self):
        result = asyncio.run(mcp_server.revoke_cert(ca_input_mode="config", domains=[]))
        assert result["status"] == "failed"
        assert "error" in result

    def test_invalid_reason_returns_failed(self):
        result = asyncio.run(
            mcp_server.revoke_cert(ca_input_mode="config", domains=["example.com"], reason=99)
        )
        assert result["status"] == "failed"

    def test_valid_reasons_accepted(self):
        revoke = {"revoked_domains": ["x.com"], "failed_revocations": [], "error_log": []}
        for reason in [0, 1, 4, 5]:
            with _patch_urlopen(revoke):
                result = asyncio.run(
                    mcp_server.revoke_cert(
                        ca_input_mode="config", domains=["x.com"], reason=reason
                    )
                )
            assert result["status"] == "success"

    def test_multiple_domains_iterated(self):
        revoke_a = {"revoked_domains": ["a.com"], "failed_revocations": [], "error_log": []}
        revoke_b = {"revoked_domains": ["b.com"], "failed_revocations": [], "error_log": []}
        with patch("urllib.request.urlopen", side_effect=[
            _make_http_response(revoke_a),
            _make_http_response(revoke_b),
        ]):
            result = asyncio.run(
                mcp_server.revoke_cert(
                    ca_input_mode="config", domains=["a.com", "b.com"], reason=0
                )
            )
        assert set(result["revoked_domains"]) == {"a.com", "b.com"}


# ── expiring_in_30_days ───────────────────────────────────────────────────────

class TestExpiringIn30Days:
    def test_calls_expiring_endpoint_with_30_days(self):
        body = {"window_days": 30, "expiring_domains": ["soon.com"]}
        with _patch_urlopen(body) as mock_open:
            result = asyncio.run(mcp_server.expiring_in_30_days())
        assert "soon.com" in result["expiring_domains"]
        called_url = mock_open.call_args[0][0]
        assert "days=30" in called_url

    def test_http_error_surfaced(self):
        import urllib.error
        err = urllib.error.HTTPError(url="http://x", code=503, msg="unavailable", hdrs=None, fp=None)
        err.read = lambda: b'{"detail": "server down"}'
        with patch("urllib.request.urlopen", side_effect=err):
            result = asyncio.run(mcp_server.expiring_in_30_days())
        assert result["status"] == "failed"


# ── expiring_within ───────────────────────────────────────────────────────────

class TestExpiringWithin:
    def test_calls_expiring_endpoint_with_given_days(self):
        body = {"window_days": 60, "expiring_domains": []}
        with _patch_urlopen(body) as mock_open:
            result = asyncio.run(mcp_server.expiring_within(days=60))
        called_url = mock_open.call_args[0][0]
        assert "days=60" in called_url

    def test_days_zero_returns_failed(self):
        result = asyncio.run(mcp_server.expiring_within(days=0))
        assert result["status"] == "failed"

    def test_days_above_3650_returns_failed(self):
        result = asyncio.run(mcp_server.expiring_within(days=9999))
        assert result["status"] == "failed"


# ── list_managed_domains ──────────────────────────────────────────────────────

class TestListManagedDomains:
    def test_calls_domains_endpoint(self):
        body = {"managed_domains": ["a.com", "b.com"], "count": 2}
        with _patch_urlopen(body) as mock_open:
            result = asyncio.run(mcp_server.list_managed_domains())
        assert result["count"] == 2
        called_url = mock_open.call_args[0][0]
        assert called_url.endswith("/domains")


# ── domain_status ─────────────────────────────────────────────────────────────

class TestDomainStatus:
    def test_calls_status_endpoint_per_domain(self):
        body = {"domain": "example.com", "status": "valid", "days_remaining": 45}
        with _patch_urlopen(body) as mock_open:
            result = asyncio.run(mcp_server.domain_status(domains=["example.com"]))
        assert result["status"] == "success"
        assert len(result["domain_statuses"]) == 1
        called_url = mock_open.call_args[0][0]
        assert "/domains/example.com/status" in called_url

    def test_empty_domains_returns_failed(self):
        result = asyncio.run(mcp_server.domain_status(domains=[]))
        assert result["status"] == "failed"

    def test_multiple_domains_each_get_own_call(self):
        status_a = {"domain": "a.com", "status": "valid"}
        status_b = {"domain": "b.com", "status": "expired"}
        with patch("urllib.request.urlopen", side_effect=[
            _make_http_response(status_a),
            _make_http_response(status_b),
        ]):
            result = asyncio.run(mcp_server.domain_status(domains=["a.com", "b.com"]))
        assert len(result["domain_statuses"]) == 2


# ── read_cert_details ─────────────────────────────────────────────────────────

class TestReadCertDetails:
    def test_calls_cert_endpoint_per_domain(self):
        body = {"domain": "example.com", "cert_found": True, "days_remaining": 30}
        with _patch_urlopen(body) as mock_open:
            result = asyncio.run(mcp_server.read_cert_details(domains=["example.com"]))
        assert result["status"] == "success"
        called_url = mock_open.call_args[0][0]
        assert "/domains/example.com/cert" in called_url  # _get uses plain string URL

    def test_empty_domains_returns_failed(self):
        result = asyncio.run(mcp_server.read_cert_details(domains=[]))
        assert result["status"] == "failed"

    def test_404_from_server_returns_cert_not_found(self):
        import urllib.error
        err = urllib.error.HTTPError(url="http://x", code=404, msg="not found", hdrs=None, fp=None)
        err.read = lambda: b'{"detail": "No certificate found"}'
        with patch("urllib.request.urlopen", side_effect=err):
            result = asyncio.run(mcp_server.read_cert_details(domains=["missing.com"]))
        assert result["status"] == "success"
        assert result["cert_details"][0]["cert_found"] is False


# ── generate_test_cert ────────────────────────────────────────────────────────

class TestGenerateTestCert:
    def test_rejects_path_separator_in_domain(self):
        result = asyncio.run(mcp_server.generate_test_cert(domain="evil/../etc", days=30))
        assert result["status"] == "failed"
        assert "path" in result["error"].lower()

    def test_rejects_forward_slash_in_domain(self):
        result = asyncio.run(mcp_server.generate_test_cert(domain="a/b", days=30))
        assert result["status"] == "failed"

    def test_rejects_empty_domain(self):
        result = asyncio.run(mcp_server.generate_test_cert(domain="", days=30))
        assert result["status"] == "failed"
        assert "empty" in result["error"]

    def test_rejects_dot_only_domain(self):
        result = asyncio.run(mcp_server.generate_test_cert(domain=".", days=30))
        assert result["status"] == "failed"

    def test_valid_domain_calls_generate_self_signed(self):
        with patch("scripts.generate_test_cert.generate_self_signed_cert") as mock_gen:
            mock_gen.return_value = None
            result = asyncio.run(mcp_server.generate_test_cert(domain="test.example.com", days=30))
        assert result["status"] == "success"
        assert result["domain"] == "test.example.com"
        assert result["validity_days"] == 30
        mock_gen.assert_called_once()

    def test_expired_cert_gets_expired_status(self):
        with patch("scripts.generate_test_cert.generate_self_signed_cert"):
            result = asyncio.run(mcp_server.generate_test_cert(domain="test.com", days=-10))
        assert result["cert_status"] == "EXPIRED"
        assert result["days_remaining"] < 0

    def test_short_validity_gets_expiring_soon_status(self):
        with patch("scripts.generate_test_cert.generate_self_signed_cert"):
            result = asyncio.run(mcp_server.generate_test_cert(domain="test.com", days=15))
        assert result["cert_status"] == "EXPIRING SOON"

    def test_long_validity_gets_valid_status(self):
        with patch("scripts.generate_test_cert.generate_self_signed_cert"):
            result = asyncio.run(mcp_server.generate_test_cert(domain="test.com", days=90))
        assert result["cert_status"] == "VALID"


# ── CA input validation (shared helper) ──────────────────────────────────────

class TestResolveCAInputs:
    def test_config_mode_returns_none_none(self):
        ca, url = mcp_server._resolve_ca_inputs("config", None, None)
        assert ca is None and url is None

    def test_config_mode_ignores_extra_params(self):
        ca, url = mcp_server._resolve_ca_inputs("config", "digicert", "file:///evil")
        assert ca is None and url is None

    def test_custom_mode_requires_both_params(self):
        with pytest.raises(ValueError):
            mcp_server._resolve_ca_inputs("custom", None, None)

    def test_custom_mode_rejects_invalid_provider(self):
        with pytest.raises(ValueError, match="ca_provider must be one of"):
            mcp_server._resolve_ca_inputs("custom", "evil-ca", "https://example.com/dir")

    def test_custom_mode_rejects_non_http_url(self):
        with pytest.raises(ValueError, match="http"):
            mcp_server._resolve_ca_inputs("custom", "custom", "file:///etc/passwd")

    def test_custom_mode_accepts_valid_inputs(self):
        ca, url = mcp_server._resolve_ca_inputs(
            "custom", "letsencrypt", "https://acme-v02.api.letsencrypt.org/directory"
        )
        assert ca == "letsencrypt"
        assert url.startswith("https://")

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            mcp_server._resolve_ca_inputs("unknown", None, None)
