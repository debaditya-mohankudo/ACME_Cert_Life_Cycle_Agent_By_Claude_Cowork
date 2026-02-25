"""
Test suite for MCP server security validations and exception handling.

Tests cover:
- Path injection prevention in generate_test_cert
- CA provider validation
- ACME directory URL validation
- Exception handling in all tools
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

import mcp_server


class TestPathInjectionPrevention:
    """Test path traversal attack prevention in generate_test_cert."""

    def test_domain_with_forward_slash_rejected(self, monkeypatch):
        """Verify domains containing forward slashes are rejected."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="test/evil", days=30))
        assert result["status"] == "failed"
        assert "path separators" in result["error"]

    def test_domain_with_backslash_rejected(self, monkeypatch):
        """Verify domains containing backslashes are rejected."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="test\\evil", days=30))
        assert result["status"] == "failed"
        assert "path separators" in result["error"]

    def test_domain_with_parent_dir_traversal_rejected(self, monkeypatch):
        """Verify domains with .. are rejected."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="../../../etc/passwd", days=30))
        assert result["status"] == "failed"
        # .. triggers path separator check first because of the /
        assert "path separators" in result["error"] or "path traversal" in result["error"]

    def test_domain_starting_with_dot_rejected(self, monkeypatch):
        """Verify domains starting with . are rejected (hidden directories)."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain=".hidden", days=30))
        assert result["status"] == "failed"
        assert "path traversal" in result["error"]

    def test_domain_dot_only_rejected(self, monkeypatch):
        """Verify single dot domain is rejected."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain=".", days=30))
        assert result["status"] == "failed"
        # "." is caught by the ".." check which happens first
        assert "path traversal" in result["error"]

    def test_domain_double_dot_rejected(self, monkeypatch):
        """Verify double dot domain is rejected."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="..", days=30))
        assert result["status"] == "failed"
        # ".." is caught by the traversal check
        assert "path traversal" in result["error"]

    def test_empty_domain_rejected(self, monkeypatch):
        """Verify empty domain is rejected."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="", days=30))
        assert result["status"] == "failed"
        assert "empty" in result["error"]

    def test_valid_domain_generates_cert(self, monkeypatch):
        """Verify legitimate domains pass validation and generate certs."""
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="test-cert-example.com", days=30))
        # Should succeed - domain validation passes
        assert result["status"] == "success"
        assert result["domain"] == "test-cert-example.com"
        assert result["validity_days"] == 30


class TestCAInputValidation:
    """Test CA provider and ACME directory URL validation."""

    def test_unknown_ca_provider_rejected(self, monkeypatch):
        """Verify unknown CA provider is rejected."""
        monkeypatch.setattr(mcp_server, "_temporary_settings_override", _noop_settings_override)
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        
        with pytest.raises(ValueError) as excinfo:
            mcp_server._resolve_ca_inputs(
                ca_input_mode="custom",
                ca_provider="evil-ca",
                acme_directory_url="https://example.com/acme/directory",
            )
        assert "evil-ca" not in str(excinfo.value)
        assert "custom, digicert" in str(excinfo.value)  # Shows valid choices

    def test_non_http_directory_url_rejected(self, monkeypatch):
        """Verify non-HTTP URLs are rejected."""
        with pytest.raises(ValueError) as excinfo:
            mcp_server._resolve_ca_inputs(
                ca_input_mode="custom",
                ca_provider="custom",
                acme_directory_url="file:///etc/passwd",
            )
        assert "http" in str(excinfo.value)

    def test_ftp_directory_url_rejected(self, monkeypatch):
        """Verify FTP URLs are rejected."""
        with pytest.raises(ValueError) as excinfo:
            mcp_server._resolve_ca_inputs(
                ca_input_mode="custom",
                ca_provider="custom",
                acme_directory_url="ftp://attacker.com/malicious",
            )
        assert "http" in str(excinfo.value)

    def test_valid_https_url_accepted(self):
        """Verify valid HTTPS URLs are accepted."""
        ca_provider, url = mcp_server._resolve_ca_inputs(
            ca_input_mode="custom",
            ca_provider="custom",
            acme_directory_url="https://example.com/acme/directory",
        )
        assert ca_provider == "custom"
        assert url == "https://example.com/acme/directory"

    def test_valid_http_url_accepted(self):
        """Verify valid HTTP URLs are accepted (for testing)."""
        ca_provider, url = mcp_server._resolve_ca_inputs(
            ca_input_mode="custom",
            ca_provider="custom",
            acme_directory_url="http://localhost:14000/dir",
        )
        assert ca_provider == "custom"
        assert url == "http://localhost:14000/dir"

    def test_known_ca_provider_accepted(self):
        """Verify known CA providers are accepted."""
        for provider in ["digicert", "letsencrypt", "letsencrypt_staging", "zerossl", "sectigo", "custom"]:
            ca_provider, url = mcp_server._resolve_ca_inputs(
                ca_input_mode="custom",
                ca_provider=provider,
                acme_directory_url="https://example.com/acme/directory",
            )
            assert ca_provider == provider

    def test_config_mode_ignores_custom_inputs(self):
        """Verify config mode ignores custom ca_provider and url."""
        ca_provider, url = mcp_server._resolve_ca_inputs(
            ca_input_mode="config",
            ca_provider="invalid-provider",  # Should be ignored
            acme_directory_url="file:///evil",  # Should be ignored
        )
        assert ca_provider is None
        assert url is None


class TestExceptionHandling:
    """Test exception handling in MCP tools."""

    def test_health_handles_exception(self, monkeypatch):
        """Verify health tool returns error dict on exception."""
        def raise_error(**kwargs):
            raise ValueError("Test error")
        
        monkeypatch.setattr(mcp_server, "_resolve_ca_inputs", raise_error)
        
        result = asyncio.run(mcp_server.health(ca_input_mode="config"))
        assert result["status"] == "failed"
        assert result["ok"] is False
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_renew_once_handles_exception(self, monkeypatch):
        """Verify renew_once tool returns error dict on exception."""
        def raise_error(**kwargs):
            raise RuntimeError("Renewal failed")
        
        monkeypatch.setattr(mcp_server, "_resolve_ca_inputs", raise_error)
        
        result = asyncio.run(mcp_server.renew_once(ca_input_mode="config"))
        assert result["status"] == "failed"
        assert "error" in result

    def test_revoke_cert_handles_exception(self, monkeypatch):
        """Verify revoke_cert tool returns error dict on exception."""
        def raise_error(**kwargs):
            raise RuntimeError("Revocation failed")
        
        monkeypatch.setattr(mcp_server, "_resolve_ca_inputs", raise_error)
        
        result = asyncio.run(mcp_server.revoke_cert(ca_input_mode="config", domains=["test.com"]))
        assert result["status"] == "failed"
        assert "error" in result

    def test_generate_test_cert_handles_exception(self, monkeypatch):
        """Verify generate_test_cert tool returns error dict on exception."""
        def raise_error(*args, **kwargs):
            raise OSError("Cannot write certificate")
        
        monkeypatch.setattr(mcp_server, "_operation_lock", _noop_operation_lock)
        monkeypatch.setattr("scripts.generate_test_cert.generate_self_signed_cert", raise_error)
        
        result = asyncio.run(mcp_server.generate_test_cert(domain="example.com", days=30))
        assert result["status"] == "failed"
        assert "error" in result


class TestValidateReason:
    """Test RFC 5280 revocation reason validation."""

    def test_valid_reasons_accepted(self):
        """Verify valid RFC 5280 reasons are accepted."""
        for reason in [0, 1, 4, 5]:
            result = mcp_server._validate_reason(reason)
            assert result == reason

    def test_invalid_reasons_rejected(self):
        """Verify invalid reasons are rejected."""
        for reason in [2, 3, 6, 7, 8, -1, 100]:
            with pytest.raises(ValueError) as excinfo:
                mcp_server._validate_reason(reason)
            assert "0, 1, 4, 5" in str(excinfo.value)


# ============================================================================
# Test Fixtures & Helpers
# ============================================================================

async def _noop_operation_lock_async(*, required: bool):
    """Context manager that does nothing."""
    yield


from contextlib import asynccontextmanager

@asynccontextmanager
async def _noop_operation_lock(*, required: bool):
    """Async context manager that does nothing."""
    yield


from contextlib import contextmanager

@contextmanager
def _noop_settings_override(settings_override=None):
    """Context manager that does nothing."""
    yield
