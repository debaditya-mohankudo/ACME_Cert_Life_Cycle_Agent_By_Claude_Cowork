"""
Guard-path unit tests for agent/nodes/finalizer.py.

Tests the early-exit branches (missing CSR, missing certificate URL) that
return an error without making any ACME network calls.
"""
from __future__ import annotations

from typing import cast
from unittest.mock import MagicMock, patch

from agent.nodes.finalizer import CertDownloaderNode, OrderFinalizerNode
from agent.state import AgentState


# ─── Shared minimal state ─────────────────────────────────────────────────────

def _base_state(**overrides) -> dict:
    state = {
        "current_domain": "example.com",
        "account_key_path": "/fake/account.key",
        "acme_account_url": "https://acme.test/acct/1",
        "current_nonce": "nonce-abc",
        "current_order": {
            "csr_der_hex": "deadbeef",
            "finalize_url": "https://acme.test/order/1/finalize",
            "order_url": "https://acme.test/order/1",
        },
        "error_log": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── OrderFinalizerNode ───────────────────────────────────────────────────────


def test_order_finalizer_no_csr_returns_error_log(monkeypatch):
    """Missing csr_der_hex exits before any ACME call."""
    monkeypatch.setattr("agent.nodes.finalizer.jwslib.load_account_key", lambda _p: MagicMock())

    state = _base_state(
        current_order={
            "csr_der_hex": "",
            "finalize_url": "https://acme.test/order/1/finalize",
            "order_url": "https://acme.test/order/1",
        }
    )
    result = OrderFinalizerNode().run(state)

    assert "error_log" in result
    assert any("no CSR" in msg for msg in result["error_log"])


def test_order_finalizer_no_csr_does_not_call_acme(monkeypatch):
    """No network call is made when CSR is missing."""
    monkeypatch.setattr("agent.nodes.finalizer.jwslib.load_account_key", lambda _p: MagicMock())
    state = _base_state(current_order={"csr_der_hex": "", "finalize_url": "", "order_url": ""})

    called = []
    monkeypatch.setattr("agent.nodes.finalizer.make_client", lambda: called.append(1) or MagicMock())

    OrderFinalizerNode().run(state)
    assert called == [], "make_client should not be called when CSR is absent"


def test_order_finalizer_acme_error_marks_order_invalid(monkeypatch):
    """AcmeError during finalization sets order status to 'invalid'."""
    from acme.client import AcmeError

    fake_key = MagicMock()
    fake_client = MagicMock()
    fake_client.get_directory.return_value = {}
    fake_client.get_nonce.return_value = "fresh-nonce"
    fake_client.finalize_order.side_effect = AcmeError(400, {"type": "badCSR"}, "nonce")

    monkeypatch.setattr("agent.nodes.finalizer.jwslib.load_account_key", lambda _p: fake_key)
    monkeypatch.setattr("agent.nodes.finalizer.make_client", lambda: fake_client)

    state = _base_state()
    result = OrderFinalizerNode().run(state)

    assert result["current_order"]["status"] == "invalid"
    assert any("Finalization failed" in msg for msg in result["error_log"])


# ─── CertDownloaderNode ───────────────────────────────────────────────────────


def test_cert_downloader_no_cert_url_returns_error_log():
    """Missing certificate_url exits before any ACME call."""
    state = _base_state(
        current_order={
            "csr_der_hex": "deadbeef",
            "certificate_url": "",
        }
    )
    result = CertDownloaderNode().run(state)

    assert "error_log" in result
    assert any("no certificate_url" in msg for msg in result["error_log"])


def test_cert_downloader_no_cert_url_does_not_call_acme(monkeypatch):
    """No network call is made when certificate_url is missing."""
    state = _base_state(current_order={"certificate_url": ""})

    called = []
    monkeypatch.setattr("agent.nodes.finalizer.make_client", lambda: called.append(1) or MagicMock())

    CertDownloaderNode().run(state)
    assert called == [], "make_client should not be called when certificate_url is absent"


def test_cert_downloader_acme_error_adds_to_error_log(monkeypatch):
    """AcmeError during download is captured in error_log."""
    from acme.client import AcmeError

    fake_key = MagicMock()
    fake_client = MagicMock()
    fake_client.get_directory.return_value = {}
    fake_client.get_nonce.return_value = "fresh-nonce"
    fake_client.download_certificate.side_effect = AcmeError(503, {"type": "serverInternal"}, "nonce")

    monkeypatch.setattr("agent.nodes.finalizer.jwslib.load_account_key", lambda _p: fake_key)
    monkeypatch.setattr("agent.nodes.finalizer.make_client", lambda: fake_client)

    state = _base_state(current_order={"certificate_url": "https://acme.test/cert/1"})
    result = CertDownloaderNode().run(state)

    assert any("Certificate download failed" in msg for msg in result["error_log"])


def test_cert_downloader_success_updates_order(monkeypatch):
    """Successful download stores full_chain_pem in current_order."""
    fake_key = MagicMock()
    fake_client = MagicMock()
    fake_client.get_directory.return_value = {}
    fake_client.get_nonce.return_value = "fresh-nonce"
    fake_client.download_certificate.return_value = ("-----BEGIN CERTIFICATE-----\n...\n", "nonce-2")

    monkeypatch.setattr("agent.nodes.finalizer.jwslib.load_account_key", lambda _p: fake_key)
    monkeypatch.setattr("agent.nodes.finalizer.make_client", lambda: fake_client)

    state = _base_state(current_order={"certificate_url": "https://acme.test/cert/1"})
    result = CertDownloaderNode().run(state)

    assert "full_chain_pem" in result["current_order"]
    assert result["current_order"]["full_chain_pem"].startswith("-----BEGIN CERTIFICATE-----")
