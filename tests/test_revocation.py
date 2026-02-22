"""
Unit and graph topology tests for certificate revocation.

Tests revocation nodes without Pebble ACME server (all mocked).
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from acme.client import AcmeError
from agent.nodes.reporter import revocation_reporter
from agent.nodes.revocation_router import pick_next_revocation_domain, revocation_loop_router
from agent.nodes.revoker import cert_revoker
from agent.revocation_graph import build_revocation_graph, revocation_initial_state
from agent.state import AgentState


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def base_revocation_state() -> dict:
    """Minimal AgentState for revocation tests."""
    return revocation_initial_state(
        domains=["example.com", "api.example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )


# ── pick_next_revocation_domain tests ──────────────────────────────────────


def test_pick_next_revocation_domain_pops_first_domain():
    """Should pop first domain and set current_revocation_domain."""
    state = {
        "revocation_targets": ["example.com", "api.example.com", "shop.example.com"],
        "current_nonce": "existing-nonce",
    }
    result = pick_next_revocation_domain(state)

    assert result["current_revocation_domain"] == "example.com"
    assert result["revocation_targets"] == ["api.example.com", "shop.example.com"]
    assert result["current_nonce"] is None  # Cleared for fresh fetch


def test_pick_next_revocation_domain_last_domain():
    """Should handle the last domain."""
    state = {
        "revocation_targets": ["example.com"],
        "current_nonce": "nonce",
    }
    result = pick_next_revocation_domain(state)

    assert result["current_revocation_domain"] == "example.com"
    assert result["revocation_targets"] == []
    assert result["current_nonce"] is None


def test_pick_next_revocation_domain_empty_targets():
    """Should handle empty targets gracefully."""
    state = {"revocation_targets": []}
    result = pick_next_revocation_domain(state)

    # Should return empty dict on empty targets
    assert result == {}


# ── revocation_loop_router tests ───────────────────────────────────────────


def test_revocation_loop_router_more_targets():
    """Should return 'next_domain' when targets remain."""
    state = {"revocation_targets": ["example.com"]}
    assert revocation_loop_router(state) == "next_domain"


def test_revocation_loop_router_no_targets():
    """Should return 'all_done' when no targets remain."""
    state = {"revocation_targets": []}
    assert revocation_loop_router(state) == "all_done"


# ── cert_revoker tests ─────────────────────────────────────────────────────


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_success(mock_make_client, mock_load_key, mock_read_cert):
    """Should successfully revoke a certificate."""
    # Setup mocks
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_key = MagicMock()
    mock_load_key.return_value = mock_key

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}
    mock_client.revoke_certificate.return_value = "new-nonce-123"

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 4,  # superseded
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    assert result["revoked_domains"] == ["example.com"]
    assert result["current_nonce"] == "new-nonce-123"
    assert result["current_revocation_domain"] is None

    # Verify the revoke call
    mock_client.revoke_certificate.assert_called_once()
    call_kwargs = mock_client.revoke_certificate.call_args[1]
    assert call_kwargs["reason"] == 4


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_missing_cert(mock_make_client, mock_load_key, mock_read_cert):
    """Should gracefully handle missing certificate file."""
    mock_read_cert.return_value = None

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    assert result["failed_revocations"] == ["example.com"]
    assert result["current_revocation_domain"] is None
    assert len(result["error_log"]) == 1
    assert "not found" in result["error_log"][0]

    # Should not call revoke_certificate
    mock_make_client.return_value.revoke_certificate.assert_not_called()


@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.make_client")
def test_cert_revoker_acme_error(mock_make_client, mock_load_key, mock_read_cert):
    """Should handle ACME error and log it."""
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = MagicMock()

    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {"revokeCert": "https://ca.example.com/revokeCert"}

    acme_error = AcmeError(403, {"type": "urn:acme:error:unauthorized", "detail": "Unauthorized"}, "new-nonce-789")
    mock_client.revoke_certificate.side_effect = acme_error

    state = {
        "current_revocation_domain": "example.com",
        "cert_store_path": "/tmp/certs",
        "account_key_path": "/tmp/account.key",
        "acme_account_url": "https://ca.example.com/account/12345",
        "current_nonce": "nonce-456",
        "revocation_reason": 0,
        "revoked_domains": [],
        "failed_revocations": [],
        "error_log": [],
    }

    result = cert_revoker(state)

    assert result["failed_revocations"] == ["example.com"]
    assert result["current_nonce"] == "new-nonce-789"
    assert result["current_revocation_domain"] is None
    assert len(result["error_log"]) == 1
    assert "Unauthorized" in result["error_log"][0]


# ── revocation_reporter tests ──────────────────────────────────────────────


@patch("agent.nodes.reporter.make_llm")
def test_revocation_reporter_success(mock_make_llm):
    """Should call LLM and return summary."""
    mock_llm = MagicMock()
    mock_make_llm.return_value = mock_llm
    mock_llm.invoke.return_value = AIMessage(content="Revocation completed successfully.")

    state = {
        "revoked_domains": ["example.com", "api.example.com"],
        "failed_revocations": [],
        "revocation_reason": 0,
        "error_log": [],
        "messages": [],
    }

    result = revocation_reporter(state)

    assert "messages" in result
    assert len(result["messages"]) == 3  # system, user, ai response
    mock_llm.invoke.assert_called_once()


@patch("agent.nodes.reporter.make_llm")
def test_revocation_reporter_with_failures(mock_make_llm):
    """Should include failed revocations in the report."""
    mock_llm = MagicMock()
    mock_make_llm.return_value = mock_llm
    mock_llm.invoke.return_value = AIMessage(content="Some domains failed.")

    state = {
        "revoked_domains": ["example.com"],
        "failed_revocations": ["api.example.com"],
        "revocation_reason": 4,
        "error_log": ["api.example.com: unauthorized"],
        "messages": [],
    }

    result = revocation_reporter(state)

    # Check that LLM was called with the failures included
    call_args = mock_llm.invoke.call_args[0][0]
    user_message_content = call_args[1].content
    assert "api.example.com" in user_message_content
    assert "unauthorized" in user_message_content


@patch("agent.nodes.reporter.make_llm")
def test_revocation_reporter_llm_failure(mock_make_llm):
    """Should fall back to simple summary on LLM error."""
    mock_llm = MagicMock()
    mock_make_llm.return_value = mock_llm
    mock_llm.invoke.side_effect = Exception("API error")

    state = {
        "revoked_domains": ["example.com"],
        "failed_revocations": [],
        "revocation_reason": 0,
        "error_log": [],
        "messages": [],
    }

    result = revocation_reporter(state)

    # Should still return a valid result with fallback summary
    assert "messages" in result


# ── Topology tests ────────────────────────────────────────────────────────


def test_revocation_graph_topology():
    """Verify the revocation graph compiles without error."""
    graph = build_revocation_graph(use_checkpointing=False)

    # Should compile without error
    assert graph is not None
    # Verify it's a compiled graph (has invoke method)
    assert callable(graph.invoke)


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
@patch("agent.nodes.reporter.make_llm")
def test_revocation_graph_single_domain_flow(
    mock_reporter_llm,
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Test a complete revocation graph run for a single domain."""
    # Setup account mocks
    mock_key_exists.return_value = False
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.create_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    # Setup revoker mocks
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_client.revoke_certificate.return_value = "nonce-789"

    # Setup reporter mock
    mock_reporter_llm.return_value = MagicMock()
    mock_reporter_llm.return_value.invoke.return_value = AIMessage(content="Revoked successfully.")

    # Build and run graph
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Verify results
    assert final_state["revoked_domains"] == ["example.com"]
    assert final_state["failed_revocations"] == []


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
@patch("agent.nodes.reporter.make_llm")
def test_revocation_graph_multi_domain_flow(
    mock_reporter_llm,
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Test revocation graph with multiple domains."""
    # Setup account mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    # Setup revoker mocks
    mock_read_cert.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_client.revoke_certificate.side_effect = ["nonce-789", "nonce-999"]

    # Setup reporter mock
    mock_reporter_llm.return_value = MagicMock()
    mock_reporter_llm.return_value.invoke.return_value = AIMessage(content="All revoked.")

    # Build and run graph
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com", "api.example.com"],
        reason=1,  # keyCompromise
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Should have revoked both domains
    assert set(final_state["revoked_domains"]) == {"example.com", "api.example.com"}
    assert final_state["failed_revocations"] == []
    assert final_state["revocation_reason"] == 1


@patch("agent.nodes.revoker.make_client")
@patch("agent.nodes.revoker.jwslib.load_account_key")
@patch("agent.nodes.revoker.fs.read_cert_pem")
@patch("agent.nodes.account.make_client")
@patch("agent.nodes.account.jwslib.load_account_key")
@patch("agent.nodes.account.jwslib.account_key_exists")
@patch("agent.nodes.reporter.make_llm")
def test_revocation_graph_partial_failure(
    mock_reporter_llm,
    mock_key_exists,
    mock_account_load_key,
    mock_account_make_client,
    mock_read_cert,
    mock_load_key,
    mock_make_client,
):
    """Test revocation graph when one domain fails but others succeed."""
    # Setup account mocks
    mock_key_exists.return_value = True
    mock_account_key = MagicMock()
    mock_account_load_key.return_value = mock_account_key
    mock_account_client = MagicMock()
    mock_account_make_client.return_value = mock_account_client
    mock_account_client.get_directory.return_value = {
        "newNonce": "https://ca.example.com/newNonce",
        "newAccount": "https://ca.example.com/newAccount",
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    mock_account_client.get_nonce.return_value = "nonce-123"
    mock_account_client.lookup_account.return_value = ("https://ca.example.com/account/12345", "nonce-456")

    # Setup revoker mocks: first succeeds, second fails (missing cert), third succeeds
    def read_cert_side_effect(cert_store, domain):
        if domain == "api.example.com":
            return None  # Missing cert
        return "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"

    mock_read_cert.side_effect = read_cert_side_effect
    mock_load_key.return_value = mock_account_key
    mock_client = MagicMock()
    mock_make_client.return_value = mock_client
    mock_client.get_directory.return_value = {
        "revokeCert": "https://ca.example.com/revokeCert",
    }
    # Return new nonces for successful revocations
    mock_client.revoke_certificate.side_effect = ["nonce-789", "nonce-999"]

    # Setup reporter mock
    mock_reporter_llm.return_value = MagicMock()
    mock_reporter_llm.return_value.invoke.return_value = AIMessage(content="Partial success.")

    # Build and run graph
    graph = build_revocation_graph(use_checkpointing=False)
    initial_state = revocation_initial_state(
        domains=["example.com", "api.example.com", "shop.example.com"],
        reason=0,
        cert_store_path="/tmp/certs",
        account_key_path="/tmp/account.key",
    )

    final_state = graph.invoke(initial_state)

    # Verify partial success
    assert "example.com" in final_state["revoked_domains"]
    assert "shop.example.com" in final_state["revoked_domains"]
    assert "api.example.com" in final_state["failed_revocations"]
