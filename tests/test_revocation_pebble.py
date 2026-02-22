"""
Integration tests for certificate revocation against Pebble ACME server.

Requires: docker compose -f docker-compose.pebble.yml up -d
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent.revocation_graph import build_revocation_graph, revocation_initial_state
from agent.nodes.account import acme_account_setup
from config import settings


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def pebble_settings(tmp_path, pebble_settings):
    """Use Pebble ACME config and temp cert/account paths."""
    pebble_settings.ACME_INSECURE = True
    pebble_settings.CERT_STORE_PATH = str(tmp_path / "certs")
    pebble_settings.ACCOUNT_KEY_PATH = str(tmp_path / "account.key")
    return pebble_settings


@pytest.fixture
def issued_cert_domain(pebble_settings, tmp_path):
    """
    Issue a test certificate for acme-test.localhost to set up revocation test.
    Returns the domain name.
    """
    from agent.graph import build_graph, initial_state
    from storage import filesystem as fs

    domain = "acme-test.localhost"
    cert_store = str(tmp_path / "certs")

    # Run a full renewal to issue a cert
    graph = build_graph(use_checkpointing=False)
    state = initial_state(
        managed_domains=[domain],
        cert_store_path=cert_store,
        account_key_path=str(tmp_path / "account.key"),
        renewal_threshold_days=30,
    )

    final_state = graph.invoke(state)

    # Verify cert was issued
    assert domain in final_state.get("completed_renewals", [])
    assert fs.read_cert_pem(cert_store, domain) is not None

    return domain


# ── Integration tests ──────────────────────────────────────────────────────


def test_revocation_graph_basic_against_pebble(pebble_settings, tmp_path, issued_cert_domain):
    """Should successfully revoke a certificate against Pebble."""
    domain = issued_cert_domain
    cert_store = str(tmp_path / "certs")
    account_key_path = str(tmp_path / "account.key")

    graph = build_revocation_graph(use_checkpointing=False)
    state = revocation_initial_state(
        domains=[domain],
        reason=0,
        cert_store_path=cert_store,
        account_key_path=account_key_path,
    )

    final_state = graph.invoke(state)

    # Should have successfully revoked
    assert domain in final_state["revoked_domains"]
    assert final_state["failed_revocations"] == []


def test_revocation_reason_codes_against_pebble(pebble_settings, tmp_path, issued_cert_domain):
    """Should accept valid RFC 5280 reason codes."""
    domain = issued_cert_domain
    cert_store = str(tmp_path / "certs")
    account_key_path = str(tmp_path / "account.key")

    # Test with reason=1 (keyCompromise)
    graph = build_revocation_graph(use_checkpointing=False)
    state = revocation_initial_state(
        domains=[domain],
        reason=1,
        cert_store_path=cert_store,
        account_key_path=account_key_path,
    )

    final_state = graph.invoke(state)

    assert domain in final_state["revoked_domains"]
    assert final_state["revocation_reason"] == 1


def test_revocation_nonexistent_cert_against_pebble(pebble_settings, tmp_path, issued_cert_domain):
    """Should fail gracefully if cert file doesn't exist."""
    domain = "nonexistent.localhost"  # not issued
    cert_store = str(tmp_path / "certs")
    account_key_path = str(tmp_path / "account.key")

    graph = build_revocation_graph(use_checkpointing=False)
    state = revocation_initial_state(
        domains=[domain],
        reason=0,
        cert_store_path=cert_store,
        account_key_path=account_key_path,
    )

    final_state = graph.invoke(state)

    # Should fail gracefully without raising
    assert domain in final_state["failed_revocations"]
    assert len(final_state["error_log"]) > 0
