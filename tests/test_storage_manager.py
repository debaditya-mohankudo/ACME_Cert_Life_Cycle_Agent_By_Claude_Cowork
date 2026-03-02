"""
Unit tests for agent/nodes/storage.py.

Covers:
  - _split_pem_chain (pure function)
  - StorageManagerNode guard paths (no full_chain_pem, no privkey.pem)
  - StorageManagerNode success path (fs mocked)
"""
from __future__ import annotations

from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from agent.nodes.storage import StorageManagerNode, _split_pem_chain
from agent.state import AgentState


# ─── _split_pem_chain ─────────────────────────────────────────────────────────

CERT1 = "-----BEGIN CERTIFICATE-----\nMIILeaf\n-----END CERTIFICATE-----\n"
CERT2 = "-----BEGIN CERTIFICATE-----\nMIIInter\n-----END CERTIFICATE-----\n"
CERT3 = "-----BEGIN CERTIFICATE-----\nMIIRoot\n-----END CERTIFICATE-----\n"


def test_split_pem_chain_single_cert():
    leaf, chain = _split_pem_chain(CERT1)
    assert leaf == CERT1
    assert chain == ""


def test_split_pem_chain_two_certs():
    full = CERT1 + CERT2
    leaf, chain = _split_pem_chain(full)
    assert leaf == CERT1
    assert chain == CERT2


def test_split_pem_chain_three_certs():
    full = CERT1 + CERT2 + CERT3
    leaf, chain = _split_pem_chain(full)
    assert leaf == CERT1
    assert chain == CERT2 + CERT3


def test_split_pem_chain_no_blocks_returns_original():
    garbage = "not a pem at all\n"
    leaf, chain = _split_pem_chain(garbage)
    assert leaf == garbage
    assert chain == ""


def test_split_pem_chain_empty_string():
    leaf, chain = _split_pem_chain("")
    assert leaf == ""
    assert chain == ""


# ─── StorageManagerNode guard: no full_chain_pem ─────────────────────────────


def test_storage_manager_no_full_chain_pem_adds_failed_renewal():
    state = cast(
        AgentState,
        {
            "current_domain": "example.com",
            "cert_store_path": "/tmp/certs",
            "current_order": {"full_chain_pem": ""},
            "failed_renewals": [],
            "error_log": [],
        },
    )
    result = StorageManagerNode().run(state)

    assert "example.com" in result["failed_renewals"]
    assert any("no full_chain_pem" in msg for msg in result["error_log"])


def test_storage_manager_missing_order_treated_as_no_chain():
    state = cast(
        AgentState,
        {
            "current_domain": "example.com",
            "cert_store_path": "/tmp/certs",
            "current_order": None,
            "failed_renewals": [],
            "error_log": [],
        },
    )
    result = StorageManagerNode().run(state)

    assert "example.com" in result["failed_renewals"]
    assert any("no full_chain_pem" in msg for msg in result["error_log"])


# ─── StorageManagerNode guard: privkey.pem not found ─────────────────────────


def test_storage_manager_missing_privkey_adds_failed_renewal(tmp_path):
    # cert_store_path exists but no privkey.pem inside
    cert_store = tmp_path / "certs"
    cert_store.mkdir()

    state = cast(
        AgentState,
        {
            "current_domain": "example.com",
            "cert_store_path": str(cert_store),
            "current_order": {"full_chain_pem": CERT1 + CERT2},
            "failed_renewals": [],
            "error_log": [],
        },
    )
    result = StorageManagerNode().run(state)

    assert "example.com" in result["failed_renewals"]
    assert any("privkey.pem not found" in msg for msg in result["error_log"])


# ─── StorageManagerNode success path ─────────────────────────────────────────


def test_storage_manager_success_adds_completed_renewal(tmp_path):
    cert_store = tmp_path / "certs"
    domain_dir = cert_store / "example.com"
    domain_dir.mkdir(parents=True)
    privkey_path = domain_dir / "privkey.pem"
    privkey_path.write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n")

    fake_metadata = {"issued_at": "2026-01-01T00:00:00Z", "expires_at": "2026-04-01T00:00:00Z"}

    state = cast(
        AgentState,
        {
            "current_domain": "example.com",
            "cert_store_path": str(cert_store),
            "current_order": {
                "full_chain_pem": CERT1 + CERT2,
                "order_url": "https://acme.test/order/1",
            },
            "completed_renewals": [],
            "cert_metadata": {},
            "error_log": [],
        },
    )

    with patch("agent.nodes.storage.fs.write_cert_files", return_value=fake_metadata), \
         patch("agent.nodes.storage.fs.sanitize_domain_for_path", return_value="example.com"):
        result = StorageManagerNode().run(state)

    assert "example.com" in result["completed_renewals"]
    assert result["cert_metadata"]["example.com"] == fake_metadata


def test_storage_manager_write_exception_adds_failed_renewal(tmp_path):
    cert_store = tmp_path / "certs"
    domain_dir = cert_store / "example.com"
    domain_dir.mkdir(parents=True)
    (domain_dir / "privkey.pem").write_text("FAKE-KEY")

    state = cast(
        AgentState,
        {
            "current_domain": "example.com",
            "cert_store_path": str(cert_store),
            "current_order": {
                "full_chain_pem": CERT1 + CERT2,
                "order_url": "",
            },
            "failed_renewals": [],
            "error_log": [],
        },
    )

    with patch("agent.nodes.storage.fs.write_cert_files", side_effect=OSError("disk full")), \
         patch("agent.nodes.storage.fs.sanitize_domain_for_path", return_value="example.com"):
        result = StorageManagerNode().run(state)

    assert "example.com" in result["failed_renewals"]
    assert any("disk full" in msg for msg in result["error_log"])
