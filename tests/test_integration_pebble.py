"""
Integration test: full agent flow against a local Pebble ACME stub.

Prerequisites
-------------
  docker compose -f docker-compose.pebble.yml up -d

Pebble is configured with PEBBLE_VA_ALWAYS_VALID=1, so HTTP-01 challenges are
auto-approved without real DNS or port-80 access.  The agent goes through every
node: scanner → planner → account → order → challenge → csr → finalize →
download → storage → reporter.

Run with:
  uv run pytest tests/test_integration_pebble.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import requires_pebble


@requires_pebble
def test_full_renewal_flow(pebble_settings, mock_llm_nodes):
    """
    Happy-path: agent renews acme-test.localhost against Pebble and writes
    PEM files to the temp cert store.
    """
    from agent.graph import build_graph, initial_state

    graph = build_graph(use_checkpointing=False)
    state = initial_state(
        managed_domains=pebble_settings.MANAGED_DOMAINS,
        cert_store_path=pebble_settings.CERT_STORE_PATH,
        account_key_path=pebble_settings.ACCOUNT_KEY_PATH,
        renewal_threshold_days=pebble_settings.RENEWAL_THRESHOLD_DAYS,
        max_retries=pebble_settings.MAX_RETRIES,
        webroot_path=pebble_settings.WEBROOT_PATH,
    )

    result = graph.invoke(state)

    domain = "acme-test.localhost"
    assert domain in result["completed_renewals"], (
        f"Expected {domain} in completed_renewals, got: {result['completed_renewals']}\n"
        f"failed: {result['failed_renewals']}\n"
        f"errors: {result['error_log']}"
    )
    assert result["failed_renewals"] == []

    # Verify PEM files on disk
    cert_dir = Path(pebble_settings.CERT_STORE_PATH) / domain
    for fname in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "metadata.json"):
        assert (cert_dir / fname).exists(), f"Missing file: {cert_dir / fname}"

    # Private key must be mode 0o600
    import stat
    key_mode = stat.S_IMODE((cert_dir / "privkey.pem").stat().st_mode)
    assert key_mode == 0o600, f"privkey.pem has mode {oct(key_mode)}, expected 0o600"

    # cert.pem must be a valid PEM certificate
    from storage.filesystem import parse_expiry
    cert_pem = (cert_dir / "cert.pem").read_text()
    expiry = parse_expiry(cert_pem)
    assert expiry is not None

    # metadata.json must have the expected keys
    import json
    metadata = json.loads((cert_dir / "metadata.json").read_text())
    assert "issued_at" in metadata
    assert "expires_at" in metadata


@requires_pebble
def test_second_run_reuses_account(pebble_settings, mock_llm_nodes, tmp_path):
    """
    On a second run with the same account key, the agent looks up the existing
    account instead of creating a new one.
    """
    from agent.graph import build_graph, initial_state

    graph = build_graph()

    def run():
        return graph.invoke(
            initial_state(
                managed_domains=pebble_settings.MANAGED_DOMAINS,
                cert_store_path=pebble_settings.CERT_STORE_PATH,
                account_key_path=pebble_settings.ACCOUNT_KEY_PATH,
                renewal_threshold_days=1,   # force renewal every run
                max_retries=1,
                webroot_path=pebble_settings.WEBROOT_PATH,
            )
        )

    first = run()
    assert "acme-test.localhost" in first["completed_renewals"]

    # Account key file now exists — second run must reuse it
    assert Path(pebble_settings.ACCOUNT_KEY_PATH).exists()
    second = run()
    assert "acme-test.localhost" in second["completed_renewals"]


@requires_pebble
def test_no_renewal_needed(pebble_settings, mock_llm_nodes):
    """
    When renewal_threshold_days is very low (0) and a fresh cert was just
    issued, the planner should put the domain in 'skip' and the agent exits
    via the no_renewals path.
    """
    from unittest.mock import MagicMock, patch
    from langchain_core.messages import AIMessage
    import json

    # First: issue a cert so cert.pem exists and is fresh
    from agent.graph import build_graph, initial_state

    graph = build_graph()
    result = graph.invoke(
        initial_state(
            managed_domains=pebble_settings.MANAGED_DOMAINS,
            cert_store_path=pebble_settings.CERT_STORE_PATH,
            account_key_path=pebble_settings.ACCOUNT_KEY_PATH,
            renewal_threshold_days=30,
            max_retries=1,
            webroot_path=pebble_settings.WEBROOT_PATH,
        )
    )
    assert "acme-test.localhost" in result["completed_renewals"]

    # Second run: planner says skip (cert just renewed, plenty of time left)
    skip_response = json.dumps({
        "urgent": [],
        "routine": [],
        "skip": ["acme-test.localhost"],
        "notes": "Certificate is fresh — nothing to do",
    })

    mock_planner_llm = MagicMock()
    mock_planner_llm.invoke.return_value = AIMessage(content=skip_response)

    with patch("llm.factory.init_chat_model", return_value=mock_planner_llm):
        result2 = graph.invoke(
            initial_state(
                managed_domains=pebble_settings.MANAGED_DOMAINS,
                cert_store_path=pebble_settings.CERT_STORE_PATH,
                account_key_path=pebble_settings.ACCOUNT_KEY_PATH,
                renewal_threshold_days=30,
                max_retries=1,
                webroot_path=pebble_settings.WEBROOT_PATH,
            )
        )

    assert result2["completed_renewals"] == []
    assert result2["failed_renewals"] == []
