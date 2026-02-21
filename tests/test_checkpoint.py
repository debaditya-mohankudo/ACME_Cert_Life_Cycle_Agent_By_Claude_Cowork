"""
Tests for LangGraph checkpoint mechanics: interrupt, resume, and state integrity.

These tests verify that:
1. Graph interruption pauses at specified nodes
2. Checkpoints persist state correctly
3. Resumed graphs complete successfully
4. Thread isolation works (different thread_ids don't interfere)
5. State integrity is maintained across interrupt/resume cycles

No Pebble required — all ACME operations are mocked.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from langchain_core.messages import AIMessage
import pytest

from agent.graph import build_graph, initial_state
from agent.state import AcmeOrder
from config import settings


# ── Constants ──────────────────────────────────────────────────────────────

DOMAIN = "checkpoint.test"

# Mock ACME order progression (status advances: pending → ready → valid)
MOCK_ORDER: AcmeOrder = {
    "order_url": "https://mock.acme/orders/1",
    "status": "pending",
    "auth_urls": ["https://mock.acme/authz/1"],
    "challenge_urls": ["https://mock.acme/challenge/1"],
    "challenge_tokens": ["mock-token-abc123"],
    "key_authorizations": ["mock-token-abc123.mock-thumbprint"],
    "finalize_url": "https://mock.acme/finalize/1",
    "certificate_url": None,
}

MOCK_ORDER_SETUP = {**MOCK_ORDER}  # After challenge_setup

MOCK_ORDER_READY = {**MOCK_ORDER, "status": "ready"}  # After challenge_verifier

MOCK_ORDER_CSR = {
    **MOCK_ORDER_READY,
    "csr_hex": "deadbeefcafebabe",  # Mocked CSR as hex string
}

MOCK_ORDER_FINAL = {**MOCK_ORDER_CSR, "status": "valid"}  # After order_finalizer

MOCK_ORDER_CERT = {
    **MOCK_ORDER_FINAL,
    "certificate_url": "https://mock.acme/cert/1",  # After cert_downloader
}

# LLM response for checkpoint tests
PLANNER_RESPONSE = json.dumps({
    "urgent": [],
    "routine": [DOMAIN],
    "skip": [],
    "notes": "Checkpoint test run",
})


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture()
def checkpoint_settings(tmp_path: Path):
    """
    Mutate the global settings singleton for the test duration.
    Restores original values after the test.
    """
    originals = {
        "CA_PROVIDER": settings.CA_PROVIDER,
        "ACME_DIRECTORY_URL": settings.ACME_DIRECTORY_URL,
        "MANAGED_DOMAINS": settings.MANAGED_DOMAINS,
        "CERT_STORE_PATH": settings.CERT_STORE_PATH,
        "ACCOUNT_KEY_PATH": settings.ACCOUNT_KEY_PATH,
        "HTTP_CHALLENGE_MODE": settings.HTTP_CHALLENGE_MODE,
        "WEBROOT_PATH": settings.WEBROOT_PATH,
        "ACME_INSECURE": settings.ACME_INSECURE,
        "ANTHROPIC_API_KEY": settings.ANTHROPIC_API_KEY,
        "MAX_RETRIES": settings.MAX_RETRIES,
    }

    cert_store = tmp_path / "certs"
    cert_store.mkdir()
    webroot = tmp_path / "webroot"
    webroot.mkdir()
    account_key = tmp_path / "account.key"

    settings.CA_PROVIDER = "custom"  # Prevent real network calls to production CAs
    settings.ACME_DIRECTORY_URL = "https://mock.acme/dir"  # Won't be used (mocked)
    settings.MANAGED_DOMAINS = [DOMAIN]
    settings.CERT_STORE_PATH = str(cert_store)
    settings.ACCOUNT_KEY_PATH = str(account_key)
    settings.HTTP_CHALLENGE_MODE = "webroot"
    settings.WEBROOT_PATH = str(webroot)
    settings.ACME_INSECURE = True
    settings.ANTHROPIC_API_KEY = "dummy-key"
    settings.MAX_RETRIES = 1

    yield settings

    for k, v in originals.items():
        setattr(settings, k, v)


@pytest.fixture()
def mock_checkpoint_llm():
    """Mock LLM factory to return a checkpoint-test-aware planner response."""
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = AIMessage(content=PLANNER_RESPONSE)

    with patch("llm.factory.init_chat_model", return_value=mock_llm):
        yield


def _mock_storage_manager_side_effect(state: dict) -> dict:
    """
    Mock storage_manager that appends the current domain to completed_renewals.
    Mirrors the real node's behavior of tracking completed domains.
    """
    domain = state.get("current_domain")
    if not domain:
        return {}

    completed = list(state.get("completed_renewals", []))
    completed.append(domain)

    return {
        "completed_renewals": completed,
        "cert_metadata": {domain: {"issued_at": "2024-01-01T00:00:00Z"}},
    }


@pytest.fixture()
def mocked_acme_nodes():
    """
    Patch all network-calling ACME nodes with minimal valid returns.
    Each node increments nonce to verify state flow.
    Patches at agent.graph level to override already-imported references.
    """
    with patch("agent.graph.acme_account_setup") as mock_account, \
         patch("agent.graph.order_initializer") as mock_order, \
         patch("agent.graph.challenge_setup") as mock_challenge_setup, \
         patch("agent.graph.challenge_verifier") as mock_challenge_verify, \
         patch("agent.graph.csr_generator") as mock_csr, \
         patch("agent.graph.order_finalizer") as mock_finalizer, \
         patch("agent.graph.cert_downloader") as mock_downloader, \
         patch("agent.graph.storage_manager") as mock_storage:

        mock_account.return_value = {
            "acme_account_url": "https://mock.acme/account/1",
            "current_nonce": "nonce-account",
        }
        mock_order.return_value = {
            "current_order": MOCK_ORDER,
            "current_nonce": "nonce-order",
        }
        mock_challenge_setup.return_value = {
            "current_order": MOCK_ORDER_SETUP,
            "current_nonce": "nonce-setup",
        }
        mock_challenge_verify.return_value = {
            "current_order": MOCK_ORDER_READY,
            "current_nonce": "nonce-verify",
        }
        mock_csr.return_value = {
            "current_order": MOCK_ORDER_CSR,
            "current_nonce": "nonce-csr",
        }
        mock_finalizer.return_value = {
            "current_order": MOCK_ORDER_FINAL,
            "current_nonce": "nonce-finalizer",
        }
        mock_downloader.return_value = {
            "current_order": MOCK_ORDER_CERT,
            "current_nonce": "nonce-downloader",
        }
        mock_storage.side_effect = _mock_storage_manager_side_effect

        yield {
            "account": mock_account,
            "order": mock_order,
            "challenge_setup": mock_challenge_setup,
            "challenge_verify": mock_challenge_verify,
            "csr": mock_csr,
            "finalizer": mock_finalizer,
            "downloader": mock_downloader,
            "storage": mock_storage,
        }


def _run_checkpoint_graph(checkpoint_settings):
    """
    Helper to build graph, state, and config for checkpoint tests.
    Returns tuple: (graph, state, config)
    """
    graph = build_graph(use_checkpointing=True)
    state = initial_state(
        managed_domains=[DOMAIN],
        cert_store_path=checkpoint_settings.CERT_STORE_PATH,
        account_key_path=checkpoint_settings.ACCOUNT_KEY_PATH,
        renewal_threshold_days=30,
        max_retries=checkpoint_settings.MAX_RETRIES,
        webroot_path=checkpoint_settings.WEBROOT_PATH,
    )
    config = {"configurable": {"thread_id": f"test-{uuid4().hex[:8]}"}}
    return graph, state, config


# ── Tests: Basic Checkpoint Mechanics ──────────────────────────────────────


class TestBasicCheckpointing:
    """Verify checkpoint creation and basic mechanics."""

    def test_complete_run_creates_checkpoint(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that a complete run creates a valid checkpoint."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        final_state = graph.invoke(state, config=config)

        snapshot = graph.get_state(config)
        assert snapshot.next == ()  # No next nodes — run finished
        assert snapshot.values["completed_renewals"] == [DOMAIN]
        assert snapshot.values["pending_renewals"] == []
        assert snapshot.values["failed_renewals"] == []

    def test_checkpoint_history_non_empty(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that checkpoint history contains all node executions."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        graph.invoke(state, config=config)

        history = list(graph.get_state_history(config))
        assert len(history) > 0

        # Collect node names from history
        node_names = set()
        for snapshot in history:
            if snapshot.next:
                node_names.update(snapshot.next)

        # Expect to see key nodes in the history
        expected_nodes = {
            "renewal_planner",
            "acme_account_setup",
            "challenge_verifier",
            "storage_manager",
            "summary_reporter",
        }
        assert expected_nodes.issubset(node_names)


# ── Tests: Interrupt and Resume ────────────────────────────────────────────


class TestInterruptResume:
    """Verify interrupt/resume mechanics."""

    def test_interrupt_before_acme_account_setup(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that interrupt_before pauses before the specified node."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        # Stream until interrupt
        for _ in graph.stream(
            state,
            config=config,
            interrupt_before=["acme_account_setup"],
        ):
            pass

        snapshot = graph.get_state(config)
        assert snapshot.next == ("acme_account_setup",)
        assert snapshot.values["pending_renewals"] == [DOMAIN]

    def test_resume_after_interrupt_completes(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that resuming from an interrupt completes the run."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        # Stream until interrupt
        for _ in graph.stream(
            state,
            config=config,
            interrupt_before=["acme_account_setup"],
        ):
            pass

        # Resume with None input
        for _ in graph.stream(None, config=config):
            pass

        snapshot = graph.get_state(config)
        assert snapshot.next == ()  # Run finished
        assert snapshot.values["completed_renewals"] == [DOMAIN]

    def test_interrupt_before_challenge_verifier(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify interrupt at a deep node in the renewal pipeline."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        # Stream until challenge_verifier
        for _ in graph.stream(
            state,
            config=config,
            interrupt_before=["challenge_verifier"],
        ):
            pass

        snapshot = graph.get_state(config)
        assert snapshot.next == ("challenge_verifier",)
        assert snapshot.values["current_domain"] == DOMAIN
        assert snapshot.values["current_order"] is not None
        assert snapshot.values["current_order"]["status"] == "pending"


# ── Tests: State Integrity ─────────────────────────────────────────────────


class TestStateIntegrity:
    """Verify state fields are preserved across checkpoints."""

    def test_critical_config_fields_preserved_through_checkpoint(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that configuration fields never mutate during checkpoint history."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        graph.invoke(state, config=config)

        history = list(graph.get_state_history(config))

        # Check that config fields are identical across snapshots that have them
        for snapshot in history:
            vals = snapshot.values
            if vals and "managed_domains" in vals:
                # Config fields should never change across snapshots
                assert vals["managed_domains"] == [DOMAIN]
            if vals and "max_retries" in vals:
                assert vals["max_retries"] == 1

    def test_completed_renewals_in_final_checkpoint(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that progress tracking is correct at run completion."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        graph.invoke(state, config=config)

        snapshot = graph.get_state(config)
        assert snapshot.values["completed_renewals"] == [DOMAIN]
        assert snapshot.values["pending_renewals"] == []
        assert snapshot.values["failed_renewals"] == []

    def test_messages_accumulate_across_checkpoints(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that LLM messages accumulate via add_messages reducer."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        graph.invoke(state, config=config)

        snapshot = graph.get_state(config)
        messages = snapshot.values["messages"]
        assert len(messages) > 0
        # Both planner and reporter add messages
        assert len(messages) >= 2


# ── Tests: Thread Isolation ────────────────────────────────────────────────


class TestThreadIsolation:
    """Verify different thread_ids maintain independent state."""

    def test_two_threads_are_independent(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that different thread_ids don't share checkpoint history."""
        graph, state, _ = _run_checkpoint_graph(checkpoint_settings)

        config_a = {"configurable": {"thread_id": "test-thread-a"}}
        config_b = {"configurable": {"thread_id": "test-thread-b"}}

        # Run on thread A
        graph.invoke(state, config=config_a)

        # Run on thread B
        graph.invoke(state, config=config_b)

        # Verify independent states
        snapshot_a = graph.get_state(config_a)
        snapshot_b = graph.get_state(config_b)

        assert snapshot_a.values["completed_renewals"] == [DOMAIN]
        assert snapshot_b.values["completed_renewals"] == [DOMAIN]

        # History should be different lengths or have different steps
        history_a = list(graph.get_state_history(config_a))
        history_b = list(graph.get_state_history(config_b))
        assert history_a != history_b


# ── Tests: Advanced Operations ─────────────────────────────────────────────


class TestAdvancedCheckpoint:
    """Verify advanced checkpoint operations like state injection."""

    def test_update_state_injects_domain_before_resume(
        self,
        checkpoint_settings,
        mock_checkpoint_llm,
        mocked_acme_nodes,
    ):
        """Verify that update_state can inject modified state for resume."""
        graph, state, config = _run_checkpoint_graph(checkpoint_settings)

        # Stream until interrupt before account setup
        for _ in graph.stream(
            state,
            config=config,
            interrupt_before=["acme_account_setup"],
        ):
            pass

        # At this point pending_renewals == [DOMAIN]
        assert graph.get_state(config).values["pending_renewals"] == [DOMAIN]

        # Inject empty pending_renewals to skip processing
        graph.update_state(
            config,
            {"pending_renewals": []},
            as_node="renewal_planner",
        )

        # Resume — should skip to summary_reporter
        for _ in graph.stream(None, config=config):
            pass

        snapshot = graph.get_state(config)
        # No domain was processed (completed_renewals should be empty or unchanged)
        assert snapshot.values["completed_renewals"] == []
