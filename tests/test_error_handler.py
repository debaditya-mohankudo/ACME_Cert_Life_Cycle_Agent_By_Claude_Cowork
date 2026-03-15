"""
Unit tests for agent/nodes/error_handler.py.

All LLM calls are mocked; no API key needed.
"""
from __future__ import annotations

import json
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

import config
from agent.nodes.error_handler import ErrorHandlerNode
from agent.state import AgentState


@pytest.fixture(autouse=True)
def _ensure_llm_enabled():
    """Ensure LLM_DISABLED is False for all tests in this module (LLM-based tests)."""
    original = config.settings.LLM_DISABLED
    config.settings.LLM_DISABLED = False
    yield
    config.settings.LLM_DISABLED = original


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _mock_llm(response_json: dict) -> MagicMock:
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content=json.dumps(response_json))
    return llm


def _base_state(**overrides) -> dict:
    state: dict = {
        "current_domain": "example.com",
        "current_order": {"status": "invalid"},
        "error_log": ["ACME returned 400"],
        "retry_count": 0,
        "max_retries": 3,
        "retry_delay_seconds": 5,
        "failed_renewals": [],
        "pending_renewals": [],
        "messages": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── retry action ─────────────────────────────────────────────────────────────


def test_error_handler_retry_increments_retry_count(monkeypatch):
    """LLM returning 'retry' increments retry_count and sets retry timing."""
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: _mock_llm(
        {"action": "retry", "suggested_delay_seconds": 10}
    ))

    result = ErrorHandlerNode().run(_base_state())

    assert result["retry_count"] == 1
    assert result["retry_delay_seconds"] == 10
    assert result["retry_not_before"] > 0


def test_error_handler_retry_uses_doubled_delay_when_suggested_zero(monkeypatch):
    """When suggested_delay is 0, fallback is min(retry_delay*2, 300)."""
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: _mock_llm(
        {"action": "retry", "suggested_delay_seconds": 0}
    ))

    result = ErrorHandlerNode().run(_base_state(retry_delay_seconds=20))

    # Fallback: min(20*2, 300) = 40
    assert result["retry_delay_seconds"] == 40


# ─── skip action ──────────────────────────────────────────────────────────────


def test_error_handler_skip_adds_domain_to_failed_renewals(monkeypatch):
    """LLM returning 'skip' adds domain to failed_renewals."""
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: _mock_llm(
        {"action": "skip"}
    ))

    result = ErrorHandlerNode().run(_base_state())

    assert "example.com" in result["failed_renewals"]
    assert "retry_count" not in result


def test_error_handler_skip_preserves_existing_failed_renewals(monkeypatch):
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: _mock_llm(
        {"action": "skip"}
    ))

    result = ErrorHandlerNode().run(_base_state(failed_renewals=["other.com"]))

    assert "other.com" in result["failed_renewals"]
    assert "example.com" in result["failed_renewals"]


# ─── abort action ─────────────────────────────────────────────────────────────


def test_error_handler_abort_clears_pending_renewals(monkeypatch):
    """LLM returning 'abort' moves current + all pending to failed_renewals."""
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: _mock_llm(
        {"action": "abort"}
    ))

    result = ErrorHandlerNode().run(_base_state(
        pending_renewals=["a.com", "b.com"],
        failed_renewals=["old.com"],
    ))

    assert result["pending_renewals"] == []
    assert "example.com" in result["failed_renewals"]
    assert "a.com" in result["failed_renewals"]
    assert "b.com" in result["failed_renewals"]
    assert "old.com" in result["failed_renewals"]


# ─── JSON parse failure fallback ──────────────────────────────────────────────


def test_error_handler_malformed_json_falls_back_to_skip(monkeypatch):
    """Non-JSON LLM response falls back to 'skip' action."""
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content="I cannot help with that.")
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: llm)

    result = ErrorHandlerNode().run(_base_state())

    assert "example.com" in result["failed_renewals"]
    assert "retry_count" not in result


def test_error_handler_stores_raw_llm_response_in_error_analysis(monkeypatch):
    """error_analysis field captures the raw LLM response string."""
    raw = json.dumps({"action": "skip"})
    llm = MagicMock()
    llm.invoke.return_value = AIMessage(content=raw)
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: llm)

    result = ErrorHandlerNode().run(_base_state())

    assert result["error_analysis"] == raw


# ─── messages accumulation ────────────────────────────────────────────────────


def test_error_handler_appends_messages(monkeypatch):
    """error_handler adds system + human + AI messages to state."""
    monkeypatch.setattr("llm.factory.make_llm", lambda **_kw: _mock_llm(
        {"action": "skip"}
    ))

    result = ErrorHandlerNode().run(_base_state())

    # Should contain at least SystemMessage, HumanMessage, AIMessage
    assert len(result["messages"]) >= 3
