"""
Unit tests for error_handler in LLM_DISABLED mode.

Tests the deterministic error handler logic:
- Retries up to MAX_RETRIES with exponential backoff
- Skips domain when max retries exceeded
- Exponential backoff: delay * 2^(retry_count + 1)
- Delay capped at 300 seconds
- Error analysis is plain text, not JSON
"""
from __future__ import annotations

from typing import cast
from unittest.mock import patch

import pytest

from agent.nodes.error_handler import ErrorHandlerNode, _error_handler_deterministic
from agent.state import AgentState


# ─── Fixtures ──────────────────────────────────────────────────────────────


def _base_state(**overrides) -> dict:
    """Create base AgentState for error handler tests."""
    state: dict = {
        "current_domain": "example.com",
        "current_order": {"status": "invalid"},
        "error_log": ["ACME returned 400"],
        "retry_count": 0,
        "max_retries": 3,
        "retry_delay_seconds": 5,
        "failed_renewals": [],
        "pending_renewals": ["example.com"],
        "messages": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── Test: Retry action ────────────────────────────────────────────────────


def test_retries_while_under_max_retries(pebble_settings):
    """Returns retry action when retry_count < max_retries."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=0, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert result["retry_count"] == 1
    assert "retry" in result["error_analysis"].lower()


def test_retry_increments_retry_count(pebble_settings):
    """Each retry increments the retry_count."""
    pebble_settings.LLM_DISABLED = True

    for current_count in [0, 1, 2]:
        state = _base_state(retry_count=current_count, max_retries=3)
        result = ErrorHandlerNode().run(state)
        assert result["retry_count"] == current_count + 1


def test_retry_sets_retry_not_before(pebble_settings):
    """Retry action sets retry_not_before timestamp."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=0, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert "retry_not_before" in result
    assert result["retry_not_before"] > 0


def test_retry_updates_retry_delay(pebble_settings):
    """Retry action updates retry_delay_seconds."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=0, max_retries=3, retry_delay_seconds=5)

    result = ErrorHandlerNode().run(state)

    # Exponential backoff: 5 * 2^(0+1) = 10
    assert result["retry_delay_seconds"] == 10


# ─── Test: Exponential backoff ──────────────────────────────────────────────


def test_exponential_backoff_delay_retry_0(pebble_settings):
    """Retry 0 → delay = base * 2^1 = base * 2."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=0, retry_delay_seconds=5)

    result = ErrorHandlerNode().run(state)

    # 5 * 2^(0+1) = 5 * 2 = 10
    assert result["retry_delay_seconds"] == 10


def test_exponential_backoff_delay_retry_1(pebble_settings):
    """Retry 1 → delay = base * 2^2 = base * 4."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=1, retry_delay_seconds=5)

    result = ErrorHandlerNode().run(state)

    # 5 * 2^(1+1) = 5 * 4 = 20
    assert result["retry_delay_seconds"] == 20


def test_exponential_backoff_delay_retry_2(pebble_settings):
    """Retry 2 → delay = base * 2^3 = base * 8."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=2, retry_delay_seconds=5)

    result = ErrorHandlerNode().run(state)

    # 5 * 2^(2+1) = 5 * 8 = 40
    assert result["retry_delay_seconds"] == 40


def test_exponential_backoff_delay_retry_3(pebble_settings):
    """Retry 3 → delay = base * 2^4 = base * 16."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=3, retry_delay_seconds=5, max_retries=4)

    result = ErrorHandlerNode().run(state)

    # 5 * 2^(3+1) = 5 * 16 = 80
    assert result["retry_delay_seconds"] == 80


def test_exponential_backoff_with_different_base_delay(pebble_settings):
    """Exponential backoff respects different base delays."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=1, retry_delay_seconds=10, max_retries=3)

    result = ErrorHandlerNode().run(state)

    # 10 * 2^(1+1) = 10 * 4 = 40
    assert result["retry_delay_seconds"] == 40


# ─── Test: Delay cap at 300 seconds ────────────────────────────────────────


def test_delay_capped_at_300_seconds_high_retry_count(pebble_settings):
    """Delay never exceeds 300 seconds regardless of retry count."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=10, retry_delay_seconds=5, max_retries=11)

    result = ErrorHandlerNode().run(state)

    # 5 * 2^(10+1) = 5 * 2048 = 10240, but capped at 300
    assert result["retry_delay_seconds"] == 300
    assert result["retry_delay_seconds"] <= 300


def test_delay_cap_with_single_retry_before_cap(pebble_settings):
    """Delay approaching 300 is still capped."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=8, retry_delay_seconds=5, max_retries=9)

    result = ErrorHandlerNode().run(state)

    # 5 * 2^(8+1) = 5 * 512 = 2560, capped at 300
    assert result["retry_delay_seconds"] == 300


# ─── Test: Skip action ─────────────────────────────────────────────────────


def test_skips_when_max_retries_exceeded(pebble_settings):
    """Returns skip action when retry_count >= max_retries."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=3, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert "failed_renewals" in result
    assert "example.com" in result["failed_renewals"]
    assert "skip" in result["error_analysis"].lower()


def test_skip_adds_domain_to_failed_renewals(pebble_settings):
    """Skip action adds domain to failed_renewals."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=3, max_retries=3, failed_renewals=["other.example.com"])

    result = ErrorHandlerNode().run(state)

    assert "example.com" in result["failed_renewals"]
    assert "other.example.com" in result["failed_renewals"]


def test_skip_does_not_set_retry_fields(pebble_settings):
    """Skip action does not set retry_count or retry_not_before."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=3, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert "retry_count" not in result or result.get("retry_count") == 3
    assert "retry_not_before" not in result or result.get("retry_not_before") is None


# ─── Test: No abort in deterministic mode ──────────────────────────────────


def test_deterministic_mode_never_aborts(pebble_settings):
    """Deterministic mode only has retry/skip, never abort."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=3, max_retries=3, pending_renewals=["other.example.com"])

    result = ErrorHandlerNode().run(state)

    # Should skip, not abort
    assert "pending_renewals" not in result or len(result.get("pending_renewals", [])) > 0 or "example.com" in str(result.get("failed_renewals", []))


# ─── Test: Error analysis plain text ────────────────────────────────────────


def test_error_analysis_is_readable_text(pebble_settings):
    """error_analysis is plain text, not JSON."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=1, max_retries=3)

    result = ErrorHandlerNode().run(state)

    analysis = result["error_analysis"]
    assert isinstance(analysis, str)
    assert not analysis.startswith("{")
    assert "deterministic" in analysis.lower()


def test_error_analysis_contains_domain(pebble_settings):
    """error_analysis includes the domain."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(current_domain="api.example.com", retry_count=0, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert "api.example.com" in result["error_analysis"]


def test_error_analysis_contains_error_message(pebble_settings):
    """error_analysis includes the last error."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(error_log=["ACME returned 403: forbidden"], retry_count=0, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert "403" in result["error_analysis"] or "forbidden" in result["error_analysis"].lower()


def test_error_analysis_contains_retry_count(pebble_settings):
    """error_analysis includes retry count info."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=2, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert "2" in result["error_analysis"] or "retry" in result["error_analysis"].lower()


# ─── Test: No LLM messages ────────────────────────────────────────────────


def test_no_llm_messages_in_deterministic_mode(pebble_settings):
    """Deterministic mode returns empty messages list."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(retry_count=0, max_retries=3)

    result = ErrorHandlerNode().run(state)

    assert result["messages"] == []


# ─── Test: Deterministic function directly ─────────────────────────────────


def test_error_handler_deterministic_function_retry():
    """Test _error_handler_deterministic returns (retry, delay)."""
    action, delay = _error_handler_deterministic(
        retry_count=0, max_retries=3, retry_delay_seconds=5
    )

    assert action == "retry"
    assert delay == 10  # 5 * 2^1


def test_error_handler_deterministic_function_skip():
    """Test _error_handler_deterministic returns (skip, 0)."""
    action, delay = _error_handler_deterministic(
        retry_count=3, max_retries=3, retry_delay_seconds=5
    )

    assert action == "skip"
    assert delay == 0


def test_error_handler_deterministic_function_cap():
    """Test _error_handler_deterministic caps delay at 300."""
    action, delay = _error_handler_deterministic(
        retry_count=10, max_retries=11, retry_delay_seconds=5
    )

    assert action == "retry"
    assert delay == 300
