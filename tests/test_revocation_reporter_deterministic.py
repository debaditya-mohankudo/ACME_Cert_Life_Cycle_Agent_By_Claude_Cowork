"""
Unit tests for RevocationReporterNode in LLM_DISABLED mode.

Tests the deterministic revocation reporter logic:
- Reports all revoked domains
- Reports all failed revocations
- Correctly maps RFC 5280 reason codes to names
- Status: SUCCESS (no failures), PARTIAL (some failures), FAILED (all failures)
- Output is plain text with box borders (═══)
- LLM is never called when LLM_DISABLED=True
"""
from __future__ import annotations

from typing import cast
from unittest.mock import patch

import pytest

from agent.nodes.reporter import RevocationReporterNode, _revocation_reporter_deterministic
from agent.state import AgentState


# ─── Fixtures ──────────────────────────────────────────────────────────────


def _base_revocation_state(**overrides) -> dict:
    """Create base AgentState for revocation reporter tests."""
    state: dict = {
        "revoked_domains": [],
        "failed_revocations": [],
        "revocation_reason": 0,
        "error_log": [],
        "messages": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── Tests: _revocation_reporter_deterministic helper ─────────────────────


def test_all_revoked_status_is_success():
    """Status is SUCCESS when nothing failed."""
    summary = _revocation_reporter_deterministic(
        revoked=["api.example.com", "shop.example.com"],
        failed=[],
        reason=0,
        error_log=[],
    )
    assert "SUCCESS" in summary
    assert "PARTIAL" not in summary
    assert "FAILED" not in summary


def test_some_failed_status_is_partial():
    """Status is PARTIAL when some domains failed but some were revoked."""
    summary = _revocation_reporter_deterministic(
        revoked=["api.example.com"],
        failed=["shop.example.com"],
        reason=0,
        error_log=[],
    )
    assert "PARTIAL" in summary


def test_all_failed_status_is_failed():
    """Status is FAILED when nothing was revoked."""
    summary = _revocation_reporter_deterministic(
        revoked=[],
        failed=["api.example.com", "shop.example.com"],
        reason=0,
        error_log=[],
    )
    assert "FAILED" in summary
    assert "SUCCESS" not in summary
    assert "PARTIAL" not in summary


def test_empty_state_is_success():
    """Empty revocation run (nothing to do) results in SUCCESS."""
    summary = _revocation_reporter_deterministic(
        revoked=[],
        failed=[],
        reason=0,
        error_log=[],
    )
    assert "SUCCESS" in summary


def test_reason_code_0_unspecified():
    """Reason code 0 maps to 'unspecified'."""
    summary = _revocation_reporter_deterministic([], [], reason=0, error_log=[])
    assert "unspecified" in summary


def test_reason_code_1_key_compromise():
    """Reason code 1 maps to 'keyCompromise'."""
    summary = _revocation_reporter_deterministic([], [], reason=1, error_log=[])
    assert "keyCompromise" in summary


def test_reason_code_2_ca_compromise():
    """Reason code 2 maps to 'cACompromise'."""
    summary = _revocation_reporter_deterministic([], [], reason=2, error_log=[])
    assert "cACompromise" in summary


def test_reason_code_3_affiliation_changed():
    """Reason code 3 maps to 'affiliationChanged'."""
    summary = _revocation_reporter_deterministic([], [], reason=3, error_log=[])
    assert "affiliationChanged" in summary


def test_reason_code_4_superseded():
    """Reason code 4 maps to 'superseded'."""
    summary = _revocation_reporter_deterministic([], [], reason=4, error_log=[])
    assert "superseded" in summary


def test_reason_code_5_cessation():
    """Reason code 5 maps to 'cessationOfOperation'."""
    summary = _revocation_reporter_deterministic([], [], reason=5, error_log=[])
    assert "cessationOfOperation" in summary


def test_reason_code_9_privilege_withdrawn():
    """Reason code 9 maps to 'privilegeWithdrawn'."""
    summary = _revocation_reporter_deterministic([], [], reason=9, error_log=[])
    assert "privilegeWithdrawn" in summary


def test_unknown_reason_code_falls_back_to_code_prefix():
    """Unknown reason codes render as 'code-<N>'."""
    summary = _revocation_reporter_deterministic([], [], reason=99, error_log=[])
    assert "code-99" in summary


def test_box_borders_present():
    """Summary has box-drawing border characters."""
    summary = _revocation_reporter_deterministic(["a.com"], [], reason=0, error_log=[])
    assert "═" in summary


def test_header_present():
    """Summary contains expected header text."""
    summary = _revocation_reporter_deterministic([], [], reason=0, error_log=[])
    assert "ACME Certificate Revocation Summary" in summary


def test_revoked_count_in_summary():
    """Summary shows correct revoked domain count."""
    summary = _revocation_reporter_deterministic(
        revoked=["a.com", "b.com"],
        failed=[],
        reason=0,
        error_log=[],
    )
    assert "Revoked:  2" in summary
    assert "a.com" in summary
    assert "b.com" in summary


def test_failed_count_in_summary():
    """Summary shows correct failed domain count."""
    summary = _revocation_reporter_deterministic(
        revoked=[],
        failed=["x.com"],
        reason=0,
        error_log=[],
    )
    assert "Failed:   1" in summary
    assert "x.com" in summary


def test_error_count_in_summary():
    """Summary shows error log count."""
    summary = _revocation_reporter_deterministic(
        revoked=[],
        failed=[],
        reason=0,
        error_log=["err1", "err2", "err3"],
    )
    assert "Errors:   3" in summary


def test_reason_code_shown_numerically():
    """Summary contains the numeric reason code."""
    summary = _revocation_reporter_deterministic([], [], reason=4, error_log=[])
    assert "4" in summary


# ─── Tests: RevocationReporterNode routing ─────────────────────────────────


def test_run_uses_deterministic_when_llm_disabled(pebble_settings):
    """RevocationReporterNode.run() calls _run_deterministic when LLM_DISABLED=True."""
    pebble_settings.LLM_DISABLED = True

    state = _base_revocation_state(
        revoked_domains=["api.example.com"],
        failed_revocations=[],
        revocation_reason=0,
    )

    result = RevocationReporterNode().run(state)
    assert result == {"messages": []}  # deterministic path returns no LLM messages


def test_run_deterministic_never_calls_make_llm(pebble_settings):
    """make_llm is never imported or called when LLM_DISABLED=True."""
    pebble_settings.LLM_DISABLED = True

    state = _base_revocation_state(revoked_domains=["a.com"])

    with patch("agent.nodes.reporter.RevocationReporterNode._run_llm") as mock_llm:
        RevocationReporterNode().run(state)
        mock_llm.assert_not_called()


def test_run_uses_llm_when_llm_enabled(pebble_settings, mock_llm_nodes):
    """RevocationReporterNode.run() calls _run_llm when LLM_DISABLED=False."""
    pebble_settings.LLM_DISABLED = False
    pebble_settings.ANTHROPIC_API_KEY = "dummy-key"

    state = _base_revocation_state(
        revoked_domains=["api.example.com"],
        failed_revocations=[],
        revocation_reason=0,
    )

    with patch.object(RevocationReporterNode, "_run_llm", return_value={"messages": []}) as mock:
        RevocationReporterNode().run(state)
        mock.assert_called_once_with(state)


def test_callable_interface_delegates_to_run(pebble_settings):
    """__call__ delegates to run()."""
    pebble_settings.LLM_DISABLED = True

    state = _base_revocation_state()
    node = RevocationReporterNode()

    result_call = node(state)
    result_run = node.run(state)

    assert result_call == result_run
