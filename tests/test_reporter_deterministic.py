"""
Unit tests for summary_reporter in LLM_DISABLED mode.

Tests the deterministic summary reporter logic:
- Reports all completed renewals
- Reports all failed domains
- Correctly identifies skipped domains
- Status: SUCCESS (no failures), PARTIAL (some failures), FAILED (all failures)
- Output is plain text, not JSON
- Formatted with box borders (═══)
"""
from __future__ import annotations

from typing import cast


from agent.nodes.reporter import SummaryReporterNode, _summary_reporter_deterministic
from agent.state import AgentState


# ─── Fixtures ──────────────────────────────────────────────────────────────


def _base_state(**overrides) -> dict:
    """Create base AgentState for reporter tests."""
    state: dict = {
        "completed_renewals": [],
        "failed_renewals": [],
        "managed_domains": [],
        "error_log": [],
        "messages": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── Test: Completed renewals ──────────────────────────────────────────────


def test_reports_all_completed_domains():
    """Summary includes all completed renewals."""

    state = _base_state(
        completed_renewals=["api.example.com", "shop.example.com"],
        failed_renewals=[],
        managed_domains=["api.example.com", "shop.example.com"],
    )

    result = SummaryReporterNode().run(state)

    # result is just {"messages": []}, but the summary is printed
    # We need to check the deterministic function directly
    summary = _summary_reporter_deterministic(
        ["api.example.com", "shop.example.com"],
        [],
        ["api.example.com", "shop.example.com"],
        [],
    )

    assert "api.example.com" in summary
    assert "shop.example.com" in summary
    assert "Renewed:   2" in summary


def test_reports_no_completed_when_empty():
    """Summary correctly shows (none) when no completions."""

    state = _base_state(
        completed_renewals=[],
        failed_renewals=[],
        managed_domains=[],
    )

    summary = _summary_reporter_deterministic([], [], [], [])

    assert "(none)" in summary
    assert "Renewed:   0: (none)" in summary


# ─── Test: Failed domains ──────────────────────────────────────────────────


def test_reports_all_failed_domains():
    """Summary includes all failed domains."""

    failed = ["api.example.com", "shop.example.com"]
    summary = _summary_reporter_deterministic([], failed, failed, [])

    assert "api.example.com" in summary
    assert "shop.example.com" in summary
    assert "Failed:    2" in summary


def test_reports_no_failed_when_empty():
    """Summary correctly shows (none) when no failures."""

    summary = _summary_reporter_deterministic(["api.example.com"], [], ["api.example.com"], [])

    assert "Failed:    0: (none)" in summary


# ─── Test: Skipped domains ────────────────────────────────────────────────


def test_correctly_identifies_skipped_domains():
    """Skipped domains are those not in completed or failed."""

    managed = ["api.example.com", "shop.example.com", "cdn.example.com"]
    completed = ["api.example.com"]
    failed = ["shop.example.com"]

    summary = _summary_reporter_deterministic(completed, failed, managed, [])

    assert "cdn.example.com" in summary
    assert "Skipped:   1" in summary


def test_no_skipped_when_all_renewed_or_failed():
    """No skipped domains when all are either completed or failed."""

    managed = ["api.example.com", "shop.example.com"]
    completed = ["api.example.com"]
    failed = ["shop.example.com"]

    summary = _summary_reporter_deterministic(completed, failed, managed, [])

    assert "Skipped:   0: (none)" in summary


def test_all_skipped_when_none_renewed_or_failed():
    """All domains skipped when none were renewed or failed."""

    managed = ["api.example.com", "shop.example.com"]

    summary = _summary_reporter_deterministic([], [], managed, [])

    assert "Skipped:   2" in summary
    assert "api.example.com" in summary
    assert "shop.example.com" in summary


# ─── Test: Status field ────────────────────────────────────────────────────


def test_status_is_success_when_no_failures():
    """Status is SUCCESS when failed list is empty."""

    summary = _summary_reporter_deterministic(
        ["api.example.com", "shop.example.com"],
        [],
        ["api.example.com", "shop.example.com"],
        [],
    )

    assert "Status:    SUCCESS" in summary


def test_status_is_partial_when_some_failures():
    """Status is PARTIAL when both completed and failed have entries."""

    summary = _summary_reporter_deterministic(
        ["api.example.com"],
        ["shop.example.com"],
        ["api.example.com", "shop.example.com"],
        [],
    )

    assert "Status:    PARTIAL" in summary


def test_status_is_failed_when_all_failures():
    """Status is FAILED when completed is empty and failed has entries."""

    summary = _summary_reporter_deterministic(
        [],
        ["api.example.com", "shop.example.com"],
        ["api.example.com", "shop.example.com"],
        [],
    )

    assert "Status:    FAILED" in summary


def test_status_is_success_when_empty_run():
    """Status is SUCCESS for empty run (no domains to renew)."""

    summary = _summary_reporter_deterministic([], [], [], [])

    assert "Status:    SUCCESS" in summary


# ─── Test: Error log count ────────────────────────────────────────────────


def test_error_count_reported_correctly():
    """Summary includes count of error_log entries."""

    errors = ["Error 1", "Error 2", "Error 3"]
    summary = _summary_reporter_deterministic([], [], [], errors)

    assert "Errors:    3" in summary


def test_no_errors_reported_when_empty():
    """Summary shows 0 errors when error_log is empty."""

    summary = _summary_reporter_deterministic([], [], [], [])

    assert "Errors:    0" in summary


# ─── Test: Plain text formatting ──────────────────────────────────────────


def test_summary_is_plain_text_no_json():
    """Summary is formatted text, not JSON."""

    summary = _summary_reporter_deterministic(
        ["api.example.com"],
        [],
        ["api.example.com"],
        [],
    )

    assert isinstance(summary, str)
    assert not summary.startswith("{")
    assert not summary.endswith("}")


def test_summary_has_box_borders():
    """Summary uses box-drawing characters (═════)."""

    summary = _summary_reporter_deterministic([], [], [], [])

    assert "═" in summary
    assert summary.count("═") >= 2  # Top and bottom


def test_summary_includes_title():
    """Summary includes the title line."""

    summary = _summary_reporter_deterministic([], [], [], [])

    assert "ACME Certificate Renewal Summary" in summary


def test_summary_has_colon_separated_fields():
    """Summary uses 'Field: value' format."""

    summary = _summary_reporter_deterministic([], [], [], [])

    assert "Renewed:" in summary
    assert "Failed:" in summary
    assert "Skipped:" in summary
    assert "Errors:" in summary
    assert "Status:" in summary


# ─── Test: Reporter node integration ──────────────────────────────────────


def test_reporter_node_returns_empty_messages():
    """Reporter node returns empty messages in deterministic mode."""

    state = _base_state(
        completed_renewals=["api.example.com"],
        failed_renewals=[],
        managed_domains=["api.example.com"],
    )

    result = SummaryReporterNode().run(state)

    assert result["messages"] == []


def test_reporter_node_with_complex_state():
    """Reporter node handles complex state correctly."""

    state = _base_state(
        completed_renewals=["api.example.com", "shop.example.com"],
        failed_renewals=["cdn.example.com"],
        managed_domains=["api.example.com", "shop.example.com", "cdn.example.com", "db.example.com"],
        error_log=["Error 1", "Error 2"],
    )

    result = SummaryReporterNode().run(state)

    assert result["messages"] == []
    # No exception raised


# ─── Test: Edge cases ──────────────────────────────────────────────────────


def test_duplicate_domains_in_lists():
    """Handles duplicate entries gracefully (shouldn't happen, but be safe)."""

    # Note: In practice, this shouldn't happen, but we test robustness
    summary = _summary_reporter_deterministic(
        ["api.example.com"],
        ["api.example.com"],  # Shouldn't overlap, but test anyway
        ["api.example.com"],
        [],
    )

    # Should handle without error
    assert "Status:" in summary


def test_empty_error_log():
    """Handles empty error log correctly."""

    summary = _summary_reporter_deterministic(
        ["api.example.com"],
        [],
        ["api.example.com"],
        [],
    )

    assert "Errors:    0" in summary


def test_deterministic_function_directly():
    """Test _summary_reporter_deterministic helper function."""
    summary = _summary_reporter_deterministic(
        completed=["api.example.com"],
        failed=["shop.example.com"],
        managed_domains=["api.example.com", "shop.example.com", "cdn.example.com"],
        error_log=["Error 1"],
    )

    assert "Renewed:   1: api.example.com" in summary
    assert "Failed:    1: shop.example.com" in summary
    assert "Skipped:   1: cdn.example.com" in summary
    assert "Errors:    1" in summary
    assert "Status:    PARTIAL" in summary
