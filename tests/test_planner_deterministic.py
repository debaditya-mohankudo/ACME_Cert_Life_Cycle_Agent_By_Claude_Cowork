"""
Unit tests for renewal_planner in LLM_DISABLED mode.

Tests the deterministic renewal planner logic:
- Renews all domains with no certificate
- Renews all domains expiring within threshold
- Skips domains beyond threshold
- Prioritizes no-cert domains before expiring domains
- Sorts expiring domains by days_until_expiry (ascending)
"""
from __future__ import annotations

from typing import cast
from unittest.mock import patch

import pytest

from agent.nodes.planner import RenewalPlannerNode, _renewal_planner_deterministic
from agent.state import AgentState


# ─── Fixtures ──────────────────────────────────────────────────────────────


def _base_state(**overrides) -> dict:
    """Create base AgentState for planner tests."""
    state: dict = {
        "cert_records": [],
        "managed_domains": [],
        "renewal_threshold_days": 30,
        "messages": [],
    }
    state.update(overrides)
    return cast("AgentState", state)


# ─── Test: No-cert domains ───────────────────────────────────────────────────


def test_renews_all_no_cert_domains(pebble_settings):
    """Domains with no certificate (days_until_expiry=None) are always renewed."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "api.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
            {"domain": "shop.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
        ],
        managed_domains=["api.example.com", "shop.example.com"],
    )

    result = RenewalPlannerNode().run(state)

    assert result["pending_renewals"] == ["api.example.com", "shop.example.com"]
    assert "deterministic" in result["renewal_plan"].lower()


def test_no_cert_domains_appear_first_in_queue(pebble_settings):
    """No-cert domains are queued before expiring domains."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "expired.example.com", "days_until_expiry": 5, "expiry_date": "2026-03-08"},
            {"domain": "missing.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
        ],
        managed_domains=["expired.example.com", "missing.example.com"],
    )

    result = RenewalPlannerNode().run(state)

    # No-cert domains should come first
    assert result["pending_renewals"] == ["missing.example.com", "expired.example.com"]


# ─── Test: Expiring domains ───────────────────────────────────────────────────


def test_renews_domains_within_threshold(pebble_settings):
    """Domains expiring within threshold are renewed."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "api.example.com", "days_until_expiry": 30, "expiry_date": "2026-04-02"},
            {"domain": "shop.example.com", "days_until_expiry": 15, "expiry_date": "2026-03-18"},
        ],
        managed_domains=["api.example.com", "shop.example.com"],
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    assert set(result["pending_renewals"]) == {"api.example.com", "shop.example.com"}


def test_skips_domains_beyond_threshold(pebble_settings):
    """Domains beyond threshold are skipped."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "api.example.com", "days_until_expiry": 60, "expiry_date": "2026-05-02"},
            {"domain": "shop.example.com", "days_until_expiry": 45, "expiry_date": "2026-04-17"},
        ],
        managed_domains=["api.example.com", "shop.example.com"],
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    assert result["pending_renewals"] == []


def test_mixed_threshold_and_beyond(pebble_settings):
    """Correctly splits domains at threshold boundary."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "within.example.com", "days_until_expiry": 30, "expiry_date": "2026-04-02"},
            {"domain": "beyond.example.com", "days_until_expiry": 31, "expiry_date": "2026-04-03"},
        ],
        managed_domains=["within.example.com", "beyond.example.com"],
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    # days_until_expiry <= threshold → within.example.com renewed
    assert result["pending_renewals"] == ["within.example.com"]


# ─── Test: Sorting by expiry date ────────────────────────────────────────────


def test_expiring_domains_sorted_by_days_ascending(pebble_settings):
    """Expiring domains sorted by days_until_expiry (closest first)."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "expires_later.example.com", "days_until_expiry": 20, "expiry_date": "2026-03-23"},
            {"domain": "expires_sooner.example.com", "days_until_expiry": 10, "expiry_date": "2026-03-13"},
            {"domain": "expires_soonest.example.com", "days_until_expiry": 5, "expiry_date": "2026-03-08"},
        ],
        managed_domains=[
            "expires_later.example.com",
            "expires_sooner.example.com",
            "expires_soonest.example.com",
        ],
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    # Should be ordered: 5 days, 10 days, 20 days
    assert result["pending_renewals"] == [
        "expires_soonest.example.com",
        "expires_sooner.example.com",
        "expires_later.example.com",
    ]


def test_same_days_until_expiry_sorted_by_date(pebble_settings):
    """When days_until_expiry is equal, sort by expiry_date."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "b.example.com", "days_until_expiry": 10, "expiry_date": "2026-03-14"},
            {"domain": "a.example.com", "days_until_expiry": 10, "expiry_date": "2026-03-13"},
            {"domain": "c.example.com", "days_until_expiry": 10, "expiry_date": "2026-03-15"},
        ],
        managed_domains=["a.example.com", "b.example.com", "c.example.com"],
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    # Same days, but sorted by date (ascending)
    assert result["pending_renewals"] == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
    ]


# ─── Test: Complex scenarios ─────────────────────────────────────────────────


def test_mixed_no_cert_and_expiring_domains(pebble_settings):
    """Combines no-cert and expiring domains with correct ordering."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "expires_10.example.com", "days_until_expiry": 10, "expiry_date": "2026-03-13"},
            {"domain": "no_cert_2.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
            {"domain": "expires_5.example.com", "days_until_expiry": 5, "expiry_date": "2026-03-08"},
            {"domain": "no_cert_1.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
        ],
        managed_domains=[
            "no_cert_1.example.com",
            "no_cert_2.example.com",
            "expires_5.example.com",
            "expires_10.example.com",
        ],
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    # Order: [no_cert_domains (in order), expiring_domains_by_date]
    pending = result["pending_renewals"]
    no_cert_domains = pending[:2]
    expiring_domains = pending[2:]

    assert set(no_cert_domains) == {"no_cert_1.example.com", "no_cert_2.example.com"}
    assert expiring_domains == ["expires_5.example.com", "expires_10.example.com"]


def test_empty_cert_records(pebble_settings):
    """Empty cert_records returns empty pending_renewals."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[],
        managed_domains=["api.example.com"],
    )

    result = RenewalPlannerNode().run(state)

    assert result["pending_renewals"] == []


def test_all_fresh_certs_none_renewed(pebble_settings):
    """All domains with fresh certs (beyond threshold) are skipped."""
    pebble_settings.LLM_DISABLED = True

    managed = ["api.example.com", "shop.example.com"]
    state = _base_state(
        cert_records=[
            {"domain": "api.example.com", "days_until_expiry": 60, "expiry_date": "2026-05-02"},
            {"domain": "shop.example.com", "days_until_expiry": 90, "expiry_date": "2026-06-01"},
        ],
        managed_domains=managed,
        renewal_threshold_days=30,
    )

    result = RenewalPlannerNode().run(state)

    assert result["pending_renewals"] == []
    # 2 managed domains, 0 renewed → 2 skipped
    assert len(managed) - len(result["pending_renewals"]) == 2


# ─── Test: Deterministic function directly ──────────────────────────────────


def test_renewal_planner_deterministic_function():
    """Test _renewal_planner_deterministic helper function."""
    cert_records = [
        {"domain": "no_cert.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
        {"domain": "expires_5.example.com", "days_until_expiry": 5, "expiry_date": "2026-03-08"},
        {"domain": "expires_15.example.com", "days_until_expiry": 15, "expiry_date": "2026-03-18"},
    ]
    managed = {"no_cert.example.com", "expires_5.example.com", "expires_15.example.com"}
    threshold = 30

    pending = _renewal_planner_deterministic(cert_records, managed, threshold)

    assert pending == [
        "no_cert.example.com",
        "expires_5.example.com",
        "expires_15.example.com",
    ]


def test_renewal_plan_summary_generated(pebble_settings):
    """Renewal plan summary contains readable text."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "api.example.com", "days_until_expiry": None, "expiry_date": "N/A"},
        ],
        managed_domains=["api.example.com", "other.example.com"],
    )

    result = RenewalPlannerNode().run(state)

    plan = result["renewal_plan"]
    assert "deterministic" in plan.lower()
    assert "threshold" in plan.lower()
    assert "renewing" in plan.lower().replace("renewal", "")
    assert "skipping" in plan.lower()


def test_no_llm_messages_in_deterministic_mode(pebble_settings):
    """Deterministic mode returns empty messages list."""
    pebble_settings.LLM_DISABLED = True

    state = _base_state(
        cert_records=[
            {"domain": "api.example.com", "days_until_expiry": 10, "expiry_date": "2026-03-13"}
        ],
        managed_domains=["api.example.com"],
    )

    result = RenewalPlannerNode().run(state)

    assert result["messages"] == []
