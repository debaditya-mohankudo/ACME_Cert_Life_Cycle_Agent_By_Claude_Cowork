"""
Unit tests for agent/nodes/router.py routing functions.

All functions are pure state-dict → str (or dict) — no mocking required.
"""
from __future__ import annotations

import json

from agent.nodes.router import (
    PickNextDomainNode,
    challenge_router,
    domain_loop_router,
    error_action_router,
    pick_next_domain,
    renewal_router,
)


# ─── pick_next_domain / PickNextDomainNode ────────────────────────────────────


def test_pick_next_domain_pops_first_and_resets_state():
    state = {
        "pending_renewals": ["a.com", "b.com", "c.com"],
        "current_order": {"status": "ready"},
        "current_nonce": "old-nonce",
        "retry_count": 2,
        "retry_delay_seconds": 60,
    }
    result = pick_next_domain(state)

    assert result["current_domain"] == "a.com"
    assert result["pending_renewals"] == ["b.com", "c.com"]
    assert result["current_order"] is None
    assert result["current_nonce"] is None
    assert result["retry_count"] == 0
    assert result["retry_delay_seconds"] == 5


def test_pick_next_domain_last_item():
    state = {"pending_renewals": ["only.com"]}
    result = pick_next_domain(state)

    assert result["current_domain"] == "only.com"
    assert result["pending_renewals"] == []


def test_pick_next_domain_empty_returns_empty_dict():
    result = pick_next_domain({"pending_renewals": []})
    assert result == {}


def test_pick_next_domain_missing_key_returns_empty_dict():
    result = pick_next_domain({})
    assert result == {}


def test_pick_next_domain_node_callable_matches_run():
    state = {"pending_renewals": ["x.com"]}
    node = PickNextDomainNode()
    assert node(state) == node.run(state)


# ─── domain_loop_router ───────────────────────────────────────────────────────


def test_domain_loop_router_pending_returns_next_domain():
    state = {"pending_renewals": ["a.com"]}
    assert domain_loop_router(state) == "next_domain"


def test_domain_loop_router_empty_returns_all_done():
    state = {"pending_renewals": []}
    assert domain_loop_router(state) == "all_done"


def test_domain_loop_router_missing_key_returns_all_done():
    assert domain_loop_router({}) == "all_done"


# ─── challenge_router ─────────────────────────────────────────────────────────


def test_challenge_router_invalid_status_returns_failed():
    state = {"current_order": {"status": "invalid"}}
    assert challenge_router(state) == "challenge_failed"


def test_challenge_router_ready_status_returns_ok():
    state = {"current_order": {"status": "ready"}}
    assert challenge_router(state) == "challenge_ok"


def test_challenge_router_no_order_returns_ok():
    assert challenge_router({"current_order": None}) == "challenge_ok"


def test_challenge_router_no_key_returns_ok():
    assert challenge_router({}) == "challenge_ok"


# ─── renewal_router ───────────────────────────────────────────────────────────


def test_renewal_router_with_pending_returns_renewals_needed():
    state = {"pending_renewals": ["example.com"]}
    assert renewal_router(state) == "renewals_needed"


def test_renewal_router_empty_returns_no_renewals():
    state = {"pending_renewals": []}
    assert renewal_router(state) == "no_renewals"


def test_renewal_router_missing_key_returns_no_renewals():
    assert renewal_router({}) == "no_renewals"


# ─── error_action_router ──────────────────────────────────────────────────────


def test_error_action_router_retry_under_limit():
    state = {
        "error_analysis": json.dumps({"action": "retry"}),
        "retry_count": 1,
        "max_retries": 3,
    }
    assert error_action_router(state) == "retry"


def test_error_action_router_retry_at_limit_falls_to_skip():
    state = {
        "error_analysis": json.dumps({"action": "retry"}),
        "retry_count": 3,
        "max_retries": 3,
    }
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_retry_exceeds_limit_falls_to_skip():
    state = {
        "error_analysis": json.dumps({"action": "retry"}),
        "retry_count": 5,
        "max_retries": 3,
    }
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_abort():
    state = {
        "error_analysis": json.dumps({"action": "abort"}),
        "retry_count": 0,
        "max_retries": 3,
    }
    assert error_action_router(state) == "abort"


def test_error_action_router_skip():
    state = {
        "error_analysis": json.dumps({"action": "skip"}),
        "retry_count": 0,
        "max_retries": 3,
    }
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_unknown_action_falls_to_skip():
    state = {
        "error_analysis": json.dumps({"action": "explode"}),
        "retry_count": 0,
        "max_retries": 3,
    }
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_malformed_json_falls_to_skip():
    state = {
        "error_analysis": "not-json-at-all",
        "retry_count": 0,
        "max_retries": 3,
    }
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_empty_analysis_falls_to_skip():
    state = {
        "error_analysis": "",
        "retry_count": 0,
        "max_retries": 3,
    }
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_missing_analysis_defaults_skip():
    state = {"retry_count": 0, "max_retries": 3}
    assert error_action_router(state) == "skip_domain"


def test_error_action_router_uses_default_max_retries_when_missing():
    """Defaults: max_retries=3, retry_count=0 → retry allowed."""
    state = {"error_analysis": json.dumps({"action": "retry"})}
    assert error_action_router(state) == "retry"
