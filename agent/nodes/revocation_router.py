"""
Revocation graph routing nodes.

pick_next_revocation_domain — pops the next domain from revocation_targets.
revocation_loop_router — routes between next domain and completion.
"""
from __future__ import annotations

import logging

from agent.state import AgentState

logger = logging.getLogger(__name__)


def pick_next_revocation_domain(state: AgentState) -> dict:
    """
    Pop the next domain from revocation_targets and set current_revocation_domain.
    Also clear current_nonce so the next cert_revoker invocation fetches a fresh one.

    If revocation_targets is empty, this node should not be called (the router
    should have routed to all_done).
    """
    targets = list(state.get("revocation_targets", []))
    if not targets:
        logger.warning("pick_next_revocation_domain called with empty revocation_targets")
        return {}

    next_domain = targets[0]
    remaining = targets[1:]

    logger.info("Starting revocation for domain: %s", next_domain)
    return {
        "current_revocation_domain": next_domain,
        "revocation_targets": remaining,
        "current_nonce": None,  # Clear so cert_revoker fetches a fresh nonce
    }


def revocation_loop_router(state: AgentState) -> str:
    """
    Routing function for add_conditional_edges().

    Returns:
      "next_domain"  — more domains to revoke in revocation_targets
      "all_done"     — no more revocation targets, go to reporter
    """
    targets = state.get("revocation_targets", [])
    if targets:
        return "next_domain"
    return "all_done"
