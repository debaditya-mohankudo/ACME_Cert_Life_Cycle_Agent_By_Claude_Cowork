"""
AgentSession — lightweight in-process session state carried across REST calls.

Design rationale
----------------
Each ACME lifecycle is tied to exactly one domain. The session carries only
state that is expensive to recompute and safe to reuse across calls:

  acme_account_url  — costs a network round-trip to re-fetch; stable once
                      the account is registered with the CA.
  current_nonce     — saves one HEAD request at the start of the next flow;
                      consumed and refreshed by the first ACME POST.
  error_log         — cumulative across flows; useful for debugging without
                      re-running the agent.

Everything else (cert_records, renewal_plan, order state) is either recomputed
cheaply, must be fresh, or is ephemeral per-flow and must not leak between runs.

Async / sync decision
---------------------
This session object is synchronous. No locks, no async primitives. This project
has decided not to introduce async I/O until a ground-up redesign. The FastAPI
server runs with a single Uvicorn worker; concurrent requests are not expected
for a certificate lifecycle agent processing one domain at a time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentSession:
    # Cached after first ACME account setup — avoids a network round-trip per run.
    acme_account_url: Optional[str] = None

    # Last known nonce — seeds the next flow, saving one HEAD request.
    # Consumed and replaced by the first ACME POST in the new run.
    current_nonce: Optional[str] = None

    # Cumulative error log across all flows in this server session.
    error_log: list[str] = field(default_factory=list)

    def absorb_state(self, final_state: dict) -> None:
        """Pull cacheable fields out of a completed graph state."""
        if final_state.get("acme_account_url"):
            self.acme_account_url = final_state["acme_account_url"]
        if final_state.get("current_nonce"):
            self.current_nonce = final_state["current_nonce"]
        self.error_log.extend(final_state.get("error_log", []))

    def as_dict(self) -> dict:
        return {
            "acme_account_url": self.acme_account_url,
            "current_nonce_cached": self.current_nonce is not None,
            "error_log_count": len(self.error_log),
        }


# Process-wide singleton — one session per server lifetime, reset on restart.
session = AgentSession()
