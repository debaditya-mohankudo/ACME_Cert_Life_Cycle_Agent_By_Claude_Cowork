"""
renewal_planner node — analyzes scan results, produces a deterministic renewal plan,
and populates pending_renewals in priority order.

Priority: no-cert domains first, then expiring-soon sorted by days ascending.
"""
from __future__ import annotations

from agent.state import AgentState
from logger import logger


class RenewalPlannerNode:
    """Callable renewal planner implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        cert_records = state["cert_records"]
        managed_domains = set(state["managed_domains"])
        threshold = state["renewal_threshold_days"]

        pending_renewals = _renewal_planner_deterministic(cert_records, managed_domains, threshold)

        renewed_count = len(pending_renewals)
        skipped_count = len(managed_domains) - renewed_count

        plan_summary = (
            f"Deterministic renewal plan:\n"
            f"- Threshold: {threshold} days\n"
            f"- Renewing: {renewed_count} domains\n"
            f"- Skipping: {skipped_count} domains\n"
            f"- Order: no-cert domains first, then by expiry date"
        )

        logger.info("Renewal planner: %s", plan_summary)

        return {
            "renewal_plan": plan_summary,
            "pending_renewals": pending_renewals,
            "messages": [],
        }


def renewal_planner(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `RenewalPlannerNode`."""
    return RenewalPlannerNode().run(state)


def _renewal_planner_deterministic(cert_records, managed_domains, threshold_days):
    """
    Renews all domains with no cert + all domains expiring within threshold.
    Order: [no_cert_domains, expiring_soon_by_days_asc]
    """
    no_cert = []
    expiring_soon = []

    for rec in cert_records:
        domain = rec["domain"]
        days = rec["days_until_expiry"]

        if days is None:
            no_cert.append(domain)
        elif days <= threshold_days:
            expiring_soon.append((domain, days, rec["expiry_date"]))

    expiring_soon.sort(key=lambda x: (x[1], x[2]))
    expiring_soon_domains = [d for d, _, _ in expiring_soon]

    return no_cert + expiring_soon_domains
