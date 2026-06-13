"""
summary_reporter node — generate a structured renewal summary.
revocation_reporter node — generate a structured revocation summary.
"""
from __future__ import annotations

from agent.state import AgentState
from logger import logger


class SummaryReporterNode:
    """Callable renewal-summary reporter implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        completed = state.get("completed_renewals", [])
        failed = state.get("failed_renewals", [])
        managed = state.get("managed_domains", [])
        error_log = state.get("error_log", [])

        summary = _summary_reporter_deterministic(completed, failed, managed, error_log)

        logger.info("\n=== Certificate Renewal Summary ===\n%s\n===================================", summary)
        print(summary)

        return {"messages": []}


class RevocationReporterNode:
    """Callable revocation-summary reporter implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        revoked = state.get("revoked_domains", [])
        failed = state.get("failed_revocations", [])
        reason = state.get("revocation_reason", 0)
        error_log = state.get("error_log", [])

        summary = _revocation_reporter_deterministic(revoked, failed, reason, error_log)

        logger.info("\n=== Certificate Revocation Summary ===\n%s\n=====================================", summary)
        print(summary)

        return {"messages": []}


def _summary_reporter_deterministic(completed, failed, managed_domains, error_log):
    renewed_and_failed = set(completed) | set(failed)
    skipped = [d for d in managed_domains if d not in renewed_and_failed]

    if not failed:
        status = "SUCCESS"
    elif completed:
        status = "PARTIAL"
    else:
        status = "FAILED"

    return (
        "═" * 50 + "\n"
        "ACME Certificate Renewal Summary\n"
        + "═" * 50 + "\n"
        + f"Renewed:   {len(completed)}: {', '.join(completed) or '(none)'}\n"
        + f"Failed:    {len(failed)}: {', '.join(failed) or '(none)'}\n"
        + f"Skipped:   {len(skipped)}: {', '.join(skipped) or '(none)'}\n"
        + f"Errors:    {len(error_log)}\n"
        + f"Status:    {status}\n"
        + "═" * 50
    )


def _revocation_reporter_deterministic(revoked, failed, reason, error_log):
    _REASON_NAMES = {
        0: "unspecified",
        1: "keyCompromise",
        2: "cACompromise",
        3: "affiliationChanged",
        4: "superseded",
        5: "cessationOfOperation",
        9: "privilegeWithdrawn",
    }
    reason_name = _REASON_NAMES.get(reason, f"code-{reason}")

    if not failed:
        status = "SUCCESS"
    elif revoked:
        status = "PARTIAL"
    else:
        status = "FAILED"

    return (
        "═" * 50 + "\n"
        "ACME Certificate Revocation Summary\n"
        + "═" * 50 + "\n"
        + f"Revoked:  {len(revoked)}: {', '.join(revoked) or '(none)'}\n"
        + f"Failed:   {len(failed)}: {', '.join(failed) or '(none)'}\n"
        + f"Reason:   {reason} ({reason_name})\n"
        + f"Errors:   {len(error_log)}\n"
        + f"Status:   {status}\n"
        + "═" * 50
    )


def summary_reporter(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `SummaryReporterNode`."""
    return SummaryReporterNode().run(state)


def revocation_reporter(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `RevocationReporterNode`."""
    return RevocationReporterNode().run(state)
