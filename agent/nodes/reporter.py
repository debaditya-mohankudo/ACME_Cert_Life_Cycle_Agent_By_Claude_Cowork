"""
summary_reporter (LLM) node — generate a final human-readable renewal summary.
revocation_reporter (LLM) node — generate a final human-readable revocation summary.
"""
from __future__ import annotations

import config

from agent.state import AgentState

from logger import logger


class SummaryReporterNode:
    """Callable renewal-summary reporter implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Summary reporter: generate final renewal summary.
        Uses LLM if LLM_DISABLED=False, otherwise deterministic formatting.
        """
        if config.settings.LLM_DISABLED:
            return self._run_deterministic(state)
        else:
            return self._run_llm(state)

    def _run_llm(self, state: AgentState) -> dict:
        """LLM-based summary reporter (original implementation)."""
        from langchain_core.messages import HumanMessage, SystemMessage

        from agent.prompts import REPORTER_SYSTEM, REPORTER_USER
        from llm.factory import make_llm

        completed = state.get("completed_renewals", [])
        failed = state.get("failed_renewals", [])
        managed = state.get("managed_domains", [])
        error_log = state.get("error_log", [])

        renewed_and_failed = set(completed) | set(failed)
        skipped = [d for d in managed if d not in renewed_and_failed]

        error_summary = "\n".join(f"  - {e}" for e in error_log) if error_log else "  (none)"

        llm = make_llm(model=config.settings.LLM_MODEL_REPORTER, max_tokens=512)

        messages = [
            SystemMessage(content=REPORTER_SYSTEM),
            HumanMessage(
                content=REPORTER_USER.format(
                    completed=", ".join(completed) or "(none)",
                    failed=", ".join(failed) or "(none)",
                    skipped=", ".join(skipped) or "(none)",
                    error_log=error_summary,
                )
            ),
        ]

        try:
            response = llm.invoke(messages)
            summary = response.content.strip()
        except Exception as exc:
            logger.error("summary_reporter LLM call failed: %s — using fallback summary", exc)
            completed_str = ", ".join(completed) or "(none)"
            failed_str = ", ".join(failed) or "(none)"
            summary = f"Renewal run complete. Renewed: {completed_str}. Failed: {failed_str}."
            logger.info("\n=== Certificate Renewal Summary ===\n%s\n===================================", summary)
            print(f"\n{'='*50}\nCertificate Renewal Summary\n{'='*50}")
            print(summary)
            print("=" * 50)
            return {"messages": messages}

        logger.info("\n=== Certificate Renewal Summary ===\n%s\n===================================", summary)
        print(f"\n{'='*50}\nCertificate Renewal Summary\n{'='*50}")
        print(summary)
        print("=" * 50)

        return {"messages": messages + [response]}

    def _run_deterministic(self, state: AgentState) -> dict:
        """
        Deterministic summary reporter when LLM is disabled.
        Generates plain-text formatted summary.
        """
        completed = state.get("completed_renewals", [])
        failed = state.get("failed_renewals", [])
        managed = state.get("managed_domains", [])
        error_log = state.get("error_log", [])

        summary = _summary_reporter_deterministic(completed, failed, managed, error_log)

        logger.info("\n=== Certificate Renewal Summary ===\n%s\n===================================", summary)
        print(summary)

        return {"messages": []}  # No LLM messages in deterministic mode


class RevocationReporterNode:
    """Callable revocation-summary reporter implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Revocation reporter: generate final revocation summary.
        Uses LLM if LLM_DISABLED=False, otherwise deterministic formatting.
        """
        if config.settings.LLM_DISABLED:
            return self._run_deterministic(state)
        else:
            return self._run_llm(state)

    def _run_llm(self, state: AgentState) -> dict:
        """LLM-based revocation reporter (original implementation)."""
        from langchain_core.messages import HumanMessage, SystemMessage

        from agent.prompts import REPORTER_SYSTEM, REVOCATION_REPORTER_USER
        from llm.factory import make_llm

        revoked = state.get("revoked_domains", [])
        failed = state.get("failed_revocations", [])
        reason = state.get("revocation_reason", 0)
        error_log = state.get("error_log", [])

        error_summary = "\n".join(f"  - {e}" for e in error_log) if error_log else "  (none)"

        llm = make_llm(model=config.settings.LLM_MODEL_REPORTER, max_tokens=512)

        messages = [
            SystemMessage(content=REPORTER_SYSTEM),
            HumanMessage(
                content=REVOCATION_REPORTER_USER.format(
                    revoked=", ".join(revoked) or "(none)",
                    failed=", ".join(failed) or "(none)",
                    reason=reason,
                    error_log=error_summary,
                )
            ),
        ]

        try:
            response = llm.invoke(messages)
            summary = response.content.strip()
        except Exception as exc:
            logger.error("revocation_reporter LLM call failed: %s — using fallback summary", exc)
            revoked_str = ", ".join(revoked) or "(none)"
            failed_str = ", ".join(failed) or "(none)"
            summary = f"Revocation run complete. Revoked: {revoked_str}. Failed: {failed_str}."
            logger.info("\n=== Certificate Revocation Summary ===\n%s\n=====================================", summary)
            print(f"\n{'='*50}\nCertificate Revocation Summary\n{'='*50}")
            print(summary)
            print("=" * 50)
            return {"messages": messages}

        logger.info("\n=== Certificate Revocation Summary ===\n%s\n=====================================", summary)
        print(f"\n{'='*50}\nCertificate Revocation Summary\n{'='*50}")
        print(summary)
        print("=" * 50)

        return {"messages": messages + [response]}

    def _run_deterministic(self, state: AgentState) -> dict:
        """
        Deterministic revocation reporter when LLM is disabled.
        Generates plain-text formatted summary — mirrors _summary_reporter_deterministic style.
        """
        revoked = state.get("revoked_domains", [])
        failed = state.get("failed_revocations", [])
        reason = state.get("revocation_reason", 0)
        error_log = state.get("error_log", [])

        summary = _revocation_reporter_deterministic(revoked, failed, reason, error_log)

        logger.info("\n=== Certificate Revocation Summary ===\n%s\n=====================================", summary)
        print(summary)

        return {"messages": []}  # No LLM messages in deterministic mode


def _summary_reporter_deterministic(completed, failed, managed_domains, error_log):
    """
    Deterministic summary reporter when LLM is disabled.

    Args:
        completed: List of successfully renewed domains
        failed: List of failed renewal domains
        managed_domains: List of all domains under management
        error_log: List of error messages

    Returns:
        summary: Plain-text formatted summary
    """
    renewed_and_failed = set(completed) | set(failed)
    skipped = [d for d in managed_domains if d not in renewed_and_failed]

    # Determine status
    if not failed:
        status = "SUCCESS"
    elif completed:
        status = "PARTIAL"
    else:
        status = "FAILED"

    summary = (
        "═" * 50 + "\n" +
        "ACME Certificate Renewal Summary\n" +
        "═" * 50 + "\n" +
        f"Renewed:   {len(completed)}: {', '.join(completed) or '(none)'}\n" +
        f"Failed:    {len(failed)}: {', '.join(failed) or '(none)'}\n" +
        f"Skipped:   {len(skipped)}: {', '.join(skipped) or '(none)'}\n" +
        f"Errors:    {len(error_log)}\n" +
        f"Status:    {status}\n" +
        "═" * 50
    )
    return summary


def _revocation_reporter_deterministic(revoked, failed, reason, error_log):
    """
    Deterministic revocation reporter when LLM is disabled.

    Args:
        revoked: List of successfully revoked domains
        failed: List of domains where revocation failed
        reason: RFC 5280 revocation reason code (int)
        error_log: List of error messages

    Returns:
        summary: Plain-text formatted summary
    """
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

    summary = (
        "═" * 50 + "\n" +
        "ACME Certificate Revocation Summary\n" +
        "═" * 50 + "\n" +
        f"Revoked:  {len(revoked)}: {', '.join(revoked) or '(none)'}\n" +
        f"Failed:   {len(failed)}: {', '.join(failed) or '(none)'}\n" +
        f"Reason:   {reason} ({reason_name})\n" +
        f"Errors:   {len(error_log)}\n" +
        f"Status:   {status}\n" +
        "═" * 50
    )
    return summary


def summary_reporter(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `SummaryReporterNode`."""
    return SummaryReporterNode().run(state)


def revocation_reporter(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `RevocationReporterNode`."""
    return RevocationReporterNode().run(state)
