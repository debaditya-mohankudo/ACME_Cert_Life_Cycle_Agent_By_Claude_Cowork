"""
summary_reporter (LLM) node — generate a final human-readable renewal summary.
revocation_reporter (LLM) node — generate a final human-readable revocation summary.
"""
from __future__ import annotations

import config

from langchain_core.messages import HumanMessage, SystemMessage

from agent.prompts import REPORTER_SYSTEM, REPORTER_USER, REVOCATION_REPORTER_USER
from agent.state import AgentState
from llm.factory import make_llm

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


class RevocationReporterNode:
    """Callable revocation-summary reporter implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
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


def summary_reporter(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `SummaryReporterNode`."""
    return SummaryReporterNode().run(state)


def revocation_reporter(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `RevocationReporterNode`."""
    return RevocationReporterNode().run(state)
