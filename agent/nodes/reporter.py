"""
summary_reporter (LLM) node — generate a final human-readable renewal summary.
"""
from __future__ import annotations

import logging

from langchain_core.messages import HumanMessage, SystemMessage

from agent.prompts import REPORTER_SYSTEM, REPORTER_USER
from agent.state import AgentState
from config import settings
from llm.factory import make_llm

logger = logging.getLogger(__name__)


def summary_reporter(state: AgentState) -> dict:
    """
    LLM node: generate a final renewal run summary.
    Returns: messages update only (summary is printed/logged).
    """
    completed = state.get("completed_renewals", [])
    failed = state.get("failed_renewals", [])
    pending_renewals = state.get("pending_renewals", [])
    managed = state.get("managed_domains", [])
    error_log = state.get("error_log", [])

    # Domains that were healthy (not in completed or failed and not pending)
    renewed_and_failed = set(completed) | set(failed)
    skipped = [d for d in managed if d not in renewed_and_failed]

    error_summary = "\n".join(f"  - {e}" for e in error_log) if error_log else "  (none)"

    llm = make_llm(model=settings.LLM_MODEL_REPORTER, max_tokens=512)

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
