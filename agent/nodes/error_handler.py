"""
error_handler (LLM) node — analyze a renewal failure and decide: retry, skip, or abort.
"""
from __future__ import annotations

import json
import logging
import time

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from agent.prompts import ERROR_HANDLER_SYSTEM, ERROR_HANDLER_USER
from agent.state import AgentState
from config import settings

logger = logging.getLogger(__name__)


def error_handler(state: AgentState) -> dict:
    """
    LLM node: reason about the last error and decide next action.

    Returns updates to: error_analysis, retry_count, retry_delay_seconds, messages,
                        failed_renewals (if skipping).
    """
    domain = state.get("current_domain", "unknown")
    order = state.get("current_order") or {}
    error_log = state.get("error_log", [])
    last_error = error_log[-1] if error_log else "Unknown error"
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    retry_delay = state.get("retry_delay_seconds", 5)

    llm = ChatAnthropic(
        model=settings.LLM_MODEL_ERROR_HANDLER,
        anthropic_api_key=settings.ANTHROPIC_API_KEY,
        max_tokens=256,
    )

    messages = [
        SystemMessage(content=ERROR_HANDLER_SYSTEM),
        HumanMessage(
            content=ERROR_HANDLER_USER.format(
                domain=domain,
                error=last_error,
                retry_count=retry_count,
                max_retries=max_retries,
                order_status=order.get("status", "unknown"),
            )
        ),
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()
    logger.debug("Error handler LLM response for %s: %s", domain, raw)

    # Parse the decision
    try:
        decision = json.loads(raw)
        action = decision.get("action", "skip")
        suggested_delay = int(decision.get("suggested_delay_seconds", retry_delay * 2))
    except Exception:
        action = "skip"
        suggested_delay = retry_delay * 2

    updates: dict = {
        "error_analysis": raw,
        "messages": messages + [response],
    }

    if action == "retry":
        new_retry_count = retry_count + 1
        new_delay = suggested_delay if suggested_delay > 0 else min(retry_delay * 2, 300)
        logger.info(
            "Error handler: RETRY #%d for %s (waiting %ds)",
            new_retry_count,
            domain,
            new_delay,
        )
        time.sleep(new_delay)
        updates["retry_count"] = new_retry_count
        updates["retry_delay_seconds"] = new_delay
    elif action == "abort":
        logger.error("Error handler: ABORT — stopping all renewals")
        # Mark all remaining pending as failed
        pending = state.get("pending_renewals", [])
        failed = state.get("failed_renewals", []) + [domain] + list(pending)
        updates["failed_renewals"] = failed
        updates["pending_renewals"] = []
    else:
        logger.warning("Error handler: SKIP domain %s", domain)
        updates["failed_renewals"] = state.get("failed_renewals", []) + [domain]

    return updates
