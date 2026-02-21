"""
retry_scheduler node — apply scheduled backoff before retrying.

This node checks if enough time has passed since error_handler scheduled a retry.
If the scheduled time hasn't arrived yet, it waits (synchronously for now).

Flow:
  error_handler (LLM decides: retry/skip/abort)
    → retry_scheduler (applies backoff) [NEW]
      → pick_next_domain (loop for retry)

Design rationale:
  - Separates concerns: error decision (error_handler) vs. timing (retry_scheduler)
  - Visible in graph traces (not hidden in error_handler)
  - Testable in isolation
  - Future: can be converted to async (await asyncio.sleep)

See: ASYNC_SCHEDULER_IMPLEMENTATION_PLAN.md
"""
from __future__ import annotations

import logging
import time as time_module

from agent.state import AgentState

logger = logging.getLogger(__name__)


def retry_scheduler(state: AgentState) -> dict:
    """
    Check if retry_not_before time has arrived. If not, wait.

    This is the synchronous version. For async execution, use retry_scheduler_async().

    Args:
        state: AgentState with retry_not_before (Unix timestamp or None)

    Returns:
        dict: Clears retry_not_before after applying backoff.
    """
    retry_not_before = state.get("retry_not_before")

    if retry_not_before is None:
        # No scheduled retry (should not reach this node if routing is correct)
        logger.debug("No scheduled retry. Passing through.")
        return {}

    now = time_module.time()
    wait_time = retry_not_before - now

    if wait_time > 0:
        logger.info(
            "Retry backoff: waiting %.1f seconds (retry_not_before=%d, now=%d)",
            wait_time,
            int(retry_not_before),
            int(now),
        )
        time_module.sleep(wait_time)

    logger.debug("Retry backoff complete. Proceeding with retry.")

    # Clear the scheduled retry time
    return {
        "retry_not_before": None,
    }


async def retry_scheduler_async(state: AgentState) -> dict:
    """
    Async version: non-blocking backoff using asyncio.sleep().

    Use this when the graph is converted to async execution.
    This allows other work to proceed during the backoff period.

    Args:
        state: AgentState with retry_not_before (Unix timestamp or None)

    Returns:
        dict: Clears retry_not_before after awaiting backoff.
    """
    import asyncio

    retry_not_before = state.get("retry_not_before")

    if retry_not_before is None:
        return {}

    now = time_module.time()
    wait_time = retry_not_before - now

    if wait_time > 0:
        logger.info(
            "Async retry backoff: waiting %.1f seconds (non-blocking)",
            wait_time,
        )
        await asyncio.sleep(wait_time)
        logger.debug("Async retry backoff complete.")

    return {
        "retry_not_before": None,
    }
