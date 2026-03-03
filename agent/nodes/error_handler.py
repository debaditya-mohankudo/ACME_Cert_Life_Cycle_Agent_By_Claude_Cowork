"""
error_handler (LLM) node — analyze a renewal failure and decide: retry, skip, or abort.
"""
from __future__ import annotations

import config
import json
import time

from langchain_core.messages import HumanMessage, SystemMessage

from agent.prompts import ERROR_HANDLER_SYSTEM, ERROR_HANDLER_USER
from agent.state import AgentState
from llm.factory import make_llm

from logger import logger


class ErrorHandlerNode:
    """Callable error-handler implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Error handler: analyze failure and decide next action.
        Uses LLM if LLM_DISABLED=False, otherwise deterministic logic.
        """
        if config.settings.LLM_DISABLED:
            return self._run_deterministic(state)
        else:
            return self._run_llm(state)

    def _run_llm(self, state: AgentState) -> dict:
        """LLM-based error handler (original implementation)."""
        domain = state.get("current_domain", "unknown")
        order = state.get("current_order") or {}
        error_log = state.get("error_log", [])
        last_error = error_log[-1] if error_log else "Unknown error"
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)
        retry_delay = state.get("retry_delay_seconds", 5)

        llm = make_llm(model=config.settings.LLM_MODEL_ERROR_HANDLER, max_tokens=256)

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
            now = time.time()
            retry_not_before = now + new_delay

            logger.info(
                "Error handler: RETRY #%d for %s (backoff %ds, will retry at %d)",
                new_retry_count,
                domain,
                new_delay,
                int(retry_not_before),
            )

            updates["retry_count"] = new_retry_count
            updates["retry_delay_seconds"] = new_delay
            updates["retry_not_before"] = retry_not_before
        elif action == "abort":
            logger.error("Error handler: ABORT — stopping all renewals")
            pending = state.get("pending_renewals", [])
            failed = state.get("failed_renewals", []) + [domain] + list(pending)
            updates["failed_renewals"] = failed
            updates["pending_renewals"] = []
        else:
            logger.warning("Error handler: SKIP domain %s", domain)
            updates["failed_renewals"] = state.get("failed_renewals", []) + [domain]

        return updates

    def _run_deterministic(self, state: AgentState) -> dict:
        """
        Deterministic error handler when LLM is disabled.
        Retry up to MAX_RETRIES with exponential backoff, then skip.
        """
        domain = state.get("current_domain", "unknown")
        error_log = state.get("error_log", [])
        last_error = error_log[-1] if error_log else "Unknown error"
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)
        retry_delay = state.get("retry_delay_seconds", 5)
        
        action, new_delay = _error_handler_deterministic(retry_count, max_retries, retry_delay)
        
        analysis = (
            f"Deterministic error handler (LLM disabled):\n"
            f"Domain: {domain}\n"
            f"Error: {last_error}\n"
            f"Retry count: {retry_count}/{max_retries}\n"
            f"Action: {action.upper()}"
        )
        
        if action == "retry":
            analysis += f"\nBackoff delay: {new_delay}s"
        
        logger.info("Deterministic error handler: %s for %s", action.upper(), domain)
        
        updates: dict = {
            "error_analysis": analysis,
            "messages": [],  # No LLM messages in deterministic mode
        }

        if action == "retry":
            new_retry_count = retry_count + 1
            now = time.time()
            retry_not_before = now + new_delay

            logger.info(
                "Deterministic error handler: RETRY #%d for %s (backoff %ds, will retry at %d)",
                new_retry_count,
                domain,
                new_delay,
                int(retry_not_before),
            )

            updates["retry_count"] = new_retry_count
            updates["retry_delay_seconds"] = new_delay
            updates["retry_not_before"] = retry_not_before
        else:  # skip (no abort in deterministic mode)
            logger.warning("Deterministic error handler: SKIP domain %s (max retries reached)", domain)
            updates["failed_renewals"] = state.get("failed_renewals", []) + [domain]

        return updates


def _error_handler_deterministic(retry_count, max_retries, retry_delay_seconds):
    """
    Deterministic error handler when LLM is disabled.
    
    Args:
        retry_count: Current retry attempt count
        max_retries: Maximum allowed retries
        retry_delay_seconds: Base delay for exponential backoff
    
    Returns:
        action: "retry" or "skip"
        new_delay_seconds: delay for next retry (if retrying)
    """
    if retry_count < max_retries:
        # Exponential backoff: delay * 2^(retry_count + 1), capped at 300s
        exponent = retry_count + 1
        new_delay = min(retry_delay_seconds * (2 ** exponent), 300)
        return "retry", int(new_delay)
    else:
        return "skip", 0


def error_handler(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `ErrorHandlerNode`."""
    return ErrorHandlerNode().run(state)
