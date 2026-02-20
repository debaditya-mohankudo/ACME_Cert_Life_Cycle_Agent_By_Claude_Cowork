"""
renewal_planner (LLM) node — analyzes scan results, writes a renewal plan,
and populates pending_renewals in priority order.

Output validation: ensures every domain in LLM JSON output is in managed_domains.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agent.prompts import PLANNER_SYSTEM, PLANNER_USER
from agent.state import AgentState
from config import settings
from llm.factory import make_llm

logger = logging.getLogger(__name__)


def renewal_planner(state: AgentState) -> dict:
    """
    LLM node: produce a JSON renewal plan from cert_records.
    Returns: renewal_plan (str), pending_renewals (list[str]), messages update.
    """
    cert_records = state["cert_records"]
    managed_domains = set(state["managed_domains"])
    threshold = state["renewal_threshold_days"]

    # Build a human-readable summary for the LLM
    lines = []
    for rec in cert_records:
        if rec["days_until_expiry"] is None:
            lines.append(f"  {rec['domain']} → no certificate found (needs renewal)")
        else:
            lines.append(
                f"  {rec['domain']} → expires {rec['expiry_date'][:10]} "
                f"({rec['days_until_expiry']} days)"
            )
    cert_summary = "\n".join(lines)

    llm = make_llm(model=settings.LLM_MODEL_PLANNER, max_tokens=512)

    messages = [
        SystemMessage(content=PLANNER_SYSTEM),
        HumanMessage(
            content=PLANNER_USER.format(
                cert_summary=cert_summary,
                managed_domains=", ".join(sorted(managed_domains)),
                threshold=threshold,
            )
        ),
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()
    logger.debug("Planner LLM raw response: %s", raw)

    plan = _parse_and_validate(raw, managed_domains)

    # Build ordered pending_renewals: urgent first, then routine
    pending: list[str] = plan.get("urgent", []) + plan.get("routine", [])

    return {
        "renewal_plan": raw,
        "pending_renewals": pending,
        "messages": messages + [response],
    }


def _parse_and_validate(raw: str, managed_domains: set[str]) -> dict[str, Any]:
    """
    Parse LLM JSON output and validate that all domains are from managed_domains.
    Falls back to a safe default on any parse failure.
    """
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Planner returned invalid JSON — falling back to renew all")
        return {"urgent": [], "routine": list(managed_domains), "skip": [], "notes": "JSON parse failed"}

    # Validate: strip any hallucinated domains not in the managed list
    for key in ("urgent", "routine", "skip"):
        original = plan.get(key, [])
        validated = [d for d in original if d in managed_domains]
        if len(validated) != len(original):
            removed = set(original) - set(validated)
            logger.warning(
                "Planner hallucinated domains — removing: %s", removed
            )
        plan[key] = validated

    # Ensure every managed domain appears in exactly one bucket
    accounted = set(plan.get("urgent", [])) | set(plan.get("routine", [])) | set(plan.get("skip", []))
    missing = managed_domains - accounted
    if missing:
        logger.warning("Planner did not classify domains %s — adding to routine", missing)
        plan.setdefault("routine", []).extend(sorted(missing))

    return plan
