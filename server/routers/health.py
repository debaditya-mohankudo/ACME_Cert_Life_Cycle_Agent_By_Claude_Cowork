"""GET /health — configuration and readiness check (no side effects, no domain context needed)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, Any]:
    """Return non-secret configuration and readiness checks."""
    import config

    s = config.settings
    missing_llm_key = (
        (s.LLM_PROVIDER == "anthropic" and not s.ANTHROPIC_API_KEY)
        or (s.LLM_PROVIDER == "openai" and not s.OPENAI_API_KEY)
    )
    warnings: list[str] = []
    if not s.MANAGED_DOMAINS:
        warnings.append("MANAGED_DOMAINS is empty")
    if missing_llm_key:
        warnings.append(f"{s.LLM_PROVIDER.upper()} API key is not set")
    if s.HTTP_CHALLENGE_MODE == "standalone" and s.HTTP_CHALLENGE_PORT != 80:
        warnings.append("HTTP_CHALLENGE_PORT is not 80; ensure public HTTP-01 reachability")
    if s.ACME_INSECURE:
        warnings.append("ACME_INSECURE=true (testing only)")

    return {
        "ok": len(warnings) == 0,
        "provider": s.CA_PROVIDER,
        "acme_directory": s.ACME_DIRECTORY_URL,
        "llm_provider": s.LLM_PROVIDER,
        "challenge_mode": s.HTTP_CHALLENGE_MODE,
        "managed_domain_count": len(s.MANAGED_DOMAINS),
        "warnings": warnings,
    }
