"""
Domain lifecycle endpoints.

All state-mutating endpoints (renew, revoke) are synchronous and blocking.
This is an explicit architectural decision — see server/main.py for rationale.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/domains", tags=["domains"])


# ── Request models ─────────────────────────────────────────────────────────

class RenewRequest(BaseModel):
    checkpoint: bool = False


class RevokeRequest(BaseModel):
    reason: int = 0
    checkpoint: bool = False


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.get("")
def list_managed_domains() -> dict[str, Any]:
    """Return the list of domains currently configured in MANAGED_DOMAINS."""
    import config
    domains = list(config.settings.MANAGED_DOMAINS)
    return {"managed_domains": domains, "count": len(domains)}


@router.get("/expiring")
def expiring_within(days: int = Query(default=30, ge=1, le=3650)) -> dict[str, Any]:
    """List domains whose current cert expires within N days (read-only)."""
    from main import list_domains_expiring_within
    expiring = list_domains_expiring_within(days=days)
    return {"window_days": days, "expiring_domains": expiring}


@router.get("/{domain}/status")
def domain_status(domain: str) -> dict[str, Any]:
    """Get certificate status for a single domain (read-only)."""
    from main import get_domain_statuses
    results = get_domain_statuses([domain])
    if not results:
        raise HTTPException(status_code=404, detail=f"Domain {domain!r} not found")
    return results[0]


@router.post("/{domain}/renew")
def renew_domain(domain: str, body: RenewRequest = RenewRequest()) -> dict[str, Any]:
    """
    Run one renewal cycle for a single domain.

    Blocks until the LangGraph run completes — synchronous by design.
    The domain is used as the log correlation key; query GET /logs?domain=<domain>
    for the full log trail of this run.
    """
    from logger import set_domain
    from main import run_once
    from server.session import session

    set_domain(domain)

    try:
        final_state = run_once(
            domains=[domain],
            use_checkpoint=body.checkpoint,
        )
    except SystemExit as exc:
        raise HTTPException(status_code=500, detail=f"Agent exited with code {exc.code}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    session.absorb_state(final_state)

    return {
        "domain": domain,
        "status": "success",
        "completed_renewals": final_state.get("completed_renewals", []),
        "failed_renewals": final_state.get("failed_renewals", []),
        "error_log": final_state.get("error_log", []),
    }


@router.delete("/{domain}/cert")
def revoke_domain_cert(domain: str, body: RevokeRequest = RevokeRequest()) -> dict[str, Any]:
    """
    Revoke the certificate for a single domain.

    Blocks until the revocation graph run completes — synchronous by design.
    """
    from logger import set_domain
    from main import run_revocation
    from server.session import session

    if body.reason not in {0, 1, 4, 5}:
        raise HTTPException(status_code=422, detail="reason must be one of: 0, 1, 4, 5")

    set_domain(domain)

    try:
        final_state = run_revocation(
            domains=[domain],
            reason=body.reason,
            use_checkpoint=body.checkpoint,
        )
    except SystemExit as exc:
        raise HTTPException(status_code=500, detail=f"Agent exited with code {exc.code}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    session.absorb_state(final_state)

    return {
        "domain": domain,
        "status": "success",
        "revoked_domains": final_state.get("revoked_domains", []),
        "failed_revocations": final_state.get("failed_revocations", []),
        "error_log": final_state.get("error_log", []),
    }
