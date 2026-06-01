"""GET /domains/{domain}/cert — rich certificate inspection (read-only)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/domains", tags=["certs"])


@router.get("/{domain}/cert")
def read_cert_details(domain: str) -> dict[str, Any]:
    """Return rich certificate details for a domain: SANs, issuer, serial, validity dates."""
    import config
    from storage.filesystem import read_cert_pem

    cert_store_path = config.settings.CERT_STORE_PATH
    pem = read_cert_pem(cert_store_path, domain)
    if pem is None:
        raise HTTPException(status_code=404, detail=f"No certificate found for {domain!r}")

    try:
        from mcp_server import _extract_cert_details
        return _extract_cert_details(pem, domain, cert_store_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse certificate: {exc}")
