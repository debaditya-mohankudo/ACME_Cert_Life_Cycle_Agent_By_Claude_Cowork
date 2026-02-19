"""
certificate_scanner node — reads all managed domain cert files and populates
cert_records + identifies which domains need renewal.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from agent.state import AgentState, CertRecord
from storage import filesystem as fs

logger = logging.getLogger(__name__)


def certificate_scanner(state: AgentState) -> dict:
    """
    For each domain in managed_domains:
      - Check if cert.pem exists in cert_store_path
      - Parse expiry date
      - Compute days_until_expiry
      - Set needs_renewal flag
    Populates state["cert_records"].
    """
    cert_store_path = state["cert_store_path"]
    managed_domains = state["managed_domains"]
    threshold = state["renewal_threshold_days"]

    records: list[CertRecord] = []

    for domain in managed_domains:
        pem = fs.read_cert_pem(cert_store_path, domain)
        domain_dir = fs.cert_dir(cert_store_path, domain)

        if pem is None:
            logger.info("  %s → no certificate found — will renew", domain)
            record: CertRecord = {
                "domain": domain,
                "cert_path": None,
                "key_path": None,
                "expiry_date": None,
                "days_until_expiry": None,
                "needs_renewal": True,
            }
        else:
            try:
                expiry = fs.parse_expiry(pem)
                days = fs.days_until_expiry(expiry)
                needs_renewal = days < threshold
                status = "URGENT" if days < 7 else ("ROUTINE" if needs_renewal else "OK")
                logger.info(
                    "  %s → expires %s (%d days) — %s",
                    domain,
                    expiry.strftime("%Y-%m-%d"),
                    days,
                    status,
                )
                record = {
                    "domain": domain,
                    "cert_path": str(domain_dir / "cert.pem"),
                    "key_path": str(domain_dir / "privkey.pem"),
                    "expiry_date": expiry.isoformat(),
                    "days_until_expiry": days,
                    "needs_renewal": needs_renewal,
                }
            except Exception as exc:
                logger.warning("  %s → failed to parse cert: %s", domain, exc)
                record = {
                    "domain": domain,
                    "cert_path": str(domain_dir / "cert.pem"),
                    "key_path": None,
                    "expiry_date": None,
                    "days_until_expiry": None,
                    "needs_renewal": True,
                }

        records.append(record)

    return {"cert_records": records}
