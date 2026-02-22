"""
cert_revoker node — revoke a certificate via ACME POST /revokeCert.

Security note: the account key is loaded from disk, never stored in AgentState
or returned in the result dict.
"""
from __future__ import annotations

import logging

from acme import jws as jwslib
from acme.client import AcmeError, make_client
from agent.state import AgentState
from storage import filesystem as fs

logger = logging.getLogger(__name__)


def cert_revoker(state: AgentState) -> dict:
    """
    Revoke the certificate for state["current_revocation_domain"].

    If the cert is not found at cert_store_path/<domain>/cert.pem, logs a
    failure and returns without raising.

    Returns:
      - On success: revoked_domains + new current_nonce, current_revocation_domain = None
      - On ACME error: failed_revocations + error_log entry + new_nonce
      - On missing cert: failed_revocations + error_log entry
    """
    domain = state["current_revocation_domain"]
    if not domain:
        logger.warning("cert_revoker called with no current_revocation_domain")
        return {}

    cert_pem = fs.read_cert_pem(state["cert_store_path"], domain)
    if cert_pem is None:
        logger.error("Certificate file not found for domain %s", domain)
        error_msg = f"Revocation failed for {domain}: certificate file not found"
        return {
            "failed_revocations": state.get("failed_revocations", []) + [domain],
            "error_log": state.get("error_log", []) + [error_msg],
            "current_revocation_domain": None,
        }

    account_key_path = state["account_key_path"]
    account_key = jwslib.load_account_key(account_key_path)

    client = make_client()
    directory = client.get_directory()

    # Get a fresh nonce if we don't have one
    nonce = state.get("current_nonce") or client.get_nonce(directory)

    try:
        new_nonce = client.revoke_certificate(
            cert_pem=cert_pem,
            account_key=account_key,
            account_url=state["acme_account_url"],
            nonce=nonce,
            directory=directory,
            reason=state.get("revocation_reason", 0),
        )
        logger.info("Revoked certificate for domain: %s", domain)
        return {
            "revoked_domains": state.get("revoked_domains", []) + [domain],
            "current_nonce": new_nonce,
            "current_revocation_domain": None,
        }

    except AcmeError as exc:
        logger.error("Revocation failed for %s: %s", domain, exc)
        error_msg = f"Revocation failed for {domain}: {exc}"
        return {
            "failed_revocations": state.get("failed_revocations", []) + [domain],
            "current_nonce": exc.new_nonce or nonce,
            "error_log": state.get("error_log", []) + [error_msg],
            "current_revocation_domain": None,
        }
