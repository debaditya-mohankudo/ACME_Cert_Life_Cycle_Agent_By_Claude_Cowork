"""
order_finalizer + cert_downloader nodes.

order_finalizer  — POST CSR to /finalize, poll until certificate URL is ready.
cert_downloader  — POST-as-GET the certificate URL, return full PEM chain.
"""
from __future__ import annotations

import logging

from acme import jws as jwslib
from acme.client import AcmeError, make_client
from agent.state import AgentState
from config import settings

logger = logging.getLogger(__name__)


def order_finalizer(state: AgentState) -> dict:
    """
    Submit the CSR to the ACME /finalize endpoint and wait for the CA to issue
    the certificate.

    Returns updates to: current_order (certificate_url set), current_nonce,
                        error_log on failure.
    """
    domain = state["current_domain"]
    order = state.get("current_order") or {}
    account_key = jwslib.load_account_key(state["account_key_path"])
    account_url = state["acme_account_url"]
    nonce = state.get("current_nonce", "")

    csr_hex = order.get("csr_der_hex", "")
    if not csr_hex:
        error = f"order_finalizer: no CSR found in state for {domain}"
        logger.error(error)
        return {"error_log": state.get("error_log", []) + [error]}

    csr_der = bytes.fromhex(csr_hex)
    finalize_url = order["finalize_url"]
    order_url = order["order_url"]

    client = make_client()
    directory = client.get_directory()
    if not nonce:
        nonce = client.get_nonce(directory)

    logger.info("Finalizing order for %s — submitting CSR", domain)
    try:
        _, nonce = client.finalize_order(finalize_url, csr_der, account_key, account_url, nonce)
        cert_url = client.poll_order_for_certificate(order_url, account_key, account_url)
    except AcmeError as exc:
        error = f"Finalization failed for {domain}: {exc}"
        logger.error(error)
        return {
            "current_order": {**order, "status": "invalid"},
            "current_nonce": nonce,
            "error_log": state.get("error_log", []) + [error],
        }

    logger.info("Certificate URL ready for %s: %s", domain, cert_url)
    updated_order = {**order, "status": "valid", "certificate_url": cert_url}
    return {
        "current_order": updated_order,
        "current_nonce": nonce,
    }


def cert_downloader(state: AgentState) -> dict:
    """
    POST-as-GET the certificate URL and store the raw PEM chain in the order.

    Returns updates to: current_order (full_chain_pem added), current_nonce.
    """
    domain = state["current_domain"]
    order = state.get("current_order") or {}
    cert_url = order.get("certificate_url", "")

    if not cert_url:
        error = f"cert_downloader: no certificate_url in state for {domain}"
        logger.error(error)
        return {"error_log": state.get("error_log", []) + [error]}

    account_key = jwslib.load_account_key(state["account_key_path"])
    account_url = state["acme_account_url"]
    nonce = state.get("current_nonce", "")

    client = make_client()
    directory = client.get_directory()
    if not nonce:
        nonce = client.get_nonce(directory)

    logger.info("Downloading certificate for %s", domain)
    try:
        full_chain_pem, nonce = client.download_certificate(cert_url, account_key, account_url, nonce)
    except AcmeError as exc:
        error = f"Certificate download failed for {domain}: {exc}"
        logger.error(error)
        return {
            "current_nonce": nonce,
            "error_log": state.get("error_log", []) + [error],
        }

    logger.info("Downloaded %d bytes of PEM for %s", len(full_chain_pem), domain)
    updated_order = {**order, "full_chain_pem": full_chain_pem}
    return {
        "current_order": updated_order,
        "current_nonce": nonce,
    }
