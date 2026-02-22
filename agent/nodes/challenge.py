"""
challenge_setup and challenge_verifier nodes.

challenge_setup  — serves the HTTP-01 token(s) either via a standalone server,
                   by writing to the webroot, or by creating DNS TXT records.
challenge_verifier — tells the ACME CA to check, then polls until valid/invalid.

Both are in one file because they share the standalone server / DNS provider lifecycle.
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Generator

from acme import jws as jwslib
from acme.client import AcmeError, make_client
from acme.dns_challenge import make_dns_provider
from acme.http_challenge import (
    StandaloneHttpChallenge,
    remove_webroot_challenge,
    write_webroot_challenge,
)
from agent.state import AgentState
from config import settings

if TYPE_CHECKING:
    from acme.dns_challenge import DnsProvider

logger = logging.getLogger(__name__)

# Module-level standalone server instance — kept alive between setup and verify
_standalone_server: StandaloneHttpChallenge | None = None

# Module-level DNS provider instance — kept alive between setup and cleanup
_dns_provider: DnsProvider | None = None


# ─── challenge_setup ──────────────────────────────────────────────────────────


def challenge_setup(state: AgentState) -> dict:
    """
    Serve all challenge tokens for the current order.

    For standalone mode: starts an HTTP server if not already running.
    For webroot mode: writes token files to WEBROOT_PATH.
    For dns mode: creates TXT records via the configured DNS provider and
                  waits DNS_PROPAGATION_WAIT_SECONDS for propagation.

    Note: For multi-domain SANs, standalone mode serves the first token at
    setup (ACME CAs validate one at a time sequentially); webroot and dns
    modes set up all challenges up front.
    """
    global _standalone_server, _dns_provider

    order = state.get("current_order")
    if not order:
        return {"error_log": state.get("error_log", []) + ["challenge_setup: no current_order in state"]}

    mode = settings.HTTP_CHALLENGE_MODE
    challenge_tokens = order["challenge_tokens"]
    key_authorizations = order["key_authorizations"]

    if mode == "webroot":
        webroot = settings.WEBROOT_PATH
        for token, key_auth in zip(challenge_tokens, key_authorizations):
            write_webroot_challenge(webroot, token, key_auth)
            logger.info("Wrote webroot challenge token %s", token)

    elif mode == "dns":
        _dns_provider = make_dns_provider()
        auth_domains = order.get("auth_domains", [])
        dns_txt_values = order.get("dns_txt_values", [])
        for domain, txt_value in zip(auth_domains, dns_txt_values):
            _dns_provider.create_txt_record(domain, txt_value)
            logger.info("Created TXT _acme-challenge.%s", domain)

        wait = settings.DNS_PROPAGATION_WAIT_SECONDS
        if wait > 0:
            logger.info("Waiting %d seconds for DNS propagation...", wait)
            time.sleep(wait)

    else:
        # Standalone: serve the first token (we restart between domains anyway)
        if _standalone_server is not None:
            _standalone_server.stop()

        _standalone_server = StandaloneHttpChallenge(port=settings.HTTP_CHALLENGE_PORT)
        # We serve each token one at a time; challenge_verifier will cycle through
        _standalone_server.start(challenge_tokens[0], key_authorizations[0])
        logger.info(
            "Standalone HTTP server started on port %d serving token %s",
            settings.HTTP_CHALLENGE_PORT,
            challenge_tokens[0],
        )

    return {}  # No state changes — challenge infrastructure is live


# ─── challenge_verifier ───────────────────────────────────────────────────────


def challenge_verifier(state: AgentState) -> dict:
    """
    For each authorization:
      1. Tell the ACME CA to verify (POST challenge URL)
      2. In standalone mode, if >1 auth, swap the served token
      3. Poll until valid or invalid

    Returns updates to: current_order (status), current_nonce, error_log.
    """
    global _standalone_server

    order = state.get("current_order")
    if not order:
        return {"error_log": state.get("error_log", []) + ["challenge_verifier: no current_order in state"]}

    account_key = jwslib.load_account_key(state["account_key_path"])
    account_url = state["acme_account_url"]
    nonce = state.get("current_nonce", "")

    client = make_client()
    directory = client.get_directory()
    if not nonce:
        nonce = client.get_nonce(directory)

    auth_urls = order["auth_urls"]
    challenge_urls = order["challenge_urls"]
    challenge_tokens = order["challenge_tokens"]
    key_authorizations = order["key_authorizations"]

    for i, (auth_url, ch_url, token, key_auth) in enumerate(
        zip(auth_urls, challenge_urls, challenge_tokens, key_authorizations)
    ):
        # In standalone mode, swap to this iteration's token
        if settings.HTTP_CHALLENGE_MODE == "standalone" and _standalone_server and i > 0:
            _standalone_server.stop()
            _standalone_server = StandaloneHttpChallenge(port=settings.HTTP_CHALLENGE_PORT)
            _standalone_server.start(token, key_auth)
            logger.info("Switched standalone server to token %s", token)

        # Check if authorization is already valid (servers may reuse previous
        # authorizations for the same domain — RFC 8555 §7.5 allows this).
        # In that case, responding to the challenge would fail with a 'malformed'
        # error ("cannot update challenge with status valid").
        authz_status = client.get_authorization(auth_url, account_key, account_url)
        if authz_status.get("status") == "valid":
            logger.info("Authorization %s already valid — skipping challenge respond", auth_url)
            continue

        logger.info("Triggering CA verification for auth %s", auth_url)
        _, nonce = client.respond_to_challenge(ch_url, account_key, account_url, nonce)

        try:
            client.poll_authorization(auth_url, account_key, account_url)
            logger.info("Authorization %s is VALID", auth_url)
        except AcmeError as exc:
            error_msg = f"Challenge failed for {state['current_domain']} ({auth_url}): {exc}"
            logger.error(error_msg)
            _cleanup_challenge(state)
            return {
                "current_order": {**order, "status": "invalid"},
                "current_nonce": nonce,
                "error_log": state.get("error_log", []) + [error_msg],
            }

    # All authorizations valid — clean up
    _cleanup_challenge(state)

    updated_order = {**order, "status": "ready"}
    return {
        "current_order": updated_order,
        "current_nonce": nonce,
    }


def _cleanup_challenge(state: AgentState) -> None:
    """Stop standalone server, remove webroot files, or delete DNS TXT records."""
    global _standalone_server, _dns_provider
    order = state.get("current_order")

    if settings.HTTP_CHALLENGE_MODE == "standalone" and _standalone_server:
        _standalone_server.stop()
        _standalone_server = None
    elif settings.HTTP_CHALLENGE_MODE == "webroot" and order:
        for token in order.get("challenge_tokens", []):
            remove_webroot_challenge(settings.WEBROOT_PATH, token)
    elif settings.HTTP_CHALLENGE_MODE == "dns" and _dns_provider is not None:
        auth_domains = order.get("auth_domains", []) if order else []
        dns_txt_values = order.get("dns_txt_values", []) if order else []
        for domain, txt_value in zip(auth_domains, dns_txt_values):
            try:
                _dns_provider.delete_txt_record(domain, txt_value)
            except Exception as exc:
                logger.warning("Failed to delete TXT record for %s: %s", domain, exc)
        _dns_provider = None
