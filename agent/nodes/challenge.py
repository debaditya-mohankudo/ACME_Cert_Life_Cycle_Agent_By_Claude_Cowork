"""
challenge_setup and challenge_verifier nodes.

challenge_setup  — serves the HTTP-01 token(s) either via a standalone server
                   or by writing to the webroot.
challenge_verifier — tells the ACME CA to check, then polls until valid/invalid.

Both are in one file because they share the standalone server lifecycle.
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Generator

from acme import jws as jwslib
from acme.client import AcmeError, make_client
from acme.http_challenge import (
    StandaloneHttpChallenge,
    remove_webroot_challenge,
    write_webroot_challenge,
)
from agent.state import AgentState
from config import settings

logger = logging.getLogger(__name__)

# Module-level standalone server instance — kept alive between setup and verify
_standalone_server: StandaloneHttpChallenge | None = None


# ─── challenge_setup ──────────────────────────────────────────────────────────


def challenge_setup(state: AgentState) -> dict:
    """
    Serve all HTTP-01 challenge tokens for the current order.

    For standalone mode: starts a server if not already running.
    For webroot mode: writes token files to WEBROOT_PATH.

    Note: This node only sets up the first challenge token.  For multi-domain
    SANs, the standalone server serves the first token (ACME CAs validate
    one at a time sequentially); webroot mode writes all files up front.
    """
    global _standalone_server

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

    return {}  # No state changes — server is live


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
    """Stop standalone server or remove webroot files after verification."""
    global _standalone_server
    order = state.get("current_order")

    if settings.HTTP_CHALLENGE_MODE == "standalone" and _standalone_server:
        _standalone_server.stop()
        _standalone_server = None
    elif settings.HTTP_CHALLENGE_MODE == "webroot" and order:
        for token in order.get("challenge_tokens", []):
            remove_webroot_challenge(settings.WEBROOT_PATH, token)
