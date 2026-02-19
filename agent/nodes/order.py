"""
order_initializer node — POST /newOrder for the current domain, then fetch
all authorizations to collect HTTP-01 challenge tokens.
"""
from __future__ import annotations

import logging

from acme import jws as jwslib
from acme.client import make_client
from agent.state import AgentState, AcmeOrder
from config import settings

logger = logging.getLogger(__name__)


def order_initializer(state: AgentState) -> dict:
    """
    Creates an ACME order for state["current_domain"] and populates
    state["current_order"] with authorization and challenge details.

    Returns updates to: current_order, current_nonce, error_log (on failure).
    """
    domain = state["current_domain"]
    account_url = state["acme_account_url"]
    account_key_path = state["account_key_path"]
    nonce = state["current_nonce"]

    logger.info("Creating ACME order for %s", domain)

    account_key = jwslib.load_account_key(account_key_path)
    client = make_client()
    directory = client.get_directory()

    if not nonce:
        nonce = client.get_nonce(directory)

    order_body, order_url, nonce = client.create_order(
        domains=[domain],
        account_key=account_key,
        account_url=account_url,
        nonce=nonce,
        directory=directory,
    )

    auth_urls: list[str] = order_body.get("authorizations", [])
    challenge_urls: list[str] = []
    challenge_tokens: list[str] = []
    key_authorizations: list[str] = []
    thumbprint = jwslib.compute_jwk_thumbprint(account_key)

    for auth_url in auth_urls:
        authz = client.get_authorization(auth_url, account_key, account_url)
        # Find the HTTP-01 challenge within this authorization
        http01 = next(
            (c for c in authz.get("challenges", []) if c.get("type") == "http-01"),
            None,
        )
        if http01 is None:
            error = f"No HTTP-01 challenge found in authorization {auth_url}"
            logger.error(error)
            return {
                "error_log": state.get("error_log", []) + [error],
                "current_nonce": nonce,
            }

        token = http01["token"]
        key_auth = f"{token}.{thumbprint}"
        challenge_urls.append(http01["url"])
        challenge_tokens.append(token)
        key_authorizations.append(key_auth)

    current_order: AcmeOrder = {
        "order_url": order_url,
        "status": order_body.get("status", "pending"),
        "auth_urls": auth_urls,
        "challenge_urls": challenge_urls,
        "challenge_tokens": challenge_tokens,
        "key_authorizations": key_authorizations,
        "finalize_url": order_body.get("finalize", ""),
        "certificate_url": None,
    }

    logger.info(
        "Order created for %s — %d authorization(s)", domain, len(auth_urls)
    )
    return {
        "current_order": current_order,
        "current_nonce": nonce,
    }
