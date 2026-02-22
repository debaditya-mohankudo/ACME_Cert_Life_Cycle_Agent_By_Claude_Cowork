"""
order_initializer node — POST /newOrder for the current domain, then fetch
all authorizations to collect challenge tokens (HTTP-01 or DNS-01).
"""
from __future__ import annotations

import logging

from acme import jws as jwslib
from acme.client import make_client
from acme.dns_challenge import compute_dns_txt_value
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
    auth_domains: list[str] = []
    dns_txt_values: list[str] = []
    thumbprint = jwslib.compute_jwk_thumbprint(account_key)

    challenge_type = "dns-01" if settings.HTTP_CHALLENGE_MODE == "dns" else "http-01"

    for auth_url in auth_urls:
        authz = client.get_authorization(auth_url, account_key, account_url)
        auth_domain = authz.get("identifier", {}).get("value", "")
        auth_domains.append(auth_domain)

        # Find the challenge matching the configured type
        challenge_obj = next(
            (c for c in authz.get("challenges", []) if c.get("type") == challenge_type),
            None,
        )
        if challenge_obj is None:
            error = f"No {challenge_type} challenge found in authorization {auth_url}"
            logger.error(error)
            return {
                "error_log": state.get("error_log", []) + [error],
                "current_nonce": nonce,
            }

        token = challenge_obj["token"]
        key_auth = f"{token}.{thumbprint}"
        challenge_urls.append(challenge_obj["url"])
        challenge_tokens.append(token)
        key_authorizations.append(key_auth)

        if settings.HTTP_CHALLENGE_MODE == "dns":
            dns_txt_values.append(compute_dns_txt_value(key_auth))

    current_order: AcmeOrder = {
        "order_url": order_url,
        "status": order_body.get("status", "pending"),
        "auth_urls": auth_urls,
        "challenge_urls": challenge_urls,
        "challenge_tokens": challenge_tokens,
        "key_authorizations": key_authorizations,
        "finalize_url": order_body.get("finalize", ""),
        "certificate_url": None,
        "auth_domains": auth_domains,
        "dns_txt_values": dns_txt_values,
    }

    logger.info(
        "Order created for %s — %d authorization(s)", domain, len(auth_urls)
    )
    return {
        "current_order": current_order,
        "current_nonce": nonce,
    }
