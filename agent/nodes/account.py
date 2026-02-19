"""
acme_account_setup node — register or retrieve a DigiCert ACME account.

Security note: the account key is never stored in AgentState (which could
leak into LangSmith traces).  Instead the key path is stored in state and
the key is loaded from disk each time it is needed.
"""
from __future__ import annotations

import logging

from acme import jws as jwslib
from acme.client import make_client
from agent.state import AgentState
from config import settings

logger = logging.getLogger(__name__)


def acme_account_setup(state: AgentState) -> dict:
    """
    Ensures a DigiCert ACME account exists and state["acme_account_url"] is set.

    If an account key already exists at account_key_path:
      - Attempts to look up the existing account (POST /newAccount onlyReturnExisting)
    If no key exists:
      - Generates a new key, saves it, and registers a new account (with EAB)

    Returns updates to: acme_account_url, current_nonce
    """
    account_key_path = state["account_key_path"]

    client = make_client()

    directory = client.get_directory()
    nonce = client.get_nonce(directory)

    if jwslib.account_key_exists(account_key_path):
        logger.info("Loading existing account key from %s", account_key_path)
        account_key = jwslib.load_account_key(account_key_path)

        account_url, new_nonce = client.lookup_account(account_key, nonce, directory)
        if account_url:
            logger.info("Retrieved existing ACME account: %s", account_url)
            return {
                "acme_account_url": account_url,
                "current_nonce": new_nonce or nonce,
            }
        logger.warning("Account key exists but account not found — re-registering")
    else:
        logger.info("No account key found — generating new key at %s", account_key_path)
        account_key = jwslib.generate_account_key()
        jwslib.save_account_key(account_key, account_key_path)

    # Register new account (EAB included only when credentials are configured)
    account_url, new_nonce = client.create_account(
        account_key=account_key,
        eab_key_id=settings.DIGICERT_EAB_KEY_ID,
        eab_hmac_key=settings.DIGICERT_EAB_HMAC_KEY,
        nonce=nonce,
        directory=directory,
    )
    logger.info("Registered new ACME account: %s", account_url)

    return {
        "acme_account_url": account_url,
        "current_nonce": new_nonce,
    }
