"""
Unit tests for failure scenarios in the ACME protocol layer.

These tests cover edge cases and error conditions: challenge failures, invalid CSRs,
nonce retry exhaustion, network timeouts, and invalid directory URLs.

Run with:  uv run pytest tests/test_unit_failure_scenarios.py -v
"""
from __future__ import annotations

import json

import pytest
import requests
import responses as resp_lib

from acme import jws as jwslib
from acme.crypto import create_csr, generate_rsa_key
from acme.client import AcmeError, AcmeClient


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def account_key():
    return jwslib.generate_account_key(key_size=2048)


@pytest.fixture(scope="module")
def domain_key():
    return generate_rsa_key(key_size=2048)


FAKE_DIRECTORY = {
    "newNonce": "https://acme.test/newNonce",
    "newAccount": "https://acme.test/newAccount",
    "newOrder": "https://acme.test/newOrder",
    "revokeCert": "https://acme.test/revokeCert",
    "keyChange": "https://acme.test/keyChange",
}

FAKE_NONCE = "testnonce12345"


# ─── Test 1: ACME Challenge Failure (invalid status) ──────────────────────────

@resp_lib.activate
def test_challenge_failure_invalid_status(account_key):
    """
    Respond to challenge succeeds, but poll_authorization returns status: invalid.
    Expects AcmeError with 'invalid' in the body.
    """
    # Mock HEAD newNonce
    resp_lib.add(
        resp_lib.HEAD,
        FAKE_DIRECTORY["newNonce"],
        headers={"Replay-Nonce": FAKE_NONCE},
    )

    # Mock POST to challenge URL (successful response)
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/challenge/1",
        json={"status": "pending"},
        status=200,
        headers={"Replay-Nonce": "nonce2"},
    )

    # Mock GET authorization URL — returns invalid
    resp_lib.add(
        resp_lib.GET,
        "https://acme.test/authz/1",
        json={"status": "invalid", "challenges": []},
    )

    client = AcmeClient("https://acme.test/dir")

    # respond_to_challenge succeeds
    challenge_body, new_nonce = client.respond_to_challenge(
        "https://acme.test/challenge/1",
        account_key,
        "https://acme.test/acct/1",
        FAKE_NONCE,
    )
    assert challenge_body["status"] == "pending"

    # poll_authorization should raise AcmeError because status is 'invalid'
    with pytest.raises(AcmeError) as exc_info:
        client.poll_authorization(
            "https://acme.test/authz/1",
            max_attempts=3,
            poll_interval=0,
        )
    assert exc_info.value.status_code == 200
    assert "invalid" in exc_info.value.body.get("detail", "").lower()


# ─── Test 2: Invalid CSR (server rejects with badCSR) ────────────────────────

@resp_lib.activate
def test_invalid_csr_rejected_by_server(account_key, domain_key):
    """
    A valid CSR is sent to finalize_order, but the server returns badCSR (400).
    Expects AcmeError with status_code 400 and badCSR in body["type"].
    """
    csr_der = create_csr(domain_key, "example.com")

    # Mock POST to finalize URL — server rejects CSR
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/finalize/1",
        json={
            "type": "urn:ietf:params:acme:error:badCSR",
            "detail": "CSR does not match order identifiers",
        },
        status=400,
        headers={"Replay-Nonce": FAKE_NONCE},
    )

    client = AcmeClient("https://acme.test/dir")
    with pytest.raises(AcmeError) as exc_info:
        client.finalize_order(
            "https://acme.test/finalize/1",
            csr_der,
            account_key,
            "https://acme.test/acct/1",
            FAKE_NONCE,
        )
    assert exc_info.value.status_code == 400
    assert "badCSR" in exc_info.value.body.get("type", "")


# ─── Test 3a: Expired Nonce — Auto-retry succeeds ────────────────────────────

@resp_lib.activate
def test_bad_nonce_retries_and_succeeds(account_key):
    """
    First POST returns badNonce with fresh nonce in Replay-Nonce header.
    Client retries automatically and succeeds on the second attempt.
    Expects exactly 2 POST calls (initial + 1 retry).
    """
    # First POST → badNonce with fresh nonce in header
    resp_lib.add(
        resp_lib.POST,
        FAKE_DIRECTORY["newAccount"],
        json={
            "type": "urn:ietf:params:acme:error:badNonce",
            "detail": "nonce expired",
        },
        status=400,
        headers={"Replay-Nonce": "freshnonce001"},
    )

    # Second POST → success (retry with fresh nonce)
    resp_lib.add(
        resp_lib.POST,
        FAKE_DIRECTORY["newAccount"],
        json={"status": "valid"},
        status=201,
        headers={
            "Replay-Nonce": "freshnonce002",
            "Location": "https://acme.test/acct/1",
        },
    )

    client = AcmeClient("https://acme.test/dir")
    account_url, new_nonce = client.create_account(account_key, FAKE_NONCE, FAKE_DIRECTORY)

    assert account_url == "https://acme.test/acct/1"
    assert new_nonce == "freshnonce002"
    # Verify exactly one retry occurred (2 POST calls total)
    assert len(resp_lib.calls) == 2


# ─── Test 3b: Expired Nonce — Retries exhausted ─────────────────────────────

@resp_lib.activate
def test_bad_nonce_exhausts_retries(account_key):
    """
    All _NONCE_RETRIES (3) attempts return badNonce.
    Client exhausts retries and raises AcmeError with badNonce error.
    On the final attempt, when retry is no longer possible, it raises the badNonce error.
    """
    # Mock 3 badNonce responses (one for each attempt in the loop)
    for i in range(3):
        resp_lib.add(
            resp_lib.POST,
            FAKE_DIRECTORY["newAccount"],
            json={
                "type": "urn:ietf:params:acme:error:badNonce",
                "detail": "nonce expired",
            },
            status=400,
            headers={"Replay-Nonce": f"nonce{i}"},
        )

    client = AcmeClient("https://acme.test/dir")
    with pytest.raises(AcmeError) as exc_info:
        client.create_account(account_key, FAKE_NONCE, FAKE_DIRECTORY)

    # On the 3rd attempt (when no more retries are available), the badNonce error is raised
    assert exc_info.value.status_code == 400
    assert "badNonce" in exc_info.value.body.get("type", "")


# ─── Test 4: Network Timeout ───────────────────────────────────────────────────

@resp_lib.activate
def test_network_timeout_on_directory_fetch():
    """
    get_directory() encounters a ConnectTimeout.
    Expects the timeout exception to propagate (no suppression).
    """
    resp_lib.add(
        resp_lib.GET,
        "https://acme.test/dir",
        body=requests.exceptions.ConnectTimeout("Connection timed out"),
    )

    client = AcmeClient("https://acme.test/dir")
    with pytest.raises(requests.exceptions.ConnectTimeout):
        client.get_directory()


# ─── Test 5a: Invalid Directory URL — Connection Error ────────────────────────

@resp_lib.activate
def test_invalid_directory_url_connection_error():
    """
    get_directory() on unreachable host raises ConnectionError.
    Expects the exception to propagate (no suppression).
    """
    resp_lib.add(
        resp_lib.GET,
        "https://invalid.nonexistent/dir",
        body=requests.exceptions.ConnectionError("Failed to resolve hostname"),
    )

    client = AcmeClient("https://invalid.nonexistent/dir")
    with pytest.raises(requests.exceptions.ConnectionError):
        client.get_directory()


# ─── Test 5b: Invalid Directory URL — Returns 404 ───────────────────────────

@resp_lib.activate
def test_invalid_directory_url_returns_404():
    """
    get_directory() on a URL that returns 404.
    raise_for_status() converts this to HTTPError.
    Expects the HTTPError exception to propagate.
    """
    resp_lib.add(
        resp_lib.GET,
        "https://acme.test/bad-dir",
        body="Not Found",
        status=404,
    )

    client = AcmeClient("https://acme.test/bad-dir")
    with pytest.raises(requests.exceptions.HTTPError):
        client.get_directory()


# ─── Test 6: Malformed JSON body (200 OK but invalid JSON) ──────────────────

@resp_lib.activate
def test_finalize_order_malformed_json_response(account_key, domain_key):
    """
    finalize_order() receives status 200 but body is not valid JSON ("not json").
    Client's resp.json() call raises JSONDecodeError.
    This tests robustness when ACME server returns 200 with malformed body.
    """
    csr_der = create_csr(domain_key, "example.com")

    # Mock POST to finalize URL — 200 OK but malformed JSON body
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/finalize/1",
        body="not json",
        status=200,
        headers={"Replay-Nonce": FAKE_NONCE},
    )

    client = AcmeClient("https://acme.test/dir")
    with pytest.raises(Exception) as exc_info:
        # resp.json() will raise JSONDecodeError, which is a ValueError subclass
        client.finalize_order(
            "https://acme.test/finalize/1",
            csr_der,
            account_key,
            "https://acme.test/acct/1",
            FAKE_NONCE,
        )
    # Should be a JSON decode error
    assert "json" in str(exc_info.value).lower() or "json" in type(exc_info.value).__name__.lower()
