"""
Integration test: full TLS certificate lifecycle against a local Pebble stub.

Lifecycle steps covered
-----------------------
1. Issue       — agent runs with no existing cert; certificate is issued and stored
2. Expiry      — scanner correctly marks cert as needing renewal when
                 renewal_threshold_days exceeds days_until_expiry
3. Renew       — agent re-runs with high threshold; a new cert (different serial)
                 is issued and replaces the original
4. Revoke      — the renewed cert is revoked via ACME /revokeCert

Prerequisites
-------------
  docker compose -f docker-compose.pebble.yml up -d

Pebble is configured with PEBBLE_VA_ALWAYS_VALID=1, so HTTP-01 challenges are
auto-approved without real DNS or port-80 access.

Run with:
  uv run pytest tests/test_lifecycle_pebble.py -v
"""
from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from tests.conftest import requires_pebble


def _run_agent(pebble_settings, renewal_threshold_days: int) -> dict:
    from agent.graph import build_graph, initial_state
    graph = build_graph(use_checkpointing=False)
    return graph.invoke(
        initial_state(
            managed_domains=pebble_settings.MANAGED_DOMAINS,
            cert_store_path=pebble_settings.CERT_STORE_PATH,
            account_key_path=pebble_settings.ACCOUNT_KEY_PATH,
            renewal_threshold_days=renewal_threshold_days,
            max_retries=pebble_settings.MAX_RETRIES,
            webroot_path=pebble_settings.WEBROOT_PATH,
        )
    )


@requires_pebble
def test_certificate_lifecycle(pebble_settings, mock_llm_nodes):
    """
    Full TLS certificate lifecycle:

    1. Issue       — first run issues a cert when none exists
    2. Expiry      — scanner detects cert as expiring when threshold > days remaining
    3. Renew       — second run with high threshold produces a new cert (different serial)
    4. Revoke      — renewed cert is successfully revoked via /revokeCert
    """
    from acme import jws as jwslib
    from acme.client import make_client
    from storage.filesystem import days_until_expiry, parse_expiry

    domain = "acme-test.localhost"
    cert_dir = Path(pebble_settings.CERT_STORE_PATH) / domain

    # ── 1. ISSUE ─────────────────────────────────────────────────────────────
    # No cert exists → scanner marks needs_renewal=True → planner says "routine"
    # → full ACME flow runs → cert.pem written to disk

    result_v1 = _run_agent(pebble_settings, renewal_threshold_days=30)

    assert domain in result_v1["completed_renewals"], (
        f"Issue failed — completed: {result_v1['completed_renewals']}, "
        f"failed: {result_v1['failed_renewals']}, errors: {result_v1['error_log']}"
    )
    assert result_v1["failed_renewals"] == []

    # All PEM files must exist
    for fname in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "metadata.json"):
        assert (cert_dir / fname).exists(), f"Missing after issue: {cert_dir / fname}"

    # Private key must be owner-read-only
    key_mode = stat.S_IMODE((cert_dir / "privkey.pem").stat().st_mode)
    assert key_mode == 0o600, f"privkey.pem mode {oct(key_mode)}, want 0o600"

    # Read issued cert for later comparison
    cert_pem_v1 = (cert_dir / "cert.pem").read_text()
    cert_obj_v1 = x509.load_pem_x509_certificate(cert_pem_v1.encode())
    serial_v1 = cert_obj_v1.serial_number
    expiry_v1 = parse_expiry(cert_pem_v1)

    metadata_v1 = json.loads((cert_dir / "metadata.json").read_text())
    assert "issued_at" in metadata_v1
    assert "expires_at" in metadata_v1

    # ── 2. EXPIRY DETECTION ───────────────────────────────────────────────────
    # Pebble issues certs with a multi-year validity. Verify that the scanner's
    # threshold logic correctly identifies the cert as "needing renewal" when the
    # configured threshold exceeds the remaining validity.

    days_left = days_until_expiry(expiry_v1)
    assert days_left > 0, "Newly issued cert must be valid"

    # With threshold=9999, scanner would set needs_renewal=True for this cert
    # (days_left < 9999 is always true for any reasonable cert lifetime)
    assert days_left < 9999, (
        f"Cert has {days_left} days left — threshold logic covered in step 3"
    )

    # ── 3. RENEW ─────────────────────────────────────────────────────────────
    # Threshold=9999 → scanner sets needs_renewal=True → planner mock returns
    # "routine: [domain]" → full ACME flow runs → new cert replaces old cert

    result_v2 = _run_agent(pebble_settings, renewal_threshold_days=9999)

    assert domain in result_v2["completed_renewals"], (
        f"Renewal failed — completed: {result_v2['completed_renewals']}, "
        f"failed: {result_v2['failed_renewals']}, errors: {result_v2['error_log']}"
    )
    assert result_v2["failed_renewals"] == []

    cert_pem_v2 = (cert_dir / "cert.pem").read_text()
    cert_obj_v2 = x509.load_pem_x509_certificate(cert_pem_v2.encode())
    serial_v2 = cert_obj_v2.serial_number

    # Renewed cert must be a different certificate
    assert serial_v2 != serial_v1, (
        "Renewed cert must have a different serial number from the original"
    )

    # metadata.json must have been updated with the new expiry
    metadata_v2 = json.loads((cert_dir / "metadata.json").read_text())
    assert metadata_v2["expires_at"] != ""
    assert metadata_v2["expires_at"] != metadata_v1["expires_at"]

    # ── 4. REVOKE ────────────────────────────────────────────────────────────
    # Revoke the renewed cert using the ACME /revokeCert endpoint.
    # make_client() returns AcmeClient pointing at Pebble (CA_PROVIDER=custom).

    client = make_client()
    directory = client.get_directory()
    nonce = client.get_nonce(directory)
    account_key = jwslib.load_account_key(pebble_settings.ACCOUNT_KEY_PATH)
    account_url = result_v2["acme_account_url"]

    new_nonce = client.revoke_certificate(
        cert_pem=cert_pem_v2,
        account_key=account_key,
        account_url=account_url,
        nonce=nonce,
        directory=directory,
    )

    # Pebble returns 200 OK on successful revocation; AcmeError would be raised otherwise
    assert isinstance(new_nonce, str)


@requires_pebble
def test_revoke_original_cert_after_renewal(pebble_settings, mock_llm_nodes):
    """
    Revoke the original (superseded) certificate after a renewal.
    Uses reason code 4 (superseded) to indicate the cert was replaced.
    """
    from acme import jws as jwslib
    from acme.client import make_client

    domain = "acme-test.localhost"
    cert_dir = Path(pebble_settings.CERT_STORE_PATH) / domain

    # Issue initial cert
    result_v1 = _run_agent(pebble_settings, renewal_threshold_days=30)
    assert domain in result_v1["completed_renewals"]
    cert_pem_v1 = (cert_dir / "cert.pem").read_text()

    # Renew (produces new cert, overwrites cert.pem)
    result_v2 = _run_agent(pebble_settings, renewal_threshold_days=9999)
    assert domain in result_v2["completed_renewals"]

    # Revoke the *original* cert with reason=4 (superseded)
    client = make_client()
    directory = client.get_directory()
    nonce = client.get_nonce(directory)
    account_key = jwslib.load_account_key(pebble_settings.ACCOUNT_KEY_PATH)
    account_url = result_v2["acme_account_url"]

    new_nonce = client.revoke_certificate(
        cert_pem=cert_pem_v1,
        account_key=account_key,
        account_url=account_url,
        nonce=nonce,
        directory=directory,
        reason=4,  # superseded
    )
    assert isinstance(new_nonce, str)
