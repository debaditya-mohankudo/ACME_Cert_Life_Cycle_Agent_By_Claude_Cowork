"""
Unit tests for the ACME protocol layer.

These tests use the `responses` library to mock HTTP calls — no Pebble or
DigiCert access required.  Run with:  uv run pytest tests/test_unit_acme.py -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses as resp_lib

from acme import jws as jwslib
from acme.crypto import create_csr, generate_rsa_key, private_key_to_pem
from acme.client import AcmeError, AcmeClient, DigiCertAcmeClient, LetsEncryptAcmeClient


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


# ─── acme/jws.py ──────────────────────────────────────────────────────────────

def test_generate_account_key(account_key):
    assert account_key is not None
    assert account_key.key.key_size == 2048


def test_jwk_thumbprint_is_deterministic(account_key):
    t1 = jwslib.compute_jwk_thumbprint(account_key)
    t2 = jwslib.compute_jwk_thumbprint(account_key)
    assert t1 == t2
    assert len(t1) > 10


def test_key_authorization(account_key):
    token = "sometoken"
    key_auth = jwslib.compute_key_authorization(token, account_key)
    thumbprint = jwslib.compute_jwk_thumbprint(account_key)
    assert key_auth == f"{token}.{thumbprint}"


def test_sign_request_jwk_header(account_key):
    body = jwslib.sign_request(
        payload={"test": True},
        account_key=account_key,
        nonce=FAKE_NONCE,
        url="https://acme.test/newAccount",
        account_url=None,  # JWK mode
    )
    import base64
    protected = json.loads(base64.urlsafe_b64decode(body["protected"] + "=="))
    assert "jwk" in protected
    assert protected["nonce"] == FAKE_NONCE
    assert protected["alg"] == "RS256"


def test_sign_request_kid_header(account_key):
    body = jwslib.sign_request(
        payload={"test": True},
        account_key=account_key,
        nonce=FAKE_NONCE,
        url="https://acme.test/newOrder",
        account_url="https://acme.test/acct/1",
    )
    import base64
    protected = json.loads(base64.urlsafe_b64decode(body["protected"] + "=="))
    assert protected["kid"] == "https://acme.test/acct/1"
    assert "jwk" not in protected


def test_save_and_load_account_key(account_key, tmp_path):
    path = str(tmp_path / "account.key")
    jwslib.save_account_key(account_key, path)
    assert Path(path).exists()

    import stat
    mode = stat.S_IMODE(Path(path).stat().st_mode)
    assert mode == 0o600

    loaded = jwslib.load_account_key(path)
    # Thumbprints must match — same key
    assert jwslib.compute_jwk_thumbprint(loaded) == jwslib.compute_jwk_thumbprint(account_key)


# ─── acme/crypto.py ───────────────────────────────────────────────────────────

def test_rsa_key_generation(domain_key):
    assert domain_key.key_size == 2048


def test_private_key_to_pem(domain_key):
    pem = private_key_to_pem(domain_key)
    assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----")


def test_create_csr_single_domain(domain_key):
    csr_der = create_csr(domain_key, "example.com")
    assert isinstance(csr_der, bytes)
    assert len(csr_der) > 100


def test_create_csr_multi_san(domain_key):
    csr_der = create_csr(domain_key, "example.com", san_domains=["www.example.com", "api.example.com"])
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    csr = x509.load_der_x509_csr(csr_der, default_backend())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [d.value for d in san.value]
    assert "example.com" in names
    assert "www.example.com" in names
    assert "api.example.com" in names


# ─── acme/client.py ───────────────────────────────────────────────────────────

@resp_lib.activate
def test_get_directory():
    resp_lib.add(resp_lib.GET, "https://acme.test/directory", json=FAKE_DIRECTORY)
    client = AcmeClient("https://acme.test/directory")
    directory = client.get_directory()
    assert directory["newAccount"] == "https://acme.test/newAccount"


@resp_lib.activate
def test_get_nonce():
    resp_lib.add(
        resp_lib.HEAD,
        "https://acme.test/newNonce",
        headers={"Replay-Nonce": FAKE_NONCE},
    )
    client = AcmeClient("https://acme.test/directory")
    nonce = client.get_nonce(FAKE_DIRECTORY)
    assert nonce == FAKE_NONCE


@resp_lib.activate
def test_create_account_without_eab(account_key):
    """Pebble / LE staging: no EAB → plain newAccount POST."""
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/newAccount",
        json={"status": "valid"},
        headers={
            "Location": "https://acme.test/acct/42",
            "Replay-Nonce": "newnonce",
        },
        status=201,
    )
    client = AcmeClient("https://acme.test/directory")
    account_url, new_nonce = client.create_account(
        account_key=account_key,
        nonce=FAKE_NONCE,
        directory=FAKE_DIRECTORY,
    )
    assert account_url == "https://acme.test/acct/42"
    assert new_nonce == "newnonce"

    # Verify EAB was NOT included in the payload
    posted = json.loads(resp_lib.calls[0].request.body)
    import base64
    payload = json.loads(base64.urlsafe_b64decode(posted["payload"] + "=="))
    assert "externalAccountBinding" not in payload


@resp_lib.activate
def test_create_order(account_key):
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/newOrder",
        json={
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        },
        headers={
            "Location": "https://acme.test/order/1",
            "Replay-Nonce": "nonce2",
        },
        status=201,
    )
    client = AcmeClient("https://acme.test/directory")
    order, order_url, nonce = client.create_order(
        domains=["example.com"],
        account_key=account_key,
        account_url="https://acme.test/acct/42",
        nonce=FAKE_NONCE,
        directory=FAKE_DIRECTORY,
    )
    assert order_url == "https://acme.test/order/1"
    assert order["finalize"] == "https://acme.test/finalize/1"


@resp_lib.activate
def test_poll_authorization_valid():
    resp_lib.add(
        resp_lib.GET,
        "https://acme.test/authz/1",
        json={"status": "valid"},
    )
    client = AcmeClient("https://acme.test/directory")
    status = client.poll_authorization("https://acme.test/authz/1", max_attempts=3, poll_interval=0)
    assert status == "valid"


@resp_lib.activate
def test_poll_authorization_invalid_raises():
    resp_lib.add(
        resp_lib.GET,
        "https://acme.test/authz/1",
        json={"status": "invalid", "challenges": []},
    )
    client = AcmeClient("https://acme.test/directory")
    with pytest.raises(AcmeError):
        client.poll_authorization("https://acme.test/authz/1", max_attempts=3, poll_interval=0)


@resp_lib.activate
def test_acme_error_on_non_2xx():
    # Use 'malformed' (not badNonce) so _post_signed does not attempt a nonce
    # retry that would require an unmocked HEAD /newNonce endpoint.
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/newAccount",
        json={"type": "urn:ietf:params:acme:error:malformed", "detail": "bad payload"},
        status=400,
    )
    client = AcmeClient("https://acme.test/directory")
    from acme import jws as jwslib
    key = jwslib.generate_account_key(key_size=2048)
    with pytest.raises(AcmeError) as exc_info:
        client.create_account(key, FAKE_NONCE, FAKE_DIRECTORY)
    assert exc_info.value.status_code == 400


@resp_lib.activate
def test_revoke_certificate(account_key):
    """POST /revokeCert — base64url-encoded DER cert in payload, Replay-Nonce returned."""
    import base64
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    # Generate a self-signed leaf cert to pass to revoke_certificate
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90))
        .sign(leaf_key, hashes.SHA256())
    )
    cert_pem = leaf_cert.public_bytes(Encoding.PEM).decode()

    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/revokeCert",
        json={},
        headers={"Replay-Nonce": "revokeNonce"},
        status=200,
    )
    client = AcmeClient("https://acme.test/directory")
    new_nonce = client.revoke_certificate(
        cert_pem=cert_pem,
        account_key=account_key,
        account_url="https://acme.test/acct/42",
        nonce=FAKE_NONCE,
        directory=FAKE_DIRECTORY,
    )
    assert new_nonce == "revokeNonce"

    # Verify the payload contained the DER-encoded cert as base64url
    posted = json.loads(resp_lib.calls[0].request.body)
    payload = json.loads(base64.urlsafe_b64decode(posted["payload"] + "=="))
    assert "certificate" in payload
    cert_der = base64.urlsafe_b64decode(payload["certificate"] + "==")
    assert cert_der == leaf_cert.public_bytes(Encoding.DER)
    assert "reason" not in payload  # default reason=0 omitted
