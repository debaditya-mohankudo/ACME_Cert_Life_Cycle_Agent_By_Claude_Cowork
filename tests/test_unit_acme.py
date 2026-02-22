"""
Unit tests for the ACME protocol layer.

These tests use the `responses` library to mock HTTP calls — no Pebble or
DigiCert access required.  Run with:  uv run pytest tests/test_unit_acme.py -v
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
import responses as resp_lib

from acme import jws as jwslib
from acme.crypto import create_csr, generate_rsa_key, private_key_to_pem
from acme.client import (
    AcmeError,
    AcmeClient,
    EabAcmeClient,
    DigiCertAcmeClient,
    ZeroSSLAcmeClient,
    SectigoAcmeClient,
    LetsEncryptAcmeClient,
    make_client,
)


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


def test_jwk_thumbprint_rfc7638_canonical_includes_kty(account_key):
    """RFC 7638 §3.2: canonical JSON for RSA must include {e, kty, n} — kty must not be absent."""
    import hashlib

    pub = account_key.public_key()
    fields = pub.fields_to_partial_json()

    # The canonical dict the fixed implementation builds
    canonical_dict = {"e": fields["e"], "kty": "RSA", "n": fields["n"]}
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    expected_digest = hashlib.sha256(canonical_json.encode()).digest()
    expected_thumbprint = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode()

    actual_thumbprint = jwslib.compute_jwk_thumbprint(account_key)

    assert actual_thumbprint == expected_thumbprint
    # Canonical JSON must contain "kty":"RSA" — the earlier broken code omitted this
    assert '"kty":"RSA"' in canonical_json
    # Canonical JSON must be alphabetically sorted: e < kty < n
    assert list(canonical_dict.keys()) == ["e", "kty", "n"]


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


def test_sign_request_rejects_empty_nonce(account_key):
    """sign_request raises ValueError for empty nonce — prevents silent badNonce from ACME server."""
    with pytest.raises(ValueError, match="nonce must not be empty"):
        jwslib.sign_request(
            payload={"test": True},
            account_key=account_key,
            nonce="",
            url="https://acme.test/newAccount",
        )


def test_sign_request_rejects_whitespace_nonce(account_key):
    """sign_request raises ValueError for whitespace-only nonce."""
    with pytest.raises(ValueError, match="nonce must not be empty"):
        jwslib.sign_request(
            payload={"test": True},
            account_key=account_key,
            nonce="   ",
            url="https://acme.test/newAccount",
        )


def test_sign_request_rejects_empty_url(account_key):
    """sign_request raises ValueError for empty url."""
    with pytest.raises(ValueError, match="url must not be empty"):
        jwslib.sign_request(
            payload={"test": True},
            account_key=account_key,
            nonce=FAKE_NONCE,
            url="",
        )


def test_sign_request_rejects_whitespace_url(account_key):
    """sign_request raises ValueError for whitespace-only url."""
    with pytest.raises(ValueError, match="url must not be empty"):
        jwslib.sign_request(
            payload={"test": True},
            account_key=account_key,
            nonce=FAKE_NONCE,
            url="   ",
        )


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
def test_post_as_get_empty_payload_jws(account_key):
    """POST-as-GET: _post_signed(None, ...) produces JWS with empty payload field."""
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/order/1",
        json={"status": "valid"},
        headers={"Replay-Nonce": "orderNonce"},
        status=200,
    )
    client = AcmeClient("https://acme.test/directory")
    resp = client._post_signed(
        payload=None,  # POST-as-GET: no payload
        account_key=account_key,
        nonce=FAKE_NONCE,
        url="https://acme.test/order/1",
        account_url="https://acme.test/acct/42",
    )
    assert resp.ok

    # Verify the JWS has empty payload field
    posted = json.loads(resp_lib.calls[0].request.body)
    assert "protected" in posted
    assert "payload" in posted
    assert posted["payload"] == ""  # POST-as-GET: empty payload


@resp_lib.activate
def test_post_as_get_sign_request_compliance(account_key):
    """POST-as-GET: sign_request(None, ...) produces correct JWS structure."""
    jws = jwslib.sign_request(
        payload=None,
        account_key=account_key,
        nonce=FAKE_NONCE,
        url="https://acme.test/order/1",
        account_url="https://acme.test/acct/42",
    )

    # Verify JWS structure for POST-as-GET
    assert isinstance(jws, dict)
    assert "protected" in jws
    assert "payload" in jws
    assert "signature" in jws

    # Verify empty payload (RFC 8555 §6.2)
    assert jws["payload"] == ""

    # Verify protected header is valid
    protected_decoded = json.loads(
        base64.urlsafe_b64decode(jws["protected"] + "==")
    )
    assert protected_decoded["alg"] == "RS256"
    assert protected_decoded["nonce"] == FAKE_NONCE
    assert protected_decoded["url"] == "https://acme.test/order/1"
    assert protected_decoded["kid"] == "https://acme.test/acct/42"
    assert "jwk" not in protected_decoded  # "kid" used instead


@resp_lib.activate
def test_post_with_payload_vs_post_as_get(account_key):
    """Contrast: POST with payload vs POST-as-GET (None payload)."""
    import base64

    # With payload
    jws_with_payload = jwslib.sign_request(
        payload={"onlyReturnExisting": True},
        account_key=account_key,
        nonce=FAKE_NONCE,
        url="https://acme.test/newAccount",
        account_url="https://acme.test/acct/42",
    )
    assert jws_with_payload["payload"] != ""  # Has payload

    payload_decoded = json.loads(
        base64.urlsafe_b64decode(jws_with_payload["payload"] + "==")
    )
    assert payload_decoded == {"onlyReturnExisting": True}

    # Without payload (POST-as-GET)
    jws_post_as_get = jwslib.sign_request(
        payload=None,
        account_key=account_key,
        nonce=FAKE_NONCE,
        url="https://acme.test/newAccount",
        account_url="https://acme.test/acct/42",
    )
    assert jws_post_as_get["payload"] == ""  # Empty for POST-as-GET

    # Protected headers are the same structure, only nonce might differ
    protected_with = json.loads(
        base64.urlsafe_b64decode(jws_with_payload["protected"] + "==")
    )
    protected_without = json.loads(
        base64.urlsafe_b64decode(jws_post_as_get["protected"] + "==")
    )
    assert protected_with["alg"] == protected_without["alg"]
    assert protected_with["kid"] == protected_without["kid"]


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
def test_lookup_account_returns_none_when_account_does_not_exist(account_key):
    """lookup_account returns (None, nonce) when account doesn't exist (400 accountDoesNotExist)."""
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/newAccount",
        json={"type": "urn:acme:error:accountDoesNotExist", "detail": "Account does not exist"},
        headers={"Replay-Nonce": "lookupnonce"},
        status=400,
    )
    client = AcmeClient("https://acme.test/directory")
    account_url, new_nonce = client.lookup_account(
        account_key=account_key,
        nonce=FAKE_NONCE,
        directory=FAKE_DIRECTORY,
    )
    assert account_url is None
    assert new_nonce == "lookupnonce"


@resp_lib.activate
def test_lookup_account_raises_for_other_400_errors(account_key):
    """lookup_account raises AcmeError for 400 errors that are NOT accountDoesNotExist."""
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/newAccount",
        json={"type": "urn:acme:error:malformed", "detail": "Request body was malformed"},
        headers={"Replay-Nonce": "lookupnonce"},
        status=400,
    )
    client = AcmeClient("https://acme.test/directory")
    with pytest.raises(AcmeError) as exc_info:
        client.lookup_account(
            account_key=account_key,
            nonce=FAKE_NONCE,
            directory=FAKE_DIRECTORY,
        )
    assert exc_info.value.status_code == 400
    assert "malformed" in exc_info.value.body.get("type", "")


@resp_lib.activate
def test_lookup_account_returns_url_when_account_exists(account_key):
    """lookup_account returns (account_url, nonce) when account exists."""
    resp_lib.add(
        resp_lib.POST,
        "https://acme.test/newAccount",
        json={"status": "valid"},
        headers={
            "Location": "https://acme.test/acct/42",
            "Replay-Nonce": "lookupnonce",
        },
        status=200,
    )
    client = AcmeClient("https://acme.test/directory")
    account_url, new_nonce = client.lookup_account(
        account_key=account_key,
        nonce=FAKE_NONCE,
        directory=FAKE_DIRECTORY,
    )
    assert account_url == "https://acme.test/acct/42"
    assert new_nonce == "lookupnonce"


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


def test_revoke_certificate_invalid_reason_negative(account_key):
    """revoke_certificate raises ValueError for reason < 0 (RFC 5280 violation)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    # Generate a dummy cert
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

    client = AcmeClient("https://acme.test/directory")
    with pytest.raises(ValueError, match="Invalid revocation reason code: -1"):
        client.revoke_certificate(
            cert_pem=cert_pem,
            account_key=account_key,
            account_url="https://acme.test/acct/42",
            nonce=FAKE_NONCE,
            directory=FAKE_DIRECTORY,
            reason=-1,
        )


def test_revoke_certificate_invalid_reason_above_10(account_key):
    """revoke_certificate raises ValueError for reason > 10 (RFC 5280 violation)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    # Generate a dummy cert
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

    client = AcmeClient("https://acme.test/directory")
    with pytest.raises(ValueError, match="Invalid revocation reason code: 11"):
        client.revoke_certificate(
            cert_pem=cert_pem,
            account_key=account_key,
            account_url="https://acme.test/acct/42",
            nonce=FAKE_NONCE,
            directory=FAKE_DIRECTORY,
            reason=11,
        )


def test_revoke_certificate_invalid_reason_far_out_of_range(account_key):
    """revoke_certificate raises ValueError for reason >> 10."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    # Generate a dummy cert
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

    client = AcmeClient("https://acme.test/directory")
    with pytest.raises(ValueError, match="Invalid revocation reason code: 100"):
        client.revoke_certificate(
            cert_pem=cert_pem,
            account_key=account_key,
            account_url="https://acme.test/acct/42",
            nonce=FAKE_NONCE,
            directory=FAKE_DIRECTORY,
            reason=100,
        )


# ─── EabAcmeClient, new CA clients, and make_client() factory ─────────────────

def test_zerossl_client_default_url():
    assert ZeroSSLAcmeClient.DEFAULT_DIRECTORY_URL == "https://acme.zerossl.com/v2/DV90"

def test_sectigo_client_default_url():
    assert SectigoAcmeClient.DEFAULT_DIRECTORY_URL == "https://acme.sectigo.com/v2/DV"

def test_digicert_client_default_url():
    assert DigiCertAcmeClient.DEFAULT_DIRECTORY_URL == "https://acme.digicert.com/v2/DV/directory"

def test_eab_subclass_hierarchy():
    assert issubclass(DigiCertAcmeClient, EabAcmeClient)
    assert issubclass(ZeroSSLAcmeClient, EabAcmeClient)
    assert issubclass(SectigoAcmeClient, EabAcmeClient)
    assert issubclass(EabAcmeClient, AcmeClient)

def test_create_account_not_overridden_in_subclasses():
    """Regression: EAB logic lives only in EabAcmeClient, not duplicated."""
    assert "create_account" not in DigiCertAcmeClient.__dict__
    assert "create_account" not in ZeroSSLAcmeClient.__dict__
    assert "create_account" not in SectigoAcmeClient.__dict__
    assert "create_account" in EabAcmeClient.__dict__

def test_make_client_returns_zerossl(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "CA_PROVIDER", "zerossl")
    monkeypatch.setattr(settings, "ACME_EAB_KEY_ID", "test-kid")
    monkeypatch.setattr(settings, "ACME_EAB_HMAC_KEY", "dGVzdA")
    monkeypatch.setattr(settings, "ACME_CA_BUNDLE", "")
    monkeypatch.setattr(settings, "ACME_INSECURE", False)
    client = make_client()
    assert isinstance(client, ZeroSSLAcmeClient)
    assert client.directory_url == ZeroSSLAcmeClient.DEFAULT_DIRECTORY_URL

def test_make_client_returns_sectigo(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "CA_PROVIDER", "sectigo")
    monkeypatch.setattr(settings, "ACME_EAB_KEY_ID", "test-kid")
    monkeypatch.setattr(settings, "ACME_EAB_HMAC_KEY", "dGVzdA")
    monkeypatch.setattr(settings, "ACME_CA_BUNDLE", "")
    monkeypatch.setattr(settings, "ACME_INSECURE", False)
    client = make_client()
    assert isinstance(client, SectigoAcmeClient)
    assert client.directory_url == SectigoAcmeClient.DEFAULT_DIRECTORY_URL

@resp_lib.activate
def test_eab_create_account_injects_eab(account_key):
    """EabAcmeClient injects externalAccountBinding when EAB creds are set."""
    import base64
    resp_lib.add(
        resp_lib.POST, "https://acme.test/newAccount",
        json={"status": "valid"},
        headers={"Location": "https://acme.test/acct/99", "Replay-Nonce": "eabnonce"},
        status=201,
    )
    # Use a valid 32-byte base64url-encoded HMAC key (per RFC 8555 minimum is 16 bytes)
    valid_hmac_key = base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")
    client = ZeroSSLAcmeClient(
        eab_key_id="my-kid", eab_hmac_key=valid_hmac_key,
        directory_url="https://acme.test/directory",
    )
    account_url, new_nonce = client.create_account(account_key, FAKE_NONCE, FAKE_DIRECTORY)
    assert account_url == "https://acme.test/acct/99"
    assert new_nonce == "eabnonce"
    posted = json.loads(resp_lib.calls[0].request.body)
    payload = json.loads(base64.urlsafe_b64decode(posted["payload"] + "=="))
    assert "externalAccountBinding" in payload
    assert payload["termsOfServiceAgreed"] is True

@resp_lib.activate
def test_eab_create_account_omits_eab_when_credentials_empty(account_key):
    """EabAcmeClient skips externalAccountBinding when EAB creds are empty."""
    import base64
    resp_lib.add(
        resp_lib.POST, "https://acme.test/newAccount",
        json={"status": "valid"},
        headers={"Location": "https://acme.test/acct/100", "Replay-Nonce": "noeabnonce"},
        status=201,
    )
    client = ZeroSSLAcmeClient(eab_key_id="", eab_hmac_key="",
                               directory_url="https://acme.test/directory")
    account_url, _ = client.create_account(account_key, FAKE_NONCE, FAKE_DIRECTORY)
    assert account_url == "https://acme.test/acct/100"
    posted = json.loads(resp_lib.calls[0].request.body)
    payload = json.loads(base64.urlsafe_b64decode(posted["payload"] + "=="))
    assert "externalAccountBinding" not in payload


def test_eab_jws_rejects_empty_eab_kid(account_key):
    """create_eab_jws raises ValueError when eab_kid is empty."""
    with pytest.raises(ValueError, match="EAB key ID.*cannot be empty"):
        jwslib.create_eab_jws(
            account_key,
            eab_kid="",  # Empty
            eab_hmac_key_b64url="dGVzdGtleXRlc3RrZXl0ZXN0a2V5",  # Valid base64url (>16 bytes)
            new_account_url="https://acme.test/newAccount",
        )


def test_eab_jws_rejects_empty_eab_hmac_key(account_key):
    """create_eab_jws raises ValueError when eab_hmac_key_b64url is empty."""
    with pytest.raises(ValueError, match="EAB HMAC key.*cannot be empty"):
        jwslib.create_eab_jws(
            account_key,
            eab_kid="test-kid",
            eab_hmac_key_b64url="",  # Empty
            new_account_url="https://acme.test/newAccount",
        )


def test_eab_jws_rejects_short_hmac_key(account_key):
    """create_eab_jws raises ValueError when HMAC key < 16 bytes (RFC 8555 minimum)."""
    import base64
    # Create a base64url string that decodes to only 8 bytes
    short_key = base64.urlsafe_b64encode(b"12345678").decode().rstrip("=")

    with pytest.raises(ValueError, match="EAB HMAC key is too short.*16 bytes"):
        jwslib.create_eab_jws(
            account_key,
            eab_kid="test-kid",
            eab_hmac_key_b64url=short_key,  # Only 8 bytes when decoded
            new_account_url="https://acme.test/newAccount",
        )


def test_eab_jws_succeeds_with_valid_inputs(account_key):
    """create_eab_jws succeeds and returns well-formed JWS with valid inputs."""
    import base64
    # Create a valid base64url HMAC key (32 bytes = 256 bits)
    valid_key = base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")

    jws = jwslib.create_eab_jws(
        account_key,
        eab_kid="test-kid",
        eab_hmac_key_b64url=valid_key,
        new_account_url="https://acme.test/newAccount",
    )

    # Validate JWS structure
    assert isinstance(jws, dict)
    assert "protected" in jws
    assert "payload" in jws
    assert "signature" in jws
    assert all(isinstance(v, str) and len(v) > 0 for v in jws.values())

    # Verify protected header is valid base64url
    protected_decoded = base64.urlsafe_b64decode(jws["protected"] + "==")
    protected_obj = json.loads(protected_decoded)
    assert protected_obj["alg"] == "HS256"
    assert protected_obj["kid"] == "test-kid"
    assert protected_obj["url"] == "https://acme.test/newAccount"


def test_eab_jws_minimum_16_byte_key(account_key):
    """create_eab_jws accepts 16-byte HMAC key (minimum per RFC 8555)."""
    import base64
    # Create exactly 16 bytes (128 bits)
    min_key = base64.urlsafe_b64encode(b"a" * 16).decode().rstrip("=")

    jws = jwslib.create_eab_jws(
        account_key,
        eab_kid="test-kid",
        eab_hmac_key_b64url=min_key,
        new_account_url="https://acme.test/newAccount",
    )

    assert all(isinstance(v, str) and len(v) > 0 for v in jws.values())


# ─── Partial EAB configuration detection ──────────────────────────────────────

@resp_lib.activate
def test_eab_create_account_raises_when_only_key_id_set(account_key):
    """EabAcmeClient raises ValueError when eab_key_id is set but eab_hmac_key is empty."""
    client = ZeroSSLAcmeClient(eab_key_id="my-key-id", eab_hmac_key="",
                               directory_url="https://acme.test/directory")
    with pytest.raises(ValueError, match="eab_hmac_key is missing"):
        client.create_account(account_key, FAKE_NONCE, FAKE_DIRECTORY)


@resp_lib.activate
def test_eab_create_account_raises_when_only_hmac_key_set(account_key):
    """EabAcmeClient raises ValueError when eab_hmac_key is set but eab_key_id is empty."""
    client = ZeroSSLAcmeClient(eab_key_id="", eab_hmac_key="dGVzdGtleXRlc3RrZXl0ZXN0a2V5",
                               directory_url="https://acme.test/directory")
    with pytest.raises(ValueError, match="eab_key_id is missing"):
        client.create_account(account_key, FAKE_NONCE, FAKE_DIRECTORY)


def test_config_rejects_partial_eab_key_id_only():
    """Settings raises ValidationError at startup when only ACME_EAB_KEY_ID is set."""
    from pydantic import ValidationError
    from config import Settings
    with pytest.raises(ValidationError, match="ACME_EAB_HMAC_KEY must be set"):
        Settings(
            CA_PROVIDER="digicert",
            ACME_EAB_KEY_ID="my-key-id",
            ACME_EAB_HMAC_KEY="",
            MANAGED_DOMAINS=["example.com"],
        )


def test_config_rejects_partial_eab_hmac_only():
    """Settings raises ValidationError at startup when only ACME_EAB_HMAC_KEY is set."""
    from pydantic import ValidationError
    from config import Settings
    with pytest.raises(ValidationError, match="ACME_EAB_KEY_ID must be set"):
        Settings(
            CA_PROVIDER="zerossl",
            ACME_EAB_KEY_ID="",
            ACME_EAB_HMAC_KEY="dGVzdGtleXRlc3RrZXl0ZXN0a2V5",
            MANAGED_DOMAINS=["example.com"],
        )


def test_config_accepts_both_eab_credentials_set():
    """Settings accepts valid full EAB configuration."""
    from config import Settings
    s = Settings(
        CA_PROVIDER="digicert",
        ACME_EAB_KEY_ID="my-key-id",
        ACME_EAB_HMAC_KEY="dGVzdGtleXRlc3RrZXl0ZXN0a2V5",
        MANAGED_DOMAINS=["example.com"],
    )
    assert s.ACME_EAB_KEY_ID == "my-key-id"


def test_config_accepts_both_eab_credentials_empty():
    """Settings accepts both-empty EAB credentials (defers validation to CA)."""
    from config import Settings
    s = Settings(
        CA_PROVIDER="digicert",
        ACME_EAB_KEY_ID="",
        ACME_EAB_HMAC_KEY="",
        MANAGED_DOMAINS=["example.com"],
    )
    assert s.ACME_EAB_KEY_ID == ""
