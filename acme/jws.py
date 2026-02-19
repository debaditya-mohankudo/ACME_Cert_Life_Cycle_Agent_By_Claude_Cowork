"""
JWK / JWS / EAB utilities for the ACME protocol (RFC 8555 + RFC 8739).

Uses *josepy* (the library powering Certbot) for battle-tested JWS support.

Responsibilities (boundary with acme/crypto.py):
  - Generate / load / save the **account** RSA key
  - Compute JWK thumbprint (for HTTP-01 key-authorizations)
  - Sign ACME POST bodies as JWS (with jwk or kid header)
  - Build the EAB outer-JWS for DigiCert account registration
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

import josepy as jose
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ─── Account key I/O ──────────────────────────────────────────────────────────


def generate_account_key(key_size: int = 2048) -> jose.JWKRSA:
    """Generate a new RSA account key wrapped in a josepy JWKRSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return jose.JWKRSA(key=private_key)


def save_account_key(jwk: jose.JWKRSA, path: str) -> None:
    """Persist account key as PEM (PKCS8).  Caller should chmod 600."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    pem = jwk.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p.write_bytes(pem)
    os.chmod(path, 0o600)


def load_account_key(path: str) -> jose.JWKRSA:
    """Load an RSA account key from a PEM file."""
    pem = Path(path).read_bytes()
    private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    return jose.JWKRSA(key=private_key)


def account_key_exists(path: str) -> bool:
    return Path(path).exists()


# ─── JWK thumbprint ───────────────────────────────────────────────────────────


def compute_jwk_thumbprint(jwk: jose.JWKRSA) -> str:
    """
    Compute the base64url SHA-256 thumbprint of the public JWK.
    Used to construct the HTTP-01 key-authorization:
      key_authorization = token + "." + thumbprint
    """
    # josepy exposes the public key components via .public_key()
    pub = jwk.public_key()
    # Canonical JSON representation per RFC 7638
    pub_dict = pub.fields_to_partial_json()
    canonical = json.dumps(pub_dict, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    return _b64url(digest)


def compute_key_authorization(token: str, jwk: jose.JWKRSA) -> str:
    """Return the HTTP-01 key-authorization string for *token*."""
    return f"{token}.{compute_jwk_thumbprint(jwk)}"


# ─── JWS signing ─────────────────────────────────────────────────────────────


def sign_request(
    payload: dict | None,
    account_key: jose.JWKRSA,
    nonce: str,
    url: str,
    account_url: str | None = None,
) -> dict:
    """
    Sign an ACME request payload and return the JWS dict to POST.

    If *account_url* is None the JWS header uses the full JWK (used for
    newAccount).  If *account_url* is set the header uses the shorter "kid"
    form (used for all subsequent requests).
    """
    header: dict[str, Any] = {
        "alg": "RS256",
        "nonce": nonce,
        "url": url,
    }
    if account_url:
        header["kid"] = account_url
    else:
        # Include the public JWK in the header
        header["jwk"] = account_key.public_key().fields_to_partial_json()
        header["jwk"]["kty"] = "RSA"

    protected = _b64url(json.dumps(header).encode())
    if payload is None:
        payload_b64 = ""
    else:
        payload_b64 = _b64url(json.dumps(payload).encode())

    signing_input = f"{protected}.{payload_b64}".encode()
    signature = _sign_rsa(account_key, signing_input)

    return {
        "protected": protected,
        "payload": payload_b64,
        "signature": _b64url(signature),
    }


# ─── EAB (External Account Binding) ──────────────────────────────────────────


def create_eab_jws(
    account_jwk: jose.JWKRSA,
    eab_kid: str,
    eab_hmac_key_b64url: str,
    new_account_url: str,
) -> dict:
    """
    Build the EAB outer-JWS required by DigiCert's newAccount request.

    Per RFC 8739:
      - Protected header: {"alg":"HS256","kid":<eab_kid>,"url":<newAccount url>}
      - Payload: the account public JWK
      - Signature: HMAC-SHA256 keyed with the decoded EAB HMAC key
    """
    # Decode the base64url HMAC key
    hmac_key = _b64url_decode(eab_hmac_key_b64url)

    pub_jwk = account_jwk.public_key().fields_to_partial_json()
    pub_jwk["kty"] = "RSA"

    eab_header = {
        "alg": "HS256",
        "kid": eab_kid,
        "url": new_account_url,
    }
    protected = _b64url(json.dumps(eab_header).encode())
    payload = _b64url(json.dumps(pub_jwk).encode())

    signing_input = f"{protected}.{payload}".encode()
    mac = hmac.new(hmac_key, signing_input, hashlib.sha256).digest()

    return {
        "protected": protected,
        "payload": payload,
        "signature": _b64url(mac),
    }


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    """URL-safe base64 encoding with no padding (as required by JOSE)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode, adding padding as needed."""
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _sign_rsa(jwk: jose.JWKRSA, data: bytes) -> bytes:
    """Sign *data* with the RSA private key using PKCS1v15 + SHA-256."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    return jwk.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
