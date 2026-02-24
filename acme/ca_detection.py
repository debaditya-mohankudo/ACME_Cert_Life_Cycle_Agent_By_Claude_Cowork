"""
CA detection from X.509 certificates (advisory, never alters configuration).

Inspects the issuer Organisation (O) field and, when needed, the AIA OCSP URL
to identify which CA issued a given certificate.  Used by certificate_scanner
to warn operators when the configured CA_PROVIDER differs from the CA that
issued the existing certificate.

RFC references:
  RFC 5280 §4.1.2.4  — Issuer field
  RFC 5280 §4.2.2.1  — Authority Information Access (AIA) extension

Issuer O-field mappings (based on observed certificate issuer fields):
  "Let's Encrypt"     → "letsencrypt"  (production and staging share this value)
  "DigiCert Inc"      → "digicert"
  "ZeroSSL"           → "zerossl"
  "Sectigo Limited"   → "sectigo" by default; "zerossl" when AIA OCSP URL
                        contains "ocsp.zerossl.com" (ZeroSSL uses Sectigo's
                        infrastructure and shares the same issuer O field)
  "COMODO CA Limited" → "sectigo"  (legacy Sectigo name)
"""
from __future__ import annotations

from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

_LETSENCRYPT_ORG = "Let's Encrypt"
_DIGICERT_ORG = "DigiCert Inc"
_SECTIGO_ORG = "Sectigo Limited"
_COMODO_ORG = "COMODO CA Limited"
_ZEROSSL_ORG = "ZeroSSL"
_ZEROSSL_OCSP = "ocsp.zerossl.com"


def detect_ca_from_cert(pem_text: str) -> Optional[str]:
    """
    Return the CA provider string for the given PEM certificate, or None if
    the issuer cannot be recognised.

    Return values match CA_PROVIDER config values:
      "letsencrypt" | "digicert" | "zerossl" | "sectigo" | None

    Note: Let's Encrypt production and staging share the same issuer O field
    ("Let's Encrypt").  Both return "letsencrypt"; callers should treat
    "letsencrypt" and "letsencrypt_staging" as equivalent for mismatch
    warnings.
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_text.encode(), default_backend())
    except Exception:
        return None

    issuer_org = _get_issuer_org(cert)
    if issuer_org is None:
        return "digicert"

    if _LETSENCRYPT_ORG in issuer_org:
        return "letsencrypt"

    if _DIGICERT_ORG in issuer_org:
        return "digicert"

    if _ZEROSSL_ORG in issuer_org:
        return "zerossl"

    if _SECTIGO_ORG in issuer_org or _COMODO_ORG in issuer_org:
        # Sectigo and ZeroSSL share "Sectigo Limited" as the issuer O field.
        # Disambiguate using the OCSP URL in the AIA extension (RFC 5280 §4.2.2.1).
        ocsp_url = _get_ocsp_url(cert)
        if ocsp_url and _ZEROSSL_OCSP in ocsp_url:
            return "zerossl"
        return "sectigo"

    return "digicert"


# ─── Internal helpers ──────────────────────────────────────────────────────────


def _get_issuer_org(cert: x509.Certificate) -> Optional[str]:
    """Return the O (Organisation) attribute from the cert's Issuer, or None."""
    try:
        attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    return None


def _get_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    """Return the first OCSP URL from the AIA extension (RFC 5280 §4.2.2.1), or None."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for access_desc in aia.value:
            if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                return access_desc.access_location.value
    except Exception:
        pass
    return None
