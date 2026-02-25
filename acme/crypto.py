"""
Domain private-key generation and CSR creation.

Boundary: this module owns everything cryptographic that is *domain*-specific.
Account-key operations (JWK, JWS, EAB) live in acme/jws.py.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key for a domain certificate."""
    from cryptography.hazmat.backends import default_backend

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )


def generate_ec_key(curve_name: str = "secp256r1") -> ec.EllipticCurvePrivateKey:
    """Generate an EC private key using the requested named curve."""
    from cryptography.hazmat.backends import default_backend

    curves: dict[str, ec.EllipticCurve] = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    curve = curves.get(curve_name.lower())
    if curve is None:
        raise ValueError(
            "Unsupported ECC curve: "
            f"{curve_name}. Supported: secp256r1, secp384r1, secp521r1"
        )

    return ec.generate_private_key(curve, default_backend())


def private_key_to_pem(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    """Serialize a private key to an unencrypted PEM string."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def create_csr(
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    domain: str,
    san_domains: list[str] | None = None,
) -> bytes:
    """
    Create a DER-encoded CSR for *domain*.

    The CSR is DER-encoded as required by RFC 8555 §7.4 (POST /finalize expects
    a base64url-encoded DER CSR in the payload).  Includes a SubjectAlternativeName
    extension (RFC 5280) covering all domains; *domain* is always in the SAN list.

    If *san_domains* is provided, all of them are added as SubjectAlternativeNames
    (required for multi-domain SANs / wildcard certs).
    """
    all_domains = list(dict.fromkeys([domain] + (san_domains or [])))  # deduplicate, preserve order

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in all_domains]
            ),
            critical=False,
        )
    )

    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)
