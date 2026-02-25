#!/usr/bin/env python3
"""
Generate self-signed test certificates with configurable validity periods.

This module is library-only. It exports the generate_self_signed_cert() function
for creating test certificates programmatically.

Usage (via main.py CLI):
    python main.py --generate-test-cert my.local --days 90
    python main.py --generate-test-cert example.com --days 7
    python main.py --generate-test-cert old.example.com --days -5  # expired cert
"""
from __future__ import annotations

import datetime
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from storage.atomic import atomic_write_bytes, atomic_write_text


def generate_self_signed_cert(
    domain: str,
    validity_days: int,
    output_dir: Path,
) -> None:
    """
    Generate a self-signed certificate and write cert.pem, privkey.pem, and metadata.json.

    Args:
        domain: Common Name (CN) for the certificate
        validity_days: Validity period in days (can be negative for expired certs)
        output_dir: Directory to write certificate files (e.g., certs/my.local/)

    Note:
        This module is library-only and designed for internal use via main.py CLI.
        Use: python main.py --generate-test-cert DOMAIN --days N
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Calculate validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    if validity_days < 0:
        # For expired certs: certificate was valid for abs(validity_days) and expired abs(validity_days) ago
        not_valid_before = now + datetime.timedelta(days=validity_days * 2)
        not_valid_after = now + datetime.timedelta(days=validity_days)
    else:
        # For valid/future certs: starts 1 hour ago, expires in validity_days
        not_valid_before = now - datetime.timedelta(hours=1)
        not_valid_after = now + datetime.timedelta(days=validity_days)

    # Build certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]
    )

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    # Sign the certificate
    certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

    # Write private key
    privkey_path = output_dir / "privkey.pem"
    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    atomic_write_bytes(privkey_path, privkey_pem)
    privkey_path.chmod(0o600)

    # Write certificate
    cert_path = output_dir / "cert.pem"
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    atomic_write_bytes(cert_path, cert_pem)

    # Write metadata.json
    metadata_path = output_dir / "metadata.json"
    metadata_content = f"""{{
  "issued_at": "{not_valid_before.isoformat()}",
  "expires_at": "{not_valid_after.isoformat()}",
  "acme_order_url": "test://self-signed",
  "ca_provider": "self-signed"
}}
"""
    atomic_write_text(metadata_path, metadata_content)

    # Calculate days until expiry
    days_remaining = (not_valid_after - now).days
    status = "EXPIRED" if days_remaining < 0 else ("EXPIRING SOON" if days_remaining <= 30 else "VALID")

    print(f"✓ Generated self-signed certificate for {domain}")
    print(f"  Valid from: {not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Valid until: {not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Status: {status} ({days_remaining:+d} days)")
    print(f"  Files written to: {output_dir}/")
    print(f"    - cert.pem")
    print(f"    - privkey.pem")
    print(f"    - metadata.json")
