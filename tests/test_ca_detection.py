"""
Tests for CA detection from X.509 certificates.

Covers:
  - acme/ca_detection.py  — detect_ca_from_cert(), _get_issuer_org(), _get_ocsp_url()
  - storage/filesystem.py — detect_ca_for_domain() (metadata-first, then cert inspection)
  - agent/nodes/scanner.py — detected_ca_provider in CertRecord, _warn_if_ca_mismatch()
"""
from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID


# ─── Synthetic certificate helpers ────────────────────────────────────────────


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert(
    issuer_org: str,
    ocsp_url: str = "",
) -> str:
    """
    Return a synthetic PEM certificate whose issuer has the given O field and,
    optionally, an AIA extension containing an OCSP URL.
    """
    key = _make_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=90)
        )
    )

    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                ]
            ),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ─── Tests: detect_ca_from_cert() ─────────────────────────────────────────────


class TestDetectCaFromCert:
    def test_letsencrypt(self):
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("Let's Encrypt")
        assert detect_ca_from_cert(pem) == "letsencrypt"

    def test_letsencrypt_r3_issuer(self):
        """Let's Encrypt R3/E1 intermediates still have O="Let's Encrypt"."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("Let's Encrypt")
        assert detect_ca_from_cert(pem) == "letsencrypt"

    def test_digicert(self):
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("DigiCert Inc")
        assert detect_ca_from_cert(pem) == "digicert"

    def test_zerossl_org_field(self):
        """If issuer O = "ZeroSSL", return zerossl without needing AIA check."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("ZeroSSL")
        assert detect_ca_from_cert(pem) == "zerossl"

    def test_sectigo_no_aia(self):
        """Sectigo Limited issuer without ZeroSSL OCSP → sectigo."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("Sectigo Limited")
        assert detect_ca_from_cert(pem) == "sectigo"

    def test_sectigo_with_sectigo_ocsp(self):
        """Sectigo Limited issuer with Sectigo OCSP URL → sectigo."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("Sectigo Limited", ocsp_url="http://ocsp.sectigo.com")
        assert detect_ca_from_cert(pem) == "sectigo"

    def test_sectigo_issuer_with_zerossl_ocsp(self):
        """Sectigo Limited issuer with ZeroSSL OCSP URL → zerossl (disambiguated)."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("Sectigo Limited", ocsp_url="http://ocsp.zerossl.com")
        assert detect_ca_from_cert(pem) == "zerossl"

    def test_comodo_legacy(self):
        """COMODO CA Limited is the legacy Sectigo name → sectigo."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("COMODO CA Limited")
        assert detect_ca_from_cert(pem) == "sectigo"

    def test_comodo_with_zerossl_ocsp(self):
        """COMODO issuer + ZeroSSL OCSP → zerossl."""
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("COMODO CA Limited", ocsp_url="http://ocsp.zerossl.com")
        assert detect_ca_from_cert(pem) == "zerossl"

    def test_unknown_ca_returns_none(self):
        from acme.ca_detection import detect_ca_from_cert

        pem = _build_cert("Unknown CA Corporation")
        assert detect_ca_from_cert(pem) == "digicert"

    def test_invalid_pem_returns_none(self):
        from acme.ca_detection import detect_ca_from_cert

        assert detect_ca_from_cert("not-a-pem") is None
        assert detect_ca_from_cert("") is None

    def test_cert_without_org_field(self):
        """A cert whose issuer has no O field should return 'digicert' (default fallback)."""
        from acme.ca_detection import detect_ca_from_cert

        key = _make_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No Org CA")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(tz=datetime.timezone.utc)
                + datetime.timedelta(days=90)
            )
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        assert detect_ca_from_cert(pem) == "digicert"


# ─── Tests: _get_issuer_org() and _get_ocsp_url() ────────────────────────────


class TestInternalHelpers:
    def test_get_issuer_org_present(self):
        from acme.ca_detection import _get_issuer_org

        pem = _build_cert("DigiCert Inc")
        cert = x509.load_pem_x509_certificate(pem.encode())
        assert _get_issuer_org(cert) == "DigiCert Inc"

    def test_get_issuer_org_absent(self):
        from acme.ca_detection import _get_issuer_org

        key = _make_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-org")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(tz=datetime.timezone.utc)
                + datetime.timedelta(days=90)
            )
            .sign(key, hashes.SHA256())
        )
        assert _get_issuer_org(cert) is None

    def test_get_ocsp_url_present(self):
        from acme.ca_detection import _get_ocsp_url

        pem = _build_cert("Sectigo Limited", ocsp_url="http://ocsp.zerossl.com")
        cert = x509.load_pem_x509_certificate(pem.encode())
        assert _get_ocsp_url(cert) == "http://ocsp.zerossl.com"

    def test_get_ocsp_url_absent(self):
        from acme.ca_detection import _get_ocsp_url

        pem = _build_cert("Sectigo Limited")  # no AIA extension
        cert = x509.load_pem_x509_certificate(pem.encode())
        assert _get_ocsp_url(cert) is None


# ─── Tests: storage.detect_ca_for_domain() ────────────────────────────────────


class TestDetectCaForDomain:
    def test_uses_metadata_ca_provider_when_present(self, tmp_path: Path):
        """metadata.json ca_provider field takes precedence over cert inspection."""
        from storage import filesystem as fs

        domain = "example.com"
        d = tmp_path / domain
        d.mkdir()
        meta = {"ca_provider": "digicert", "issued_at": "2026-01-01T00:00:00+00:00"}
        (d / "metadata.json").write_text(json.dumps(meta))
        # PEM would say letsencrypt, but metadata overrides
        pem = _build_cert("Let's Encrypt")
        result = fs.detect_ca_for_domain(str(tmp_path), domain, pem)
        assert result == "digicert"

    def test_falls_back_to_cert_inspection_when_no_metadata(self, tmp_path: Path):
        from storage import filesystem as fs

        domain = "example.com"
        (tmp_path / domain).mkdir()
        pem = _build_cert("DigiCert Inc")
        result = fs.detect_ca_for_domain(str(tmp_path), domain, pem)
        assert result == "digicert"

    def test_falls_back_to_cert_inspection_when_metadata_has_no_ca_provider(
        self, tmp_path: Path
    ):
        from storage import filesystem as fs

        domain = "example.com"
        d = tmp_path / domain
        d.mkdir()
        # Old metadata without ca_provider field
        meta = {"acme_order_url": "https://acme.example.com/order/1"}
        (d / "metadata.json").write_text(json.dumps(meta))
        pem = _build_cert("Let's Encrypt")
        result = fs.detect_ca_for_domain(str(tmp_path), domain, pem)
        assert result == "letsencrypt"

    def test_returns_digicert_for_unknown_ca(self, tmp_path: Path):
        from storage import filesystem as fs

        domain = "example.com"
        (tmp_path / domain).mkdir()
        pem = _build_cert("Totally Unknown CA Inc")
        assert fs.detect_ca_for_domain(str(tmp_path), domain, pem) == "digicert"


# ─── Tests: write_cert_files() includes ca_provider in metadata ───────────────


class TestWriteCertFilesCAProvider:
    def test_ca_provider_written_to_metadata(self, tmp_path: Path):
        from storage import filesystem as fs

        domain = "example.com"
        # Build a minimal PEM that parse_expiry can parse
        pem = _build_cert("Let's Encrypt")
        fs.write_cert_files(
            cert_store_path=str(tmp_path),
            domain=domain,
            cert_pem=pem,
            chain_pem="",
            privkey_pem="",
            acme_order_url="https://acme.example.com/order/1",
            ca_provider="letsencrypt",
        )
        meta = json.loads((tmp_path / domain / "metadata.json").read_text())
        assert meta["ca_provider"] == "letsencrypt"

    def test_ca_provider_defaults_to_empty_string(self, tmp_path: Path):
        from storage import filesystem as fs

        domain = "example.com"
        pem = _build_cert("DigiCert Inc")
        meta = fs.write_cert_files(
            cert_store_path=str(tmp_path),
            domain=domain,
            cert_pem=pem,
            chain_pem="",
            privkey_pem="",
        )
        assert meta["ca_provider"] == ""


# ─── Tests: scanner._warn_if_ca_mismatch() ────────────────────────────────────


class TestWarnIfCaMismatch:
    def test_no_warning_when_detected_is_none(self, caplog):
        from agent.nodes.scanner import _warn_if_ca_mismatch

        with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
            _warn_if_ca_mismatch("example.com", None, "letsencrypt")
        assert "mismatch" not in caplog.text.lower()

    def test_no_warning_when_cas_match(self, caplog):
        from agent.nodes.scanner import _warn_if_ca_mismatch

        with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
            _warn_if_ca_mismatch("example.com", "letsencrypt", "letsencrypt")
        assert "mismatch" not in caplog.text.lower()

    def test_no_warning_letsencrypt_vs_staging(self, caplog):
        """letsencrypt and letsencrypt_staging are treated as equivalent."""
        from agent.nodes.scanner import _warn_if_ca_mismatch

        with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
            _warn_if_ca_mismatch("example.com", "letsencrypt", "letsencrypt_staging")
        assert "mismatch" not in caplog.text.lower()

    def test_no_warning_staging_vs_letsencrypt(self, caplog):
        from agent.nodes.scanner import _warn_if_ca_mismatch

        with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
            _warn_if_ca_mismatch("example.com", "letsencrypt_staging", "letsencrypt")
        assert "mismatch" not in caplog.text.lower()

    def test_warning_on_mismatch(self, caplog):
        from agent.nodes.scanner import _warn_if_ca_mismatch

        with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
            _warn_if_ca_mismatch("example.com", "letsencrypt", "digicert")
        assert "mismatch" in caplog.text.lower()
        assert "letsencrypt" in caplog.text
        assert "digicert" in caplog.text

    def test_warning_includes_domain(self, caplog):
        from agent.nodes.scanner import _warn_if_ca_mismatch

        with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
            _warn_if_ca_mismatch("api.example.com", "sectigo", "zerossl")
        assert "api.example.com" in caplog.text


# ─── Tests: certificate_scanner node integration ──────────────────────────────


class TestCertificateScannerCADetection:
    def _make_state(self, cert_store_path: str, domains: list[str]) -> dict:
        return {
            "cert_store_path": cert_store_path,
            "managed_domains": domains,
            "renewal_threshold_days": 30,
        }

    def test_no_cert_gives_none_detected_ca(self, tmp_path: Path):
        from agent.nodes.scanner import certificate_scanner

        state = self._make_state(str(tmp_path), ["example.com"])
        with patch("agent.nodes.scanner.settings") as mock_settings:
            mock_settings.CA_PROVIDER = "letsencrypt"
            result = certificate_scanner(state)

        record = result["cert_records"][0]
        assert record["detected_ca_provider"] is None

    def test_cert_present_detected_ca_populated(self, tmp_path: Path):
        from agent.nodes.scanner import certificate_scanner

        domain = "example.com"
        d = tmp_path / domain
        d.mkdir()
        pem = _build_cert("DigiCert Inc")
        (d / "cert.pem").write_text(pem)

        state = self._make_state(str(tmp_path), [domain])
        with patch("agent.nodes.scanner.settings") as mock_settings:
            mock_settings.CA_PROVIDER = "digicert"
            result = certificate_scanner(state)

        record = result["cert_records"][0]
        assert record["detected_ca_provider"] == "digicert"
        assert record["needs_renewal"] is False or record["days_until_expiry"] is not None

    def test_mismatch_triggers_warning(self, tmp_path: Path, caplog):
        from agent.nodes.scanner import certificate_scanner

        domain = "example.com"
        d = tmp_path / domain
        d.mkdir()
        pem = _build_cert("Let's Encrypt")
        (d / "cert.pem").write_text(pem)

        state = self._make_state(str(tmp_path), [domain])
        with patch("agent.nodes.scanner.settings") as mock_settings:
            mock_settings.CA_PROVIDER = "digicert"
            with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
                certificate_scanner(state)

        assert "mismatch" in caplog.text.lower()

    def test_no_mismatch_warning_when_cas_agree(self, tmp_path: Path, caplog):
        from agent.nodes.scanner import certificate_scanner

        domain = "example.com"
        d = tmp_path / domain
        d.mkdir()
        pem = _build_cert("Let's Encrypt")
        (d / "cert.pem").write_text(pem)

        state = self._make_state(str(tmp_path), [domain])
        with patch("agent.nodes.scanner.settings") as mock_settings:
            mock_settings.CA_PROVIDER = "letsencrypt"
            with caplog.at_level(logging.WARNING, logger="agent.nodes.scanner"):
                certificate_scanner(state)

        assert "mismatch" not in caplog.text.lower()
