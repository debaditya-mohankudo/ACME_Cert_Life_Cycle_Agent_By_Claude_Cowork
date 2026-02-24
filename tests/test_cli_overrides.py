from __future__ import annotations

from types import SimpleNamespace

import pytest

import config
import main


def test_apply_runtime_settings_overrides_custom(monkeypatch):
    original_settings = config.settings
    monkeypatch.setenv("CA_PROVIDER", "digicert")
    monkeypatch.setenv("ACME_DIRECTORY_URL", "")

    try:
        main.apply_runtime_settings_overrides(
            ca_provider="custom",
            acme_directory_url="https://localhost:14000/dir",
        )
        assert config.settings.CA_PROVIDER == "custom"
        assert config.settings.ACME_DIRECTORY_URL == "https://localhost:14000/dir"
    finally:
        config.settings = original_settings


def test_apply_runtime_settings_overrides_named_provider_uses_preset(monkeypatch):
    original_settings = config.settings
    monkeypatch.setenv("CA_PROVIDER", "custom")
    monkeypatch.setenv("ACME_DIRECTORY_URL", "https://example.invalid/dir")

    try:
        main.apply_runtime_settings_overrides(
            ca_provider="letsencrypt",
            acme_directory_url="https://override.invalid/dir",
        )
        assert config.settings.CA_PROVIDER == "letsencrypt"
        assert config.settings.ACME_DIRECTORY_URL == "https://acme-v02.api.letsencrypt.org/directory"
    finally:
        config.settings = original_settings


def test_list_domains_expiring_within_filters_and_sorts(monkeypatch):
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(
            MANAGED_DOMAINS=["a.example.com", "b.example.com", "c.example.com", "d.example.com"],
            CERT_STORE_PATH="/tmp/certs",
        )

        pem_by_domain = {
            "a.example.com": "pem_a",
            "b.example.com": "pem_b",
            "c.example.com": "pem_c",
            "d.example.com": None,
        }
        days_by_pem = {
            "pem_a": 40,
            "pem_b": 30,
            "pem_c": -2,
        }

        monkeypatch.setattr(
            "storage.filesystem.read_cert_pem",
            lambda cert_store_path, domain: pem_by_domain[domain],
        )
        monkeypatch.setattr("storage.filesystem.parse_expiry", lambda pem: pem)
        monkeypatch.setattr(
            "storage.filesystem.days_until_expiry",
            lambda expiry: days_by_pem[expiry],
        )

        result = main.list_domains_expiring_within(days=30)

        assert result == ["c.example.com", "b.example.com"]
    finally:
        config.settings = original_settings


def test_list_domains_expiring_within_exits_when_no_domains_configured():
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(MANAGED_DOMAINS=[], CERT_STORE_PATH="/tmp/certs")
        with pytest.raises(SystemExit) as exc:
            main.list_domains_expiring_within(days=30)
        assert exc.value.code == 1
    finally:
        config.settings = original_settings


def test_get_domain_statuses_classifies_domains(monkeypatch):
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(CERT_STORE_PATH="/tmp/certs")

        class FakeExpiry:
            def __init__(self, value: str):
                self.value = value

            def isoformat(self) -> str:
                return self.value

        pem_by_domain = {
            "missing.example.com": None,
            "expired.example.com": "pem_expired",
            "soon.example.com": "pem_soon",
            "ok.example.com": "pem_ok",
        }
        expiry_by_pem = {
            "pem_expired": FakeExpiry("2025-01-01T00:00:00+00:00"),
            "pem_soon": FakeExpiry("2026-03-01T00:00:00+00:00"),
            "pem_ok": FakeExpiry("2026-07-01T00:00:00+00:00"),
        }
        days_by_expiry = {
            expiry_by_pem["pem_expired"]: -1,
            expiry_by_pem["pem_soon"]: 7,
            expiry_by_pem["pem_ok"]: 120,
        }

        monkeypatch.setattr(
            "storage.filesystem.read_cert_pem",
            lambda cert_store_path, domain: pem_by_domain[domain],
        )
        monkeypatch.setattr("storage.filesystem.parse_expiry", lambda pem: expiry_by_pem[pem])
        monkeypatch.setattr(
            "storage.filesystem.days_until_expiry",
            lambda expiry: days_by_expiry[expiry],
        )

        statuses = main.get_domain_statuses(
            ["missing.example.com", "expired.example.com", "soon.example.com", "ok.example.com"]
        )

        assert statuses[0]["status"] == "missing"
        assert statuses[0]["cert_found"] is False

        assert statuses[1]["status"] == "expired"
        assert statuses[1]["expired"] is True
        assert statuses[1]["days_until_expiry"] == -1

        assert statuses[2]["status"] == "expiring_soon"
        assert statuses[2]["expired"] is False
        assert statuses[2]["days_until_expiry"] == 7

        assert statuses[3]["status"] == "valid"
        assert statuses[3]["expired"] is False
        assert statuses[3]["days_until_expiry"] == 120
    finally:
        config.settings = original_settings


def test_get_domain_statuses_exits_when_empty_domains():
    with pytest.raises(SystemExit) as exc:
        main.get_domain_statuses([])
    assert exc.value.code == 1
