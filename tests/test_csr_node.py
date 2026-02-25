from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import config
from agent.nodes import csr as csr_node
from agent.state import AgentState


def test_csr_generator_uses_configured_domain_key_size(monkeypatch, tmp_path):
    original_settings = config.settings
    captured: dict[str, int] = {}

    try:
        config.settings = SimpleNamespace(KEY_TYPE="rsa", DOMAIN_KEY_SIZE=3072, ECC_CURVE="secp256r1")

        def fake_generate_rsa_key(*, key_size: int):
            captured["key_size"] = key_size
            return object()

        monkeypatch.setattr(csr_node, "generate_rsa_key", fake_generate_rsa_key)
        monkeypatch.setattr(csr_node, "private_key_to_pem", lambda _key: "FAKE-PEM")
        monkeypatch.setattr(csr_node, "create_csr", lambda _key, _domain: b"\x01\x02")

        result = csr_node.csr_generator(
            cast(
                AgentState,
                {
                    "current_domain": "api.example.com",
                    "cert_store_path": str(tmp_path),
                    "current_order": None,
                },
            )
        )

        assert captured["key_size"] == 3072
        assert result["current_order"]["csr_der_hex"] == "0102"
        key_path = tmp_path / "api.example.com" / "privkey.pem"
        assert key_path.exists()
        assert key_path.read_text() == "FAKE-PEM"
    finally:
        config.settings = original_settings


def test_csr_generator_uses_configured_ecc_curve(monkeypatch, tmp_path):
    original_settings = config.settings
    captured: dict[str, str] = {}

    try:
        config.settings = SimpleNamespace(KEY_TYPE="ecc", DOMAIN_KEY_SIZE=2048, ECC_CURVE="secp384r1")

        def fake_generate_ec_key(*, curve_name: str):
            captured["curve_name"] = curve_name
            return object()

        monkeypatch.setattr(csr_node, "generate_ec_key", fake_generate_ec_key)
        monkeypatch.setattr(csr_node, "private_key_to_pem", lambda _key: "FAKE-EC-PEM")
        monkeypatch.setattr(csr_node, "create_csr", lambda _key, _domain: b"\x0A\x0B")

        result = csr_node.csr_generator(
            cast(
                AgentState,
                {
                    "current_domain": "api.example.com",
                    "cert_store_path": str(tmp_path),
                    "current_order": None,
                },
            )
        )

        assert captured["curve_name"] == "secp384r1"
        assert result["current_order"]["csr_der_hex"] == "0a0b"
        key_path = tmp_path / "api.example.com" / "privkey.pem"
        assert key_path.exists()
        assert key_path.read_text() == "FAKE-EC-PEM"
    finally:
        config.settings = original_settings
