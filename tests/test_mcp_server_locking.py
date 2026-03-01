from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
from types import SimpleNamespace

import mcp_server


def test_mutating_tools_always_request_operation_lock(monkeypatch):
    calls: list[bool] = []

    @asynccontextmanager
    async def fake_operation_lock(*, required: bool):
        calls.append(required)
        yield

    @contextmanager
    def noop_override(settings_override=None):
        yield

    monkeypatch.setattr(mcp_server, "_operation_lock", fake_operation_lock)
    monkeypatch.setattr(mcp_server, "_temporary_settings_override", noop_override)
    monkeypatch.setattr(mcp_server, "_resolve_ca_inputs", lambda **kwargs: (None, None))
    monkeypatch.setattr(mcp_server, "_build_effective_settings", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        mcp_server,
        "_run_renew_once",
        lambda domains, checkpoint, settings=None: {
            "completed_renewals": domains or [],
            "failed_renewals": [],
            "error_log": [],
        },
    )
    monkeypatch.setattr(
        mcp_server,
        "_run_revoke",
        lambda domains, reason, checkpoint, settings=None: {
            "revoked_domains": domains,
            "failed_revocations": [],
            "error_log": [],
        },
    )

    import config

    original_settings = config.settings
    try:
        config.settings = SimpleNamespace(
            LLM_PROVIDER="anthropic",
            ANTHROPIC_API_KEY="key",
            OPENAI_API_KEY="",
            MANAGED_DOMAINS=["a.example.com"],
            HTTP_CHALLENGE_MODE="webroot",
            HTTP_CHALLENGE_PORT=80,
            ACME_INSECURE=False,
            CA_PROVIDER="custom",
            ACME_DIRECTORY_URL="https://localhost:14000/dir",
        )

        asyncio.run(mcp_server.health(ca_input_mode="config"))
        asyncio.run(mcp_server.renew_once(ca_input_mode="config", domains=["a.example.com"]))
        asyncio.run(mcp_server.revoke_cert(ca_input_mode="config", domains=["a.example.com"], reason=0))
    finally:
        config.settings = original_settings

    assert calls == [True, True, True]


def test_read_only_tools_are_not_serialized(monkeypatch):
    calls: list[bool] = []

    @asynccontextmanager
    async def fake_operation_lock(*, required: bool):
        calls.append(required)
        yield

    monkeypatch.setattr(mcp_server, "_operation_lock", fake_operation_lock)
    monkeypatch.setattr(mcp_server, "_run_expiring_in_30_days", lambda domains, settings=None: ["a.example.com"])
    monkeypatch.setattr(mcp_server, "_run_expiring_within", lambda days, domains, settings=None: ["a.example.com"])
    monkeypatch.setattr(
        mcp_server,
        "_run_domain_status",
        lambda domains, settings=None: [{"domain": domains[0], "status": "valid"}],
    )

    monkeypatch.setattr(
        mcp_server,
        "_extract_cert_details",
        lambda pem, domain, cert_store_path: {"domain": domain, "cert_found": True, "status": "valid"},
    )

    import config
    import storage.filesystem as _fs

    original_settings = config.settings
    try:
        config.settings = SimpleNamespace(MANAGED_DOMAINS=["a.example.com"], CERT_STORE_PATH="./certs")
        monkeypatch.setattr(_fs, "read_cert_pem", lambda cert_store_path, domain: "FAKEPEM")
        asyncio.run(mcp_server.expiring_in_30_days(domains=["a.example.com"]))
        asyncio.run(mcp_server.expiring_within(days=60, domains=["a.example.com"]))
        asyncio.run(mcp_server.domain_status(domains=["a.example.com"]))
        asyncio.run(mcp_server.list_managed_domains())
        asyncio.run(mcp_server.read_cert_details(domains=["a.example.com"]))
    finally:
        config.settings = original_settings

    assert calls == [False, False, False, False, False]


