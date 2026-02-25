from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import config
from agent.nodes import account as account_module
from agent.nodes import challenge as challenge_module
from agent.nodes import csr as csr_module
from agent.nodes import error_handler as error_handler_module
from agent.nodes import finalizer as finalizer_module
from agent.nodes import order as order_module
from agent.nodes import planner as planner_module
from agent.nodes import reporter as reporter_module
from agent.nodes import retry_scheduler as retry_scheduler_module
from agent.nodes import revoker as revoker_module
from agent.nodes import scanner as scanner_module
from agent.nodes import storage as storage_module
from agent.state import AgentState


def test_scanner_function_and_class_parity(monkeypatch):
    original_settings = config.settings

    try:
        config.settings = SimpleNamespace(CA_PROVIDER="custom")

        monkeypatch.setattr(scanner_module.fs, "read_cert_pem", lambda _store, _domain: None)
        monkeypatch.setattr(
            scanner_module.fs,
            "cert_dir",
            lambda _store, domain: SimpleNamespace(__truediv__=lambda self, p: f"{domain}/{p}"),
        )

        state = cast(
            AgentState,
            {
                "cert_store_path": "./certs",
                "managed_domains": ["example.com"],
                "renewal_threshold_days": 30,
            },
        )

        fn_result = scanner_module.certificate_scanner(state)
        cls_result = scanner_module.CertificateScannerNode().run(state)

        assert fn_result == cls_result
        assert fn_result["cert_records"][0]["domain"] == "example.com"
        assert fn_result["cert_records"][0]["needs_renewal"] is True
    finally:
        config.settings = original_settings


def test_account_function_and_class_parity(monkeypatch):
    class FakeClient:
        def get_directory(self):
            return {"newAccount": "https://acme.test/newAccount"}

        def get_nonce(self, _directory):
            return "nonce-1"

        def lookup_account(self, _account_key, _nonce, _directory):
            return "https://acme.test/acct/1", "nonce-2"

    monkeypatch.setattr(account_module, "make_client", lambda: FakeClient())
    monkeypatch.setattr(account_module.jwslib, "account_key_exists", lambda _p: True)
    monkeypatch.setattr(account_module.jwslib, "load_account_key", lambda _p: object())

    state = cast(
        AgentState,
        {
            "account_key_path": "./account.key",
        },
    )

    fn_result = account_module.acme_account_setup(state)
    cls_result = account_module.AcmeAccountSetupNode().run(state)

    assert fn_result == cls_result
    assert fn_result["acme_account_url"] == "https://acme.test/acct/1"
    assert fn_result["current_nonce"] == "nonce-2"


def _assert_wrapper_delegates_to_class_run(monkeypatch, module, class_name: str, fn_name: str):
    state = cast(AgentState, {"current_domain": "example.com"})
    expected = {"ok": fn_name}
    captured: dict = {}

    def fake_run(self, input_state):
        captured["state"] = input_state
        return expected

    monkeypatch.setattr(getattr(module, class_name), "run", fake_run)

    result = getattr(module, fn_name)(state)

    assert result == expected
    assert captured["state"] is state


def test_order_initializer_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        order_module,
        "OrderInitializerNode",
        "order_initializer",
    )


def test_csr_generator_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        csr_module,
        "CsrGeneratorNode",
        "csr_generator",
    )


def test_challenge_setup_wrapper_delegates(monkeypatch):
    state = cast(AgentState, {"current_domain": "example.com"})
    fn_result = challenge_module.challenge_setup(state)
    cls_result = challenge_module.ChallengeSetupNode().run(state)

    assert fn_result == cls_result


def test_challenge_verifier_wrapper_delegates(monkeypatch):
    state = cast(AgentState, {"current_domain": "example.com"})
    fn_result = challenge_module.challenge_verifier(state)
    cls_result = challenge_module.ChallengeVerifierNode().run(state)

    assert fn_result == cls_result


def test_order_finalizer_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        finalizer_module,
        "OrderFinalizerNode",
        "order_finalizer",
    )


def test_cert_downloader_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        finalizer_module,
        "CertDownloaderNode",
        "cert_downloader",
    )


def test_storage_manager_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        storage_module,
        "StorageManagerNode",
        "storage_manager",
    )


def test_error_handler_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        error_handler_module,
        "ErrorHandlerNode",
        "error_handler",
    )


def test_retry_scheduler_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        retry_scheduler_module,
        "RetrySchedulerNode",
        "retry_scheduler",
    )


def test_renewal_planner_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        planner_module,
        "RenewalPlannerNode",
        "renewal_planner",
    )


def test_summary_reporter_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        reporter_module,
        "SummaryReporterNode",
        "summary_reporter",
    )


def test_revocation_reporter_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        reporter_module,
        "RevocationReporterNode",
        "revocation_reporter",
    )


def test_cert_revoker_wrapper_delegates(monkeypatch):
    _assert_wrapper_delegates_to_class_run(
        monkeypatch,
        revoker_module,
        "CertRevokerNode",
        "cert_revoker",
    )
