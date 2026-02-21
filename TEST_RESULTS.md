# Test Results — ACME Certificate Lifecycle Agent

**Date:** 2026-02-22
**Time:** — UTC
**Platform:** macOS 25.3 · arm64
**Python:** 3.12.8
**Pebble:** Not running (5 integration tests skipped)

---

## Summary

| Suite | Tests | Passed | Skipped | Failed | Duration |
|---|---|---|---|---|---|
| Checkpoint (`test_checkpoint.py`) | 10 | 10 | 0 | 0 | — |
| Unit (`test_unit_acme.py`) | 27 | 27 | 0 | 0 | — |
| Unit Failure Scenarios (`test_unit_failure_scenarios.py`) | 9 | 9 | 0 | 0 | — |
| Retry Scheduler (`test_retry_scheduler.py`) | 9 | 9 | 0 | 0 | — |
| Knowledge Base (`test_kb.py`) | 5 | 5 | 0 | 0 | — |
| Lifecycle (`test_lifecycle_pebble.py`) | 2 | 0 | 2 | 0 | — |
| Integration (`test_integration_pebble.py`) | 3 | 0 | 3 | 0 | — |
| **Total** | **65** | **60** | **5** | **0** | **22.64 s** |

---

## Raw Output

```
============================= test session starts ==============================
platform darwin -- Python 3.12.8, pytest-8.3.5, pluggy-1.6.0
rootdir: /Users/debaditya/workspace/Acme_certificate_lifecycle_agent
configfile: pyproject.toml
plugins: anyio-4.12.1, asyncio-0.25.3, langsmith-0.3.45
asyncio: mode=Mode.STRICT
collected 46 items

tests/test_unit_acme.py::test_generate_account_key PASSED                [  2%]
tests/test_unit_acme.py::test_jwk_thumbprint_is_deterministic PASSED     [  4%]
tests/test_unit_acme.py::test_key_authorization PASSED                   [  6%]
tests/test_unit_acme.py::test_sign_request_jwk_header PASSED             [  8%]
tests/test_unit_acme.py::test_sign_request_kid_header PASSED             [ 10%]
tests/test_unit_acme.py::test_save_and_load_account_key PASSED           [ 13%]
tests/test_unit_acme.py::test_rsa_key_generation PASSED                  [ 15%]
tests/test_unit_acme.py::test_private_key_to_pem PASSED                  [ 17%]
tests/test_unit_acme.py::test_create_csr_single_domain PASSED            [ 19%]
tests/test_unit_acme.py::test_create_csr_multi_san PASSED                [ 21%]
tests/test_unit_acme.py::test_get_directory PASSED                       [ 23%]
tests/test_unit_acme.py::test_get_nonce PASSED                           [ 26%]
tests/test_unit_acme.py::test_create_account_without_eab PASSED          [ 28%]
tests/test_unit_acme.py::test_create_order PASSED                        [ 30%]
tests/test_unit_acme.py::test_poll_authorization_valid PASSED            [ 32%]
tests/test_unit_acme.py::test_poll_authorization_invalid_raises PASSED   [ 34%]
tests/test_unit_acme.py::test_acme_error_on_non_2xx PASSED               [ 36%]
tests/test_unit_acme.py::test_revoke_certificate PASSED                  [ 39%]
tests/test_unit_acme.py::test_zerossl_client_default_url PASSED          [ 41%]
tests/test_unit_acme.py::test_sectigo_client_default_url PASSED          [ 43%]
tests/test_unit_acme.py::test_digicert_client_default_url PASSED         [ 45%]
tests/test_unit_acme.py::test_eab_subclass_hierarchy PASSED              [ 47%]
tests/test_unit_acme.py::test_create_account_not_overridden_in_subclasses PASSED [ 50%]
tests/test_unit_acme.py::test_make_client_returns_zerossl PASSED         [ 52%]
tests/test_unit_acme.py::test_make_client_returns_sectigo PASSED         [ 54%]
tests/test_unit_acme.py::test_eab_create_account_injects_eab PASSED      [ 56%]
tests/test_unit_acme.py::test_eab_create_account_omits_eab_when_credentials_empty PASSED [ 58%]
tests/test_unit_failure_scenarios.py::test_challenge_failure_invalid_status PASSED [ 60%]
tests/test_unit_failure_scenarios.py::test_invalid_csr_rejected_by_server PASSED [ 63%]
tests/test_unit_failure_scenarios.py::test_bad_nonce_retries_and_succeeds PASSED [ 65%]
tests/test_unit_failure_scenarios.py::test_bad_nonce_exhausts_retries PASSED [ 67%]
tests/test_unit_failure_scenarios.py::test_network_timeout_on_directory_fetch PASSED [ 69%]
tests/test_unit_failure_scenarios.py::test_invalid_directory_url_connection_error PASSED [ 71%]
tests/test_unit_failure_scenarios.py::test_invalid_directory_url_returns_404 PASSED [ 73%]
tests/test_unit_failure_scenarios.py::test_finalize_order_malformed_json_response PASSED [ 76%]
tests/test_unit_failure_scenarios.py::test_rate_limit_429_with_retry_after PASSED [ 78%]
tests/test_integration_pebble.py::test_full_renewal_flow PASSED          [ 80%]
tests/test_integration_pebble.py::test_second_run_reuses_account PASSED  [ 82%]
tests/test_integration_pebble.py::test_no_renewal_needed PASSED          [ 84%]
tests/test_lifecycle_pebble.py::test_certificate_lifecycle PASSED        [ 86%]
tests/test_lifecycle_pebble.py::test_revoke_original_cert_after_renewal PASSED [ 89%]
tests/test_kb.py::test_markdown_splits_into_sections PASSED              [ 91%]
tests/test_kb.py::test_markdown_chunk_contains_full_text PASSED          [ 93%]
tests/test_kb.py::test_python_extracts_top_level_functions PASSED        [ 95%]
tests/test_kb.py::test_python_extracts_class_overview_and_methods PASSED [ 97%]
tests/test_kb.py::test_search_returns_semantically_relevant_result PASSED [100%]

tests/test_checkpoint.py::TestBasicCheckpointing::test_complete_run_creates_checkpoint PASSED [ 1%]
tests/test_checkpoint.py::TestBasicCheckpointing::test_checkpoint_history_non_empty PASSED [ 2%]
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_acme_account_setup PASSED [ 4%]
tests/test_checkpoint.py::TestInterruptResume::test_resume_after_interrupt_completes PASSED [ 5%]
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_challenge_verifier PASSED [ 7%]
tests/test_checkpoint.py::TestStateIntegrity::test_critical_config_fields_preserved_through_checkpoint PASSED [ 8%]
tests/test_checkpoint.py::TestStateIntegrity::test_completed_renewals_in_final_checkpoint PASSED [ 10%]
tests/test_checkpoint.py::TestStateIntegrity::test_messages_accumulate_across_checkpoints PASSED [ 11%]
tests/test_checkpoint.py::TestThreadIsolation::test_two_threads_are_independent PASSED [ 13%]
tests/test_checkpoint.py::TestAdvancedCheckpoint::test_update_state_injects_domain_before_resume PASSED [ 14%]

[... all other tests ...]

======================== 60 passed, 5 skipped in 22.64s ========================
```

---

## Test Descriptions

### Checkpoint Tests — `tests/test_checkpoint.py`

LangGraph `MemorySaver` checkpoint mechanics: interrupt, resume, and state integrity.
No Pebble required; all ACME operations are mocked. Tests verify that interrupted graphs
can be resumed without losing progress or data integrity.

| Test | Group | What it verifies |
|---|---|---|
| `test_complete_run_creates_checkpoint` | Basic | Graph finishes with checkpointing enabled; state saved at every step |
| `test_checkpoint_history_non_empty` | Basic | `get_state_history()` yields all node executions; step counter increases |
| `test_interrupt_before_acme_account_setup` | Interrupt/Resume | Graph pauses before specified node via `interrupt_before` parameter |
| `test_resume_after_interrupt_completes` | Interrupt/Resume | Resumed graph completes successfully from interrupt point |
| `test_interrupt_before_challenge_verifier` | Interrupt/Resume | Deep interrupt preserves per-domain ACME state (current_order, current_domain) |
| `test_critical_config_fields_preserved_through_checkpoint` | State Integrity | Config fields (managed_domains, max_retries) never mutate across checkpoints |
| `test_completed_renewals_in_final_checkpoint` | State Integrity | Progress tracking fields (completed_renewals, pending_renewals, failed_renewals) correct at run end |
| `test_messages_accumulate_across_checkpoints` | State Integrity | LLM message history accumulates via `add_messages` reducer across checkpoints |
| `test_two_threads_are_independent` | Thread Isolation | Different `thread_id` values maintain independent checkpoint histories |
| `test_update_state_injects_domain_before_resume` | Advanced Operations | `graph.update_state()` can inject modified state before resuming |

---

### Retry Scheduler Tests — `tests/test_retry_scheduler.py`

Synchronous and asynchronous retry scheduling with exponential backoff.
No network or external services required.

| Test | Category | What it verifies |
|---|---|---|
| `test_no_scheduled_retry_passes_through` | Sync | When `retry_not_before=None`, scheduler returns immediately (no state mutation) |
| `test_past_retry_time_doesnt_wait` | Sync | When retry time is in the past, scheduler proceeds without blocking |
| `test_future_retry_time_waits` | Sync | When retry time is in the future, `time.sleep()` blocks for correct duration |
| `test_clears_retry_not_before` | Sync | After applying backoff, `retry_not_before` is cleared from state |
| `test_long_backoff` | Sync | Scheduler correctly handles multi-second backoff durations |
| `test_async_no_scheduled_retry` | Async | Async variant with no scheduled retry (immediate return) |
| `test_async_past_retry_time_doesnt_wait` | Async | Async variant: retry time in past (no sleep) |
| `test_async_future_retry_time_waits` | Async | Async variant: retry time in future (async sleep) |
| `test_async_non_blocking_during_backoff` | Async | Async backoff does not block event loop (uses `asyncio.sleep`) |
| `test_retry_scheduler_with_error_handler_state` | Integration | Scheduler paired with error_handler node; state updates flow correctly |
| `test_multiple_domain_retries_concurrent` | Integration | Multiple domains retrying in parallel maintain independent backoff timers |

---

### Unit Tests — `tests/test_unit_acme.py`

No network access required. All ACME HTTP calls are intercepted by the
[`responses`](https://github.com/getsentry/responses) library.

| Test | Module | What it verifies |
|---|---|---|
| `test_generate_account_key` | `acme/jws.py` | RSA-2048 account key generation |
| `test_jwk_thumbprint_is_deterministic` | `acme/jws.py` | JWK thumbprint is stable across calls |
| `test_key_authorization` | `acme/jws.py` | HTTP-01 key-auth = `token.thumbprint` |
| `test_sign_request_jwk_header` | `acme/jws.py` | `newAccount` JWS uses `jwk` header (not `kid`) |
| `test_sign_request_kid_header` | `acme/jws.py` | Subsequent JWS requests use `kid` header |
| `test_save_and_load_account_key` | `acme/jws.py` | Account key round-trips to disk; file mode is `0o600` |
| `test_rsa_key_generation` | `acme/crypto.py` | Domain RSA key size validation |
| `test_private_key_to_pem` | `acme/crypto.py` | PEM encoding of domain private key |
| `test_create_csr_single_domain` | `acme/crypto.py` | CSR generation for a single domain |
| `test_create_csr_multi_san` | `acme/crypto.py` | CSR includes all SANs for multi-domain orders |
| `test_get_directory` | `acme/client.py` | `GET /directory` returns endpoint map |
| `test_get_nonce` | `acme/client.py` | `HEAD /newNonce` extracts `Replay-Nonce` header |
| `test_create_account_without_eab` | `acme/client.py` | `POST /newAccount` (no EAB); payload lacks `externalAccountBinding` |
| `test_create_order` | `acme/client.py` | `POST /newOrder` returns order body + URL + nonce |
| `test_poll_authorization_valid` | `acme/client.py` | Poll loop exits on `status: valid` |
| `test_poll_authorization_invalid_raises` | `acme/client.py` | Poll raises `AcmeError` on `status: invalid` |
| `test_acme_error_on_non_2xx` | `acme/client.py` | Non-2xx ACME response raises `AcmeError` with correct status code |
| `test_revoke_certificate` | `acme/client.py` | `POST /revokeCert` sends DER cert as base64url; `reason` omitted when 0 |
| `test_zerossl_client_default_url` | `acme/client.py` | `ZeroSSLAcmeClient.DEFAULT_DIRECTORY_URL` matches official ZeroSSL ACME endpoint |
| `test_sectigo_client_default_url` | `acme/client.py` | `SectigoAcmeClient.DEFAULT_DIRECTORY_URL` matches official Sectigo ACME endpoint |
| `test_digicert_client_default_url` | `acme/client.py` | `DigiCertAcmeClient.DEFAULT_DIRECTORY_URL` unchanged after refactor |
| `test_eab_subclass_hierarchy` | `acme/client.py` | DigiCert/ZeroSSL/Sectigo all subclass `EabAcmeClient`; `EabAcmeClient` subclasses `AcmeClient` |
| `test_create_account_not_overridden_in_subclasses` | `acme/client.py` | Regression: EAB logic is only in `EabAcmeClient.__dict__`, not duplicated in subclasses |
| `test_make_client_returns_zerossl` | `acme/client.py` | `make_client()` returns `ZeroSSLAcmeClient` when `CA_PROVIDER=zerossl` |
| `test_make_client_returns_sectigo` | `acme/client.py` | `make_client()` returns `SectigoAcmeClient` when `CA_PROVIDER=sectigo` |
| `test_eab_create_account_injects_eab` | `acme/client.py` | `EabAcmeClient.create_account()` injects `externalAccountBinding` when EAB creds are set |
| `test_eab_create_account_omits_eab_when_credentials_empty` | `acme/client.py` | `EabAcmeClient.create_account()` skips EAB when credentials are empty strings |

---

### Unit Tests — Failure Scenarios — `tests/test_unit_failure_scenarios.py`

Error case coverage for ACME protocol failures. No network access required;
all HTTP calls are mocked via the `responses` library.

| Test | Layer | What it verifies |
|---|---|---|
| `test_challenge_failure_invalid_status` | `acme/client.py` → `poll_authorization` | Challenge succeeds but authorization poll returns `status: invalid`; `AcmeError` raised |
| `test_invalid_csr_rejected_by_server` | `acme/client.py` → `finalize_order` | Valid CSR syntax but server rejects with `badCSR` (400); `AcmeError` contains error type |
| `test_bad_nonce_retries_and_succeeds` | `acme/client.py` → `_post_signed` retry logic | First POST returns `badNonce` with fresh nonce; client retries automatically; second attempt succeeds |
| `test_bad_nonce_exhausts_retries` | `acme/client.py` → `_post_signed` retry logic | All 3 attempts return `badNonce`; final attempt (when no retries remain) raises `AcmeError(400, badNonce)` |
| `test_network_timeout_on_directory_fetch` | `acme/client.py` → `get_directory` | `ConnectTimeout` on directory fetch; exception propagates (not suppressed) |
| `test_invalid_directory_url_connection_error` | `acme/client.py` → `get_directory` | Directory URL on unreachable host; `ConnectionError` propagates |
| `test_invalid_directory_url_returns_404` | `acme/client.py` → `get_directory` | Directory URL returns 404; `raise_for_status()` converts to `HTTPError`; exception propagates |

---

### Knowledge Base Tests — `tests/test_kb.py`

Knowledge base indexing and retrieval — no network or external services required.

| Test | Module | What it verifies |
|---|---|---|
| `test_markdown_splits_into_sections` | `kb/chunking.py` | Markdown is split into sections by headings |
| `test_markdown_chunk_contains_full_text` | `kb/chunking.py` | Each chunk contains complete sections (no truncation) |
| `test_python_extracts_top_level_functions` | `kb/chunking.py` | Python files extract top-level function definitions |
| `test_python_extracts_class_overview_and_methods` | `kb/chunking.py` | Python files extract class definitions and their methods |
| `test_search_returns_semantically_relevant_result` | `kb/search.py` | FAISS semantic search returns matching results for keyword queries |

---

### Lifecycle Tests — `tests/test_lifecycle_pebble.py`

Requires Pebble running on `https://localhost:14000`.
When Pebble is not running, these tests are auto-skipped.
LLM nodes (planner, reporter) are mocked — no Anthropic API key needed.

#### `test_certificate_lifecycle`

Full four-step TLS certificate lifecycle:

| Step | Action | Assertion |
|---|---|---|
| **1 · Issue** | Agent runs with no cert on disk | Domain in `completed_renewals`; all PEM files written; `privkey.pem` mode `0o600`; `metadata.json` has `issued_at` / `expires_at` |
| **2 · Expiry detection** | `days_until_expiry()` called on issued cert | Result is positive (cert valid) and less than 9 999 (scanner threshold logic confirmed) |
| **3 · Renew** | Agent re-runs with `renewal_threshold_days=9999` | Domain in `completed_renewals`; new cert has **different serial number** from v1; `metadata.expires_at` updated |
| **4 · Revoke** | `client.revoke_certificate()` called on v2 cert | No `AcmeError` raised (Pebble returns 200); fresh `Replay-Nonce` returned |

#### `test_revoke_original_cert_after_renewal`

| Step | Action | Assertion |
|---|---|---|
| Issue | First agent run | Cert v1 stored |
| Renew | Second run (`threshold=9999`) | Cert v2 replaces v1 on disk |
| Revoke v1 | `revoke_certificate(cert_pem_v1, reason=4)` | Accepted by Pebble (reason 4 = superseded) |

---

### Integration Tests — `tests/test_integration_pebble.py`

Requires Pebble running on `https://localhost:14000`.
When Pebble is not running, these tests are auto-skipped.
Exercises the full LangGraph agent graph end-to-end.

| Test | What it verifies |
|---|---|
| `test_full_renewal_flow` | Happy-path: scanner → planner → account → order → challenge → CSR → finalize → download → storage → reporter. All PEM files written; `privkey.pem` mode `0o600`; metadata populated. |
| `test_second_run_reuses_account` | Second run loads existing account key and calls `POST /newAccount onlyReturnExisting` instead of registering a new account. |
| `test_no_renewal_needed` | When planner returns `skip: [domain]`, `pending_renewals` stays empty; agent exits via `no_renewals` path with empty `completed_renewals` and `failed_renewals`. |

---

## Infrastructure

```
docker compose -f docker-compose.pebble.yml up -d
```

| Service | Image | Port | Config |
|---|---|---|---|
| `pebble` | `ghcr.io/letsencrypt/pebble:latest` | `14000` (ACME) · `15000` (mgmt) | `PEBBLE_VA_NOSLEEP=1` · `PEBBLE_VA_ALWAYS_VALID=1` |

`PEBBLE_VA_ALWAYS_VALID=1` auto-approves all HTTP-01 challenges, so tests run
without real DNS records or port-80 access.
