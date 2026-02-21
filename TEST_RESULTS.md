# Test Results — ACME Certificate Lifecycle Agent

**Date:** 2026-02-21
**Time:** 14:45 UTC
**Platform:** macOS 25.3 · arm64
**Python:** 3.12.8
**Pebble:** Not running (tests auto-skipped)

---

## Summary

| Suite | Tests | Passed | Skipped | Failed | Duration |
|---|---|---|---|---|---|
| Unit (`test_unit_acme.py`) | 18 | 18 | 0 | 0 | — |
| Unit Failure Scenarios (`test_unit_failure_scenarios.py`) | 7 | 7 | 0 | 0 | — |
| Knowledge Base (`test_kb.py`) | 5 | 5 | 0 | 0 | — |
| Lifecycle (`test_lifecycle_pebble.py`) | 2 | 0 | 2 | 0 | — |
| Integration (`test_integration_pebble.py`) | 3 | 0 | 3 | 0 | — |
| **Total** | **35** | **30** | **5** | **0** | **14.65 s** |

---

## Raw Output

```
============================= test session starts ==============================
platform darwin -- Python 3.12.8, pytest-8.3.5, pluggy-1.6.0
rootdir: /Users/debaditya/workspace/Acme_certificate_lifecycle_agent
configfile: pyproject.toml
plugins: anyio-4.12.1, asyncio-0.25.3, langsmith-0.3.45
asyncio: mode=Mode.STRICT
collected 35 items

tests/test_integration_pebble.py::test_full_renewal_flow SKIPPED        [  2%]
tests/test_integration_pebble.py::test_second_run_reuses_account SKIPPED [  5%]
tests/test_integration_pebble.py::test_no_renewal_needed SKIPPED        [  8%]
tests/test_kb.py::test_markdown_splits_into_sections PASSED              [ 11%]
tests/test_kb.py::test_markdown_chunk_contains_full_text PASSED          [ 14%]
tests/test_kb.py::test_python_extracts_top_level_functions PASSED        [ 17%]
tests/test_kb.py::test_python_extracts_class_overview_and_methods PASSED [ 20%]
tests/test_kb.py::test_search_returns_semantically_relevant_result PASSED [ 22%]
tests/test_lifecycle_pebble.py::test_certificate_lifecycle SKIPPED      [ 25%]
tests/test_lifecycle_pebble.py::test_revoke_original_cert_after_renewal SKIPPED [ 28%]
tests/test_unit_acme.py::test_generate_account_key PASSED                [ 31%]
tests/test_unit_acme.py::test_jwk_thumbprint_is_deterministic PASSED     [ 34%]
tests/test_unit_acme.py::test_key_authorization PASSED                   [ 37%]
tests/test_unit_acme.py::test_sign_request_jwk_header PASSED             [ 40%]
tests/test_unit_acme.py::test_sign_request_kid_header PASSED             [ 42%]
tests/test_unit_acme.py::test_save_and_load_account_key PASSED           [ 45%]
tests/test_unit_acme.py::test_rsa_key_generation PASSED                  [ 48%]
tests/test_unit_acme.py::test_private_key_to_pem PASSED                  [ 51%]
tests/test_unit_acme.py::test_create_csr_single_domain PASSED            [ 54%]
tests/test_unit_acme.py::test_create_csr_multi_san PASSED                [ 57%]
tests/test_unit_acme.py::test_get_directory PASSED                       [ 60%]
tests/test_unit_acme.py::test_get_nonce PASSED                           [ 62%]
tests/test_unit_acme.py::test_create_account_without_eab PASSED          [ 65%]
tests/test_unit_acme.py::test_create_order PASSED                        [ 68%]
tests/test_unit_acme.py::test_poll_authorization_valid PASSED            [ 71%]
tests/test_unit_acme.py::test_poll_authorization_invalid_raises PASSED   [ 74%]
tests/test_unit_acme.py::test_acme_error_on_non_2xx PASSED               [ 77%]
tests/test_unit_acme.py::test_revoke_certificate PASSED                  [ 80%]
tests/test_unit_failure_scenarios.py::test_challenge_failure_invalid_status PASSED [ 82%]
tests/test_unit_failure_scenarios.py::test_invalid_csr_rejected_by_server PASSED [ 85%]
tests/test_unit_failure_scenarios.py::test_bad_nonce_retries_and_succeeds PASSED [ 88%]
tests/test_unit_failure_scenarios.py::test_bad_nonce_exhausts_retries PASSED [ 91%]
tests/test_unit_failure_scenarios.py::test_network_timeout_on_directory_fetch PASSED [ 94%]
tests/test_unit_failure_scenarios.py::test_invalid_directory_url_connection_error PASSED [ 97%]
tests/test_unit_failure_scenarios.py::test_invalid_directory_url_returns_404 PASSED [100%]

======================== 30 passed, 5 skipped in 14.65s ========================
```

---

## Test Descriptions

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
