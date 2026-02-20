# Test Results — ACME Certificate Lifecycle Agent

**Date:** 2026-02-20
**Time:** 17:35 UTC
**Platform:** macOS 26.3 · arm64
**Python:** 3.12.8
**Pebble:** Running (`ghcr.io/letsencrypt/pebble:latest`, `PEBBLE_VA_ALWAYS_VALID=1`)

---

## Summary

| Suite | Tests | Passed | Skipped | Failed | Duration |
|---|---|---|---|---|---|
| Unit (`test_unit_acme.py`) | 18 | 18 | 0 | 0 | — |
| Lifecycle (`test_lifecycle_pebble.py`) | 2 | 2 | 0 | 0 | — |
| Integration (`test_integration_pebble.py`) | 3 | 3 | 0 | 0 | — |
| **Total** | **23** | **23** | **0** | **0** | **9.18 s** |

---

## Raw Output

```
============================= test session starts ==============================
platform darwin -- Python 3.12.8, pytest-8.3.5, pluggy-1.6.0
rootdir: /Users/debaditya/workspace/Acme_certificate_lifecycle_agent
configfile: pyproject.toml
plugins: anyio-4.12.1, asyncio-0.25.3, langsmith-0.3.45
asyncio: mode=Mode.STRICT
collected 23 items

tests/test_integration_pebble.py::test_full_renewal_flow PASSED          [  4%]
tests/test_integration_pebble.py::test_second_run_reuses_account PASSED  [  8%]
tests/test_integration_pebble.py::test_no_renewal_needed PASSED          [ 13%]
tests/test_lifecycle_pebble.py::test_certificate_lifecycle PASSED        [ 17%]
tests/test_lifecycle_pebble.py::test_revoke_original_cert_after_renewal PASSED [ 21%]
tests/test_unit_acme.py::test_generate_account_key PASSED                [ 26%]
tests/test_unit_acme.py::test_jwk_thumbprint_is_deterministic PASSED     [ 30%]
tests/test_unit_acme.py::test_key_authorization PASSED                   [ 34%]
tests/test_unit_acme.py::test_sign_request_jwk_header PASSED             [ 39%]
tests/test_unit_acme.py::test_sign_request_kid_header PASSED             [ 43%]
tests/test_unit_acme.py::test_save_and_load_account_key PASSED           [ 47%]
tests/test_unit_acme.py::test_rsa_key_generation PASSED                  [ 52%]
tests/test_unit_acme.py::test_private_key_to_pem PASSED                  [ 56%]
tests/test_unit_acme.py::test_create_csr_single_domain PASSED            [ 60%]
tests/test_unit_acme.py::test_create_csr_multi_san PASSED                [ 65%]
tests/test_unit_acme.py::test_get_directory PASSED                       [ 69%]
tests/test_unit_acme.py::test_get_nonce PASSED                           [ 73%]
tests/test_unit_acme.py::test_create_account_without_eab PASSED          [ 78%]
tests/test_unit_acme.py::test_create_order PASSED                        [ 82%]
tests/test_unit_acme.py::test_poll_authorization_valid PASSED            [ 86%]
tests/test_unit_acme.py::test_poll_authorization_invalid_raises PASSED   [ 91%]
tests/test_unit_acme.py::test_acme_error_on_non_2xx PASSED               [ 95%]
tests/test_unit_acme.py::test_revoke_certificate PASSED                  [100%]

============================== 23 passed in 9.18s ===========================
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

### Lifecycle Tests — `tests/test_lifecycle_pebble.py`

Requires Pebble running on `https://localhost:14000`.
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
