# CI Test Coverage

This document describes what the GitHub Actions workflow runs on every push and
pull request to `main`, and analyses whether Pebble integration tests can be
added.

---

## Workflow: `.github/workflows/tests.yml`

Trigger: every push and PR targeting `main`.
Runner: `ubuntu-latest`.
Container: `python:3.12-slim-bookworm` — all steps execute inside this image,
giving a minimal and reproducible Debian Bookworm environment with Python 3.12
pre-installed. Git is installed before checkout since the slim image omits it.
Toolchain: `uv` via `astral-sh/setup-uv` (no `python-version` override —
container already owns Python 3.12).

### Command

```bash
uv run pytest -v \
  --ignore=tests/test_revocation_pebble.py \
  --ignore=tests/test_integration_pebble.py \
  --ignore=tests/test_lifecycle_pebble.py \
  --ignore=tests/test_kb.py
```

**218 tests, 0 skips, no external services required.**

---

## Tests Currently in CI (218 total)

### `tests/test_unit_acme.py` — 55 tests
Core ACME RFC 8555 protocol layer. All HTTP calls mocked with the `responses`
library; no network access needed.

| Group | Tests | What is verified |
|---|---|---|
| JWS signing — Case A | `test_sign_request_jwk_header` | protected header has `jwk`, no `kid`; payload round-trips via base64url |
| JWS signing — Case B | `test_sign_request_kid_header` | protected header has `kid`, no `jwk` |
| JWS signing — Case C | `test_sign_request_post_as_get_signature_is_valid` | `payload == ""` (RFC 8555 §6.3); RS256 signature cryptographically valid |
| JWS input guards | `test_sign_request_rejects_empty_nonce` / `_whitespace_nonce` | `ValueError` on empty / whitespace nonce |
| JWS input guards | `test_sign_request_rejects_empty_url` / `_whitespace_url` | `ValueError` on empty / whitespace URL |
| RFC 7638 thumbprint | `test_jwk_thumbprint_rfc7638_canonical_*` | canonical form is `{e,kty,n}` alphabetical, no padding |
| RFC 7638 thumbprint | `test_jwk_thumbprint_matches_independent_rfc7638_computation` | independent SHA-256 digest matches `compute_jwk_thumbprint()` |
| RFC 7638 thumbprint | `test_jwk_thumbprint_differs_when_extra_fields_included` | adding `alg` field changes digest |
| Key auth | `test_compute_key_authorization` | `token.thumbprint` format |
| Account key I/O | `test_save_and_load_account_key` | file mode `0o600`; thumbprint survives round-trip |
| Crypto | `test_rsa_key_generation`, `test_private_key_to_pem` | RSA-2048, PEM headers |
| CSR | `test_create_csr_single_domain`, `_multi_san` | SAN list correct |
| Directory / nonce | `test_get_directory`, `test_get_nonce` | mocked HTTP GET |
| POST-as-GET compliance | `test_post_as_get_*`, `test_post_with_payload_vs_post_as_get` | RFC 8555 §6.2 POST-as-GET |
| Account ops | `test_create_account_*`, `test_lookup_account_*` | 200 happy path + 404 miss + 400 error |
| Order / auth | `test_create_order`, `test_poll_authorization_*` | order creation, valid vs invalid auth |
| Error handling | `test_acme_error_on_non_2xx` | `AcmeError` raised |
| Revocation | `test_revoke_certificate`, `test_revoke_certificate_invalid_reason_*` | reason code validation (0–10 allowed) |
| CA hierarchy | `test_zerossl_*`, `test_sectigo_*`, `test_digicert_*`, `test_eab_subclass_*` | class URLs, EAB inheritance |
| Factory | `test_make_client_returns_zerossl`, `_sectigo` | `make_client()` dispatch |
| EAB account | `test_eab_create_account_injects_eab`, `_omits_eab_when_credentials_empty` | EAB injection logic |
| EAB JWS guards | `test_eab_jws_rejects_*`, `_succeeds_*`, `_minimum_*` | input validation, minimum 16-byte HMAC |
| Config EAB | `test_config_rejects_partial_*`, `_accepts_*` | Pydantic validator for partial EAB config |

---

### `tests/test_unit_failure_scenarios.py` — 9 tests
Protocol error paths; all HTTP mocked.

| Test | What is verified |
|---|---|
| `test_challenge_failure_invalid_status` | `invalid` challenge status raises `AcmeError` |
| `test_invalid_csr_rejected_by_server` | 400 on finalize raises `AcmeError` |
| `test_bad_nonce_retries_and_succeeds` | `badNonce` triggers retry with fresh nonce |
| `test_bad_nonce_exhausts_retries` | retry cap raises `AcmeError` |
| `test_network_timeout_on_directory_fetch` | `ConnectionError` on directory |
| `test_invalid_directory_url_connection_error` | bad URL raises `ConnectionError` |
| `test_invalid_directory_url_returns_404` | 404 directory raises `AcmeError` |
| `test_finalize_order_malformed_json_response` | malformed body raises `AcmeError` |
| `test_rate_limit_429_with_retry_after` | 429 raises `AcmeError` |

---

### `tests/test_dns_challenge.py` — 51 tests
DNS-01 challenge provider layer; all cloud SDK calls mocked.

| Group | Tests | What is verified |
|---|---|---|
| TXT value computation | 8 tests | known RFC vector, no padding, determinism, base64url, 43-char fixed length |
| Provider factory | 7 tests | Cloudflare / Route53 / Google dispatch; unknown provider error; import-error hints |
| Cloudflare provider | 6 tests | create (explicit zone, auto-discover, idempotent), delete (found, error, missing) |
| Route53 provider | 5 tests | UPSERT with quotes, explicit zone, auto-discover, DELETE action, error swallowed |
| Google Cloud DNS | 6 tests | add+create, delete+create, error swallowed, idempotent same value, replace different value, no-existing |
| Order node (dns-01) | 5 tests | challenge type selection, `auth_domains`, `dns_txt_values` populated, http-01 leaves empty, missing challenge error |
| Challenge setup | 4 tests | `create_txt_record` called per domain, propagation sleep called/skipped |
| Challenge cleanup | 3 tests | `delete_txt_record` called per domain, continues on partial failure, safe with no provider |
| Config validation | 7 tests | `dns` mode accepted, invalid mode rejected, Cloudflare token required, Google project-id required, Route53 no mandatory fields, standalone/webroot unchanged |

---

### `tests/test_planner_validation.py` — 12 tests
LLM output validation; no LLM calls made (direct function tests + mocked LLM).

| Test | What is verified |
|---|---|
| `test_invalid_json_falls_back_to_renew_all` | malformed JSON → all domains queued |
| `test_hallucinated_domain_in_{urgent,routine,skip}_stripped` | invented domain stripped from every bucket |
| `test_mixed_real_and_hallucinated_preserves_real` | real domains pass through |
| `test_lookalike_domain_stripped` | `evil.example.com` stripped when only `example.com` is managed |
| `test_missing_domain_added_to_routine` | domain absent from LLM output added to routine queue |
| `test_all_missing_domains_added_to_routine` | all domains fall back to routine if LLM omits all |
| `test_all_hallucinated_triggers_missing_domain_fallback` | all-hallucinated response → managed domains queued |
| `test_planner_node_strips_hallucinated_from_pending_renewals` | full planner node integration |
| `test_planner_node_invalid_json_queues_all_domains` | node-level fallback |
| `test_planner_node_urgent_before_routine_in_pending` | urgent domains precede routine |

---

### `tests/test_revocation.py` — 15 tests
Revocation subgraph; no ACME server required (mocked).

| Group | Tests | What is verified |
|---|---|---|
| Router | 3 tests | picks next domain, handles last domain, handles empty target list |
| Loop router | 2 tests | routes to revoker when targets remain, to reporter when done |
| Revoker node | 3 tests | successful revocation, missing cert file, `AcmeError` handling |
| Reporter | 3 tests | LLM summary on success, summary with failures, LLM call failure graceful |
| Graph topology | 1 test | graph compiles with expected node set |
| Full graph flow | 3 tests | single-domain flow, multi-domain flow, partial failure tracking |

---

### `tests/test_checkpoint.py` — 10 tests
LangGraph `MemorySaver` checkpoint mechanics; all ACME nodes mocked.

| Group | Tests | What is verified |
|---|---|---|
| Basic | 2 tests | completed run creates checkpoint; checkpoint history non-empty |
| Interrupt / resume | 3 tests | interrupt before account setup; resume completes; interrupt before challenge verifier |
| State integrity | 3 tests | config fields preserved; completed renewals in final state; messages accumulate |
| Thread isolation | 1 test | two `thread_id` values produce independent state |
| Advanced | 1 test | `update_state` injects domain before resume |

---

### `tests/test_atomic_writes.py` — 12 tests
`storage/atomic.py` — crash-safe PEM file writes.

| Group | Tests | What is verified |
|---|---|---|
| Text writes | 5 tests | creates file, overwrites, no temp file left, creates parent dirs, cleans up temp on error |
| Bytes writes | 4 tests | creates file, overwrites, no temp file left, large file (1 MB) |
| Integration | 3 tests | PEM round-trip, multiple writes same dir, concurrent writes different files |

---

### `tests/test_ca_detection.py` — 32 tests
CA detection from X.509 issuer fields; no network calls (synthetic certs built in-process).

| Group | Tests | What is verified |
|---|---|---|
| `detect_ca_from_cert()` — known CAs | 8 tests | Let's Encrypt, Let's Encrypt staging, DigiCert, ZeroSSL, Sectigo (no AIA), Sectigo (Sectigo OCSP), Sectigo (ZeroSSL OCSP), COMODO legacy with ZeroSSL OCSP |
| `detect_ca_from_cert()` — fallback | 3 tests | unknown issuer org returns `None`; invalid/empty PEM returns `None`; cert with no O field returns `None` |
| Internal helpers | 4 tests | `_get_issuer_org` present/absent; `_get_ocsp_url` present/absent |
| `detect_ca_for_domain()` | 4 tests | metadata `ca_provider` takes precedence; falls back to cert inspection; falls back when metadata lacks `ca_provider`; unknown CA returns `None` |
| `write_cert_files()` metadata | 2 tests | `ca_provider` written to `metadata.json`; defaults to empty string when omitted |
| `_warn_if_ca_mismatch()` | 6 tests | no warning when detected is `None`; no warning on match; letsencrypt/staging treated as equivalent (both directions); warning logged on real mismatch; domain name included in warning |
| Scanner integration | 4 tests | no cert → `detected_ca_provider` is `None`; cert present → provider populated; mismatch triggers warning; matching CAs suppress warning |

---

## Tests Excluded from CI

| File | Count | Reason excluded |
|---|---|---|
| `tests/test_integration_pebble.py` | 4 | Requires Pebble ACME stub server |
| `tests/test_lifecycle_pebble.py` | 2 | Requires Pebble ACME stub server |
| `tests/test_revocation_pebble.py` | 3 | Requires Pebble ACME stub server |
| `tests/test_kb.py` | variable | Requires `faiss-cpu` + `sentence-transformers` (not in `requirements.txt`) |

**Pebble total: 9 tests.**

---

## Can We Add Pebble Tests to CI?

### What Pebble tests do

The 9 Pebble tests exercise the **complete agent end-to-end** against
[`ghcr.io/letsencrypt/pebble`](https://github.com/letsencrypt/pebble), a
lightweight ACME test server. With `PEBBLE_VA_ALWAYS_VALID=1` set, it
auto-approves all challenges — no real DNS or port-80 access needed.

Tests covered:

| Test | Scenario |
|---|---|
| `test_full_renewal_flow` | HTTP-01 happy path: all 11 agent nodes execute |
| `test_second_run_reuses_account` | Account key persisted; second run skips `newAccount` |
| `test_no_renewal_needed` | Scanner detects valid cert; planner skips renewal |
| `test_full_renewal_flow_dns01` | DNS-01 happy path with mocked Cloudflare provider |
| `test_certificate_lifecycle` | Issue → read cert → confirm SAN list |
| `test_revoke_original_cert_after_renewal` | Renew then revoke old cert |
| `test_revocation_graph_basic_against_pebble` | Revocation subgraph happy path |
| `test_revocation_reason_codes_against_pebble` | Reason codes 0, 1, 4, 5 accepted |
| `test_revocation_nonexistent_cert_against_pebble` | Revoke non-existent cert: graceful failure |

### Feasibility

**Yes — adding Pebble tests to CI is feasible.** GitHub Actions supports
Docker Compose service containers, which is exactly what Pebble requires.

### What needs to change

**1. Add a `services:` block to the workflow**

```yaml
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    ports:
      - 14000:14000
      - 15000:15000
    env:
      PEBBLE_VA_NOSLEEP: "1"
      PEBBLE_VA_ALWAYS_VALID: "1"
```

**2. Wait for Pebble to be ready**

Add a health-check step before running Pebble tests:

```yaml
- name: Wait for Pebble
  run: |
    for i in $(seq 1 15); do
      curl -sk https://localhost:14000/dir && break
      sleep 1
    done
```

**3. Run Pebble tests as a separate job (or separate step)**

Keep the existing `--ignore` flags for the unit-test step unchanged.
Add a second step (or second job) that includes the Pebble tests:

```yaml
- name: Run Pebble integration tests
  run: |
    uv run pytest tests/test_integration_pebble.py \
                  tests/test_lifecycle_pebble.py \
                  tests/test_revocation_pebble.py -v
  env:
    CA_PROVIDER: custom
    ACME_DIRECTORY_URL: https://localhost:14000/dir
    ACME_INSECURE: "true"
    MANAGED_DOMAINS: acme-test.localhost
    HTTP_CHALLENGE_MODE: webroot
    WEBROOT_PATH: /tmp/pebble-webroot
    CERT_STORE_PATH: /tmp/pebble-certs
    ACCOUNT_KEY_PATH: /tmp/pebble-account.key
    ANTHROPIC_API_KEY: dummy-key-for-testing
    MAX_RETRIES: "2"
```

**4. `ACME_INSECURE` on the runner**

Pebble uses a self-signed certificate. The `ACME_INSECURE=true` env var tells
`AcmeClient` to use `verify=False` on requests. This is already supported and
safe in a CI-only context.

### Residual risk / caveats

| Item | Detail |
|---|---|
| Pebble image availability | `ghcr.io/letsencrypt/pebble:latest` is public; no auth needed |
| TLS self-signed cert | Handled by `ACME_INSECURE=true`; not a concern in CI |
| `test_full_renewal_flow_dns01` | Uses mocked Cloudflare SDK — no real DNS; works without changes |
| Port conflicts | Pebble binds 14000 + 15000; standard GitHub runners have no conflicts |
| `requires_pebble` decorator | Automatically skips if port 14000 unreachable; safe to leave in place |
| Flakiness | Pebble with `PEBBLE_VA_ALWAYS_VALID=1` is deterministic; historically stable in CI |
| No slim container for Pebble job | GitHub `services:` containers require the job to run directly on the runner host (not inside a container job) for Docker networking to resolve correctly. The Pebble job uses `ubuntu-latest` + `python-version: "3.12"` via uv instead of `python:3.12-slim-bookworm`. |

### Recommended implementation

Add the Pebble block as a **second job** (`pebble-integration`) in the same
workflow file, with `needs: [test]` so it only runs when the unit tests pass.
This keeps the failure signal clean: unit-test failures surface immediately
without waiting for Pebble to start.

```yaml
pebble-integration:
  needs: [test]
  runs-on: ubuntu-latest
  # No container: block here — service containers (Pebble) require the job to
  # run directly on the runner host so Docker networking resolves correctly.

  services:
    pebble:
      image: ghcr.io/letsencrypt/pebble:latest
      ports:
        - 14000:14000
        - 15000:15000
      env:
        PEBBLE_VA_NOSLEEP: "1"
        PEBBLE_VA_ALWAYS_VALID: "1"

  steps:
    - uses: actions/checkout@v4

    - name: Install uv
      uses: astral-sh/setup-uv@v5
      with:
        enable-cache: true
        python-version: "3.12"   # managed by uv here; no slim container

    - name: Install dependencies
      run: uv sync

    - name: Wait for Pebble
      run: |
        for i in $(seq 1 15); do
          curl -sk https://localhost:14000/dir && echo && break
          sleep 1
        done

    - name: Run Pebble integration tests
      env:
        CA_PROVIDER: custom
        ACME_DIRECTORY_URL: https://localhost:14000/dir
        ACME_INSECURE: "true"
        MANAGED_DOMAINS: acme-test.localhost
        HTTP_CHALLENGE_MODE: webroot
        WEBROOT_PATH: /tmp/pebble-webroot
        CERT_STORE_PATH: /tmp/pebble-certs
        ACCOUNT_KEY_PATH: /tmp/pebble-account.key
        ANTHROPIC_API_KEY: dummy-key-for-testing
        MAX_RETRIES: "2"
      run: |
        uv run pytest tests/test_integration_pebble.py \
                      tests/test_lifecycle_pebble.py \
                      tests/test_revocation_pebble.py -v
```

This adds **9 real end-to-end tests** to CI with no changes to the existing
unit-test job.
