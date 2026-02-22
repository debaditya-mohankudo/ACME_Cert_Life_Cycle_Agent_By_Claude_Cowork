# Test Results — ACME Certificate Lifecycle Agent

**Date:** 2026-02-22
**Time:** Latest run
**Platform:** macOS 25.3 · arm64
**Python:** 3.12.8
**Pebble:** Running (all integration tests executed and passed)

---

## Summary

| Suite | Tests | Passed | Skipped | Failed | Duration |
|---|---|---|---|---|---|
| Atomic Writes (`test_atomic_writes.py`) | 12 | 12 | 0 | 0 | — |
| Checkpoint (`test_checkpoint.py`) | 10 | 10 | 0 | 0 | — |
| DNS-01 Challenge (`test_dns_challenge.py`) | 51 | 51 | 0 | 0 | — |
| Unit (`test_unit_acme.py`) | 30 | 30 | 0 | 0 | — |
| Unit Failure Scenarios (`test_unit_failure_scenarios.py`) | 9 | 9 | 0 | 0 | — |
| Retry Scheduler (`test_retry_scheduler.py`) | 11 | 11 | 0 | 0 | — |
| Knowledge Base (`test_kb.py`) | 5 | 5 | 0 | 0 | — |
| Planner Validation (`test_planner_validation.py`) | 12 | 12 | 0 | 0 | — |
| Lifecycle Pebble (`test_lifecycle_pebble.py`) | 2 | 2 | 0 | 0 | — |
| Integration Pebble (`test_integration_pebble.py`) | 4 | 4 | 0 | 0 | — |
| Revocation (`test_revocation.py`) | 15 | 15 | 0 | 0 | — |
| Revocation Pebble (`test_revocation_pebble.py`) | 3 | 3 | 0 | 0 | — |
| **Total (with Pebble)** | **175** | **175** | **0** | **0** | **37.12 s** |

---

## Recent Improvements (2026-02-22)

### Full Test Suite with Pebble Integration (Latest)
- **175 total tests passing** including all Pebble integration tests
  - 166 unit tests (no Pebble required)
  - 4 integration tests (HTTP-01 and DNS-01 renewal flows)
  - 2 lifecycle tests (certificate issue → renew → revoke)
  - 3 revocation tests (certificate revocation against Pebble)
- All tests execute in 37.12 seconds with Pebble running

### POST-as-GET Compliance Tests
- **3 new tests for RFC 8555 §6.2 POST-as-GET verification**:
  - `test_post_as_get_empty_payload_jws()` — Verifies `_post_signed(None, ...)` produces JWS with empty payload field
  - `test_post_as_get_sign_request_compliance()` — Validates JWS structure for POST-as-GET requests (protected header, empty payload, signature)
  - `test_post_with_payload_vs_post_as_get()` — Contrasts normal POST (with payload) vs POST-as-GET (empty payload) to ensure both work correctly
- Total unit tests now: 30 (27 previous + 3 new POST-as-GET)

---

## Raw Output

```
============================= test session starts ==============================
platform darwin -- Python 3.12.8, pytest-9.0.2, pluggy-1.6.0 -- /Users/debaditya/workspace/Acme_certificate_lifecycle_agent/.venv/bin/python3
rootdir: /Users/debaditya/workspace/Acme_certificate_lifecycle_agent
configfile: pyproject.toml
plugins: anyio-4.12.1, langsmith-0.7.6, asyncio-1.3.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None
collected 175 items

tests/test_atomic_writes.py::TestAtomicWriteText::test_atomic_write_text_creates_file PASSED [  0%]
tests/test_atomic_writes.py::TestAtomicWriteText::test_atomic_write_text_overwrites_existing PASSED [  1%]
tests/test_atomic_writes.py::TestAtomicWriteText::test_atomic_write_text_no_temp_file_left PASSED [  1%]
tests/test_atomic_writes.py::TestAtomicWriteText::test_atomic_write_text_creates_parent_dirs PASSED [  2%]
tests/test_atomic_writes.py::TestAtomicWriteText::test_atomic_write_text_cleans_up_temp_on_error PASSED [  3%]
tests/test_atomic_writes.py::TestAtomicWriteBytes::test_atomic_write_bytes_creates_file PASSED [  3%]
tests/test_atomic_writes.py::TestAtomicWriteBytes::test_atomic_write_bytes_overwrites_existing PASSED [  4%]
tests/test_atomic_writes.py::TestAtomicWriteBytes::test_atomic_write_bytes_no_temp_file_left PASSED [  5%]
tests/test_atomic_writes.py::TestAtomicWriteBytes::test_atomic_write_bytes_large_file PASSED [  5%]
tests/test_atomic_writes.py::TestAtomicWriteIntegration::test_pem_file_atomic_write_text PASSED [  6%]
tests/test_atomic_writes.py::TestAtomicWriteIntegration::test_multiple_atomic_writes_to_same_dir PASSED [  7%]
tests/test_atomic_writes.py::TestAtomicWriteIntegration::test_concurrent_writes_to_different_files PASSED [  7%]
tests/test_checkpoint.py::TestBasicCheckpointing::test_complete_run_creates_checkpoint PASSED [  8%]
tests/test_checkpoint.py::TestBasicCheckpointing::test_checkpoint_history_non_empty PASSED [  9%]
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_acme_account_setup PASSED [  9%]
tests/test_checkpoint.py::TestInterruptResume::test_resume_after_interrupt_completes PASSED [ 10%]
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_challenge_verifier PASSED [ 10%]
tests/test_checkpoint.py::TestStateIntegrity::test_critical_config_fields_preserved_through_checkpoint PASSED [ 11%]
tests/test_checkpoint.py::TestStateIntegrity::test_completed_renewals_in_final_checkpoint PASSED [ 12%]
tests/test_checkpoint.py::TestStateIntegrity::test_messages_accumulate_across_checkpoints PASSED [ 12%]
tests/test_checkpoint.py::TestThreadIsolation::test_two_threads_are_independent PASSED [ 13%]
tests/test_checkpoint.py::TestAdvancedCheckpoint::test_update_state_injects_domain_before_resume PASSED [ 14%]
tests/test_dns_challenge.py::TestComputeDnsTxtValue::test_known_vector PASSED [ 14%]
tests/test_dns_challenge.py::TestComputeDnsTxtValue::test_no_padding PASSED [ 15%]
tests/test_dns_challenge.py::TestComputeDnsTxtValue::test_deterministic PASSED [ 16%]
tests/test_dns_challenge.py::TestComputeDnsTxtValue::test_different_inputs_produce_different_outputs PASSED [ 16%]
tests/test_dns_challenge.py::TestComputeDnsTxtValue::test_output_is_valid_base64url PASSED [ 17%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_dispatches_cloudflare PASSED [ 18%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_dispatches_route53 PASSED [ 18%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_dispatches_google PASSED [ 19%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_unknown_provider_raises PASSED [ 20%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_cloudflare_importerror_hint PASSED [ 20%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_route53_importerror_hint PASSED [ 21%]
tests/test_dns_challenge.py::TestMakeDnsProvider::test_google_importerror_hint PASSED [ 21%]
tests/test_dns_challenge.py::TestCloudflareDnsProvider::test_create_txt_record_explicit_zone PASSED [ 22%]
tests/test_dns_challenge.py::TestCloudflareDnsProvider::test_create_txt_record_auto_discover_zone PASSED [ 23%]
tests/test_dns_challenge.py::TestCloudflareDnsProvider::test_create_txt_record_idempotent PASSED [ 23%]
tests/test_dns_challenge.py::TestCloudflareDnsProvider::test_delete_txt_record_finds_and_deletes PASSED [ 24%]
tests/test_dns_challenge.py::TestCloudflareDnsProvider::test_delete_txt_record_swallows_errors PASSED [ 25%]
tests/test_dns_challenge.py::TestCloudflareDnsProvider::test_delete_txt_record_missing_record_silent PASSED [ 25%]
tests/test_dns_challenge.py::TestRoute53DnsProvider::test_create_txt_record_upsert_with_quotes PASSED [ 26%]
tests/test_dns_challenge.py::TestRoute53DnsProvider::test_create_txt_record_uses_explicit_zone_id PASSED [ 27%]
tests/test_dns_challenge.py::TestRoute53DnsProvider::test_create_txt_record_auto_discover_zone PASSED [ 27%]
tests/test_dns_challenge.py::TestRoute53DnsProvider::test_delete_txt_record_uses_delete_action PASSED [ 28%]
tests/test_dns_challenge.py::TestRoute53DnsProvider::test_delete_txt_record_swallows_errors PASSED [ 29%]
tests/test_dns_challenge.py::TestGoogleCloudDnsProvider::test_create_txt_record_calls_add_and_create PASSED [ 29%]
tests/test_dns_challenge.py::TestGoogleCloudDnsProvider::test_delete_txt_record_calls_delete_and_create PASSED [ 30%]
tests/test_dns_challenge.py::TestGoogleCloudDnsProvider::test_delete_txt_record_swallows_errors PASSED [ 30%]
tests/test_dns_challenge.py::TestOrderInitializerDns01::test_dns01_challenge_selected PASSED [ 31%]
tests/test_dns_challenge.py::TestOrderInitializerDns01::test_dns01_populates_auth_domains PASSED [ 32%]
tests/test_dns_challenge.py::TestOrderInitializerDns01::test_dns01_populates_dns_txt_values PASSED [ 32%]
tests/test_dns_challenge.py::TestOrderInitializerDns01::test_http01_dns_txt_values_empty PASSED [ 33%]
tests/test_dns_challenge.py::TestOrderInitializerDns01::test_missing_dns01_challenge_returns_error PASSED [ 34%]
tests/test_dns_challenge.py::TestChallengeSetupDns::test_create_txt_record_called_for_each_domain PASSED [ 34%]
tests/test_dns_challenge.py::TestChallengeSetupDns::test_propagation_sleep_called_when_positive PASSED [ 35%]
tests/test_dns_challenge.py::TestChallengeSetupDns::test_propagation_sleep_skipped_when_zero PASSED [ 36%]
tests/test_dns_challenge.py::TestChallengeSetupDns::test_returns_empty_dict PASSED [ 36%]
tests/test_dns_challenge.py::TestCleanupChallengeDns::test_delete_called_for_each_domain PASSED [ 37%]
tests/test_dns_challenge.py::TestCleanupChallengeDns::test_continues_on_partial_failure PASSED [ 38%]
tests/test_dns_challenge.py::TestCleanupChallengeDns::test_safe_when_no_provider PASSED [ 38%]
tests/test_dns_challenge.py::TestConfigValidation::test_dns_mode_accepted PASSED [ 39%]
tests/test_dns_challenge.py::TestConfigValidation::test_invalid_mode_rejected PASSED [ 40%]
tests/test_dns_challenge.py::TestConfigValidation::test_cloudflare_missing_token_raises PASSED [ 40%]
tests/test_dns_challenge.py::TestConfigValidation::test_google_missing_project_id_raises PASSED [ 41%]
tests/test_dns_challenge.py::TestConfigValidation::test_route53_no_mandatory_fields PASSED [ 41%]
tests/test_dns_challenge.py::TestConfigValidation::test_standalone_mode_unchanged PASSED [ 42%]
tests/test_dns_challenge.py::TestConfigValidation::test_webroot_mode_unchanged PASSED [ 43%]
tests/test_integration_pebble.py::test_full_renewal_flow PASSED          [ 43%]
tests/test_integration_pebble.py::test_second_run_reuses_account PASSED  [ 44%]
tests/test_integration_pebble.py::test_no_renewal_needed PASSED          [ 45%]
tests/test_integration_pebble.py::test_full_renewal_flow_dns01 PASSED    [ 45%]
tests/test_kb.py::test_markdown_splits_into_sections PASSED              [ 46%]
tests/test_kb.py::test_markdown_chunk_contains_full_text PASSED          [ 47%]
tests/test_kb.py::test_python_extracts_top_level_functions PASSED        [ 47%]
tests/test_kb.py::test_python_extracts_class_overview_and_methods PASSED [ 48%]
tests/test_kb.py::test_search_returns_semantically_relevant_result PASSED [ 49%]
tests/test_lifecycle_pebble.py::test_certificate_lifecycle PASSED        [ 49%]
tests/test_lifecycle_pebble.py::test_revoke_original_cert_after_renewal PASSED [ 50%]
tests/test_planner_validation.py::TestParseAndValidate::test_invalid_json_falls_back_to_renew_all PASSED [ 50%]
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_urgent_stripped PASSED [ 51%]
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_routine_stripped PASSED [ 52%]
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_skip_stripped PASSED [ 52%]
tests/test_planner_validation.py::TestParseAndValidate::test_mixed_real_and_hallucinated_preserves_real PASSED [ 53%]
tests/test_planner_validation.py::TestParseAndValidate::test_lookalike_domain_stripped PASSED [ 54%]
tests/test_planner_validation.py::TestParseAndValidate::test_missing_domain_added_to_routine PASSED [ 54%]
tests/test_planner_validation.py::TestParseAndValidate::test_all_missing_domains_added_to_routine PASSED [ 55%]
tests/test_planner_validation.py::TestParseAndValidate::test_all_hallucinated_triggers_missing_domain_fallback PASSED [ 56%]
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_strips_hallucinated_from_pending_renewals PASSED [ 56%]
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_invalid_json_queues_all_domains PASSED [ 57%]
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_urgent_before_routine_in_pending PASSED [ 58%]
tests/test_retry_scheduler.py::TestRetrySchedulerSync::test_no_scheduled_retry_passes_through PASSED [ 58%]
tests/test_retry_scheduler.py::TestRetrySchedulerSync::test_past_retry_time_doesnt_wait PASSED [ 59%]
tests/test_retry_scheduler.py::TestRetrySchedulerSync::test_future_retry_time_waits PASSED [ 60%]
tests/test_retry_scheduler.py::TestRetrySchedulerSync::test_clears_retry_not_before PASSED [ 60%]
tests/test_retry_scheduler.py::TestRetrySchedulerSync::test_long_backoff PASSED [ 61%]
tests/test_retry_scheduler.py::TestRetrySchedulerAsync::test_async_no_scheduled_retry PASSED [ 61%]
tests/test_retry_scheduler.py::TestRetrySchedulerAsync::test_async_past_retry_time_doesnt_wait PASSED [ 62%]
tests/test_retry_scheduler.py::TestRetrySchedulerAsync::test_async_future_retry_time_waits PASSED [ 63%]
tests/test_retry_scheduler.py::TestRetrySchedulerAsync::test_async_non_blocking_during_backoff PASSED [ 63%]
tests/test_retry_scheduler.py::TestRetrySchedulerIntegration::test_retry_scheduler_with_error_handler_state PASSED [ 64%]
tests/test_retry_scheduler.py::TestRetrySchedulerIntegration::test_multiple_domain_retries_concurrent PASSED [ 65%]
tests/test_revocation.py::test_pick_next_revocation_domain_pops_first_domain PASSED [ 65%]
tests/test_revocation.py::test_pick_next_revocation_domain_last_domain PASSED [ 66%]
tests/test_revocation.py::test_pick_next_revocation_domain_empty_targets PASSED [ 67%]
tests/test_revocation.py::test_revocation_loop_router_more_targets PASSED [ 67%]
tests/test_revocation.py::test_revocation_loop_router_no_targets PASSED  [ 68%]
tests/test_revocation.py::test_cert_revoker_success PASSED               [ 69%]
tests/test_revocation.py::test_cert_revoker_missing_cert PASSED          [ 69%]
tests/test_revocation.py::test_cert_revoker_acme_error PASSED            [ 70%]
tests/test_revocation.py::test_revocation_reporter_success PASSED        [ 70%]
tests/test_revocation.py::test_revocation_reporter_with_failures PASSED  [ 71%]
tests/test_revocation.py::test_revocation_reporter_llm_failure PASSED    [ 72%]
tests/test_revocation.py::test_revocation_graph_topology PASSED          [ 72%]
tests/test_revocation.py::test_revocation_graph_single_domain_flow PASSED [ 73%]
tests/test_revocation.py::test_revocation_graph_multi_domain_flow PASSED [ 74%]
tests/test_revocation.py::test_revocation_graph_partial_failure PASSED   [ 74%]
tests/test_revocation_pebble.py::test_revocation_graph_basic_against_pebble PASSED [ 75%]
tests/test_revocation_pebble.py::test_revocation_reason_codes_against_pebble PASSED [ 76%]
tests/test_revocation_pebble.py::test_revocation_nonexistent_cert_against_pebble PASSED [ 76%]
tests/test_unit_acme.py::test_generate_account_key PASSED                [ 77%]
tests/test_unit_acme.py::test_jwk_thumbprint_is_deterministic PASSED     [ 78%]
tests/test_unit_acme.py::test_key_authorization PASSED                   [ 78%]
tests/test_unit_acme.py::test_sign_request_jwk_header PASSED             [ 79%]
tests/test_unit_acme.py::test_sign_request_kid_header PASSED             [ 80%]
tests/test_unit_acme.py::test_save_and_load_account_key PASSED           [ 80%]
tests/test_unit_acme.py::test_rsa_key_generation PASSED                  [ 81%]
tests/test_unit_acme.py::test_private_key_to_pem PASSED                  [ 81%]
tests/test_unit_acme.py::test_create_csr_single_domain PASSED            [ 82%]
tests/test_unit_acme.py::test_create_csr_multi_san PASSED                [ 83%]
tests/test_unit_acme.py::test_get_directory PASSED                       [ 83%]
tests/test_unit_acme.py::test_get_nonce PASSED                           [ 84%]
tests/test_unit_acme.py::test_post_as_get_empty_payload_jws PASSED       [ 84%]
tests/test_unit_acme.py::test_post_as_get_sign_request_compliance PASSED [ 85%]
tests/test_unit_acme.py::test_post_with_payload_vs_post_as_get PASSED    [ 85%]
tests/test_unit_acme.py::test_create_account_without_eab PASSED          [ 86%]
tests/test_unit_acme.py::test_create_order PASSED                        [ 85%]
tests/test_unit_acme.py::test_poll_authorization_valid PASSED            [ 86%]
tests/test_unit_acme.py::test_poll_authorization_invalid_raises PASSED   [ 87%]
tests/test_unit_acme.py::test_acme_error_on_non_2xx PASSED               [ 87%]
tests/test_unit_acme.py::test_revoke_certificate PASSED                  [ 88%]
tests/test_unit_acme.py::test_zerossl_client_default_url PASSED          [ 89%]
tests/test_unit_acme.py::test_sectigo_client_default_url PASSED          [ 89%]
tests/test_unit_acme.py::test_digicert_client_default_url PASSED         [ 90%]
tests/test_unit_acme.py::test_eab_subclass_hierarchy PASSED              [ 90%]
tests/test_unit_acme.py::test_create_account_not_overridden_in_subclasses PASSED [ 91%]
tests/test_unit_acme.py::test_make_client_returns_zerossl PASSED         [ 92%]
tests/test_unit_acme.py::test_make_client_returns_sectigo PASSED         [ 92%]
tests/test_unit_acme.py::test_eab_create_account_injects_eab PASSED      [ 93%]
tests/test_unit_acme.py::test_eab_create_account_omits_eab_when_credentials_empty PASSED [ 94%]
tests/test_unit_failure_scenarios.py::test_challenge_failure_invalid_status PASSED [ 94%]
tests/test_unit_failure_scenarios.py::test_invalid_csr_rejected_by_server PASSED [ 95%]
tests/test_unit_failure_scenarios.py::test_bad_nonce_retries_and_succeeds PASSED [ 96%]
tests/test_unit_failure_scenarios.py::test_bad_nonce_exhausts_retries PASSED [ 96%]
tests/test_unit_failure_scenarios.py::test_network_timeout_on_directory_fetch PASSED [ 97%]
tests/test_unit_failure_scenarios.py::test_invalid_directory_url_connection_error PASSED [ 98%]
tests/test_unit_failure_scenarios.py::test_invalid_directory_url_returns_404 PASSED [ 98%]
tests/test_unit_failure_scenarios.py::test_finalize_order_malformed_json_response PASSED [ 99%]
tests/test_unit_failure_scenarios.py::test_rate_limit_429_with_retry_after PASSED [100%]

============================== 175 passed in 37.12s ==============================
```

---

## Test Descriptions

### Atomic Write Tests — `tests/test_atomic_writes.py`

Filesystem atomic write operations for certificate and metadata storage.
No network or external services required.

| Test | Group | What it verifies |
|---|---|---|
| `test_atomic_write_text_creates_file` | Text | Creates new file with atomic write operation |
| `test_atomic_write_text_overwrites_existing` | Text | Overwrites existing file atomically (no temp files left) |
| `test_atomic_write_text_no_temp_file_left` | Text | Temporary file is cleaned up on success |
| `test_atomic_write_text_creates_parent_dirs` | Text | Missing parent directories are created |
| `test_atomic_write_text_cleans_up_temp_on_error` | Text | Temporary file is cleaned up on write failure |
| `test_atomic_write_bytes_creates_file` | Bytes | Creates new file with atomic write operation (binary mode) |
| `test_atomic_write_bytes_overwrites_existing` | Bytes | Overwrites existing file atomically |
| `test_atomic_write_bytes_no_temp_file_left` | Bytes | Temporary file cleanup on success |
| `test_atomic_write_bytes_large_file` | Bytes | Large file writes complete atomically |
| `test_pem_file_atomic_write_text` | Integration | PEM file writes via atomic operation (certificate storage scenario) |
| `test_multiple_atomic_writes_to_same_dir` | Integration | Multiple concurrent writes to same directory don't interfere |
| `test_concurrent_writes_to_different_files` | Integration | Concurrent writes to different files all succeed atomically |

---

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

### DNS-01 Challenge Tests — `tests/test_dns_challenge.py`

Full coverage of DNS-01 challenge support — Cloudflare, Route53, Google Cloud DNS.
No network, no DNS credentials, no Pebble required; all provider API calls are mocked.

| Test | Group | What it verifies |
|---|---|---|
| `test_known_vector` | `compute_dns_txt_value` | SHA-256 → base64url output matches manual computation (RFC 8555 §8.4) |
| `test_no_padding` | `compute_dns_txt_value` | Output contains no `=` padding characters |
| `test_deterministic` | `compute_dns_txt_value` | Same key_auth always produces the same TXT value |
| `test_different_inputs_produce_different_outputs` | `compute_dns_txt_value` | Different key_auth strings produce different TXT values |
| `test_output_is_valid_base64url` | `compute_dns_txt_value` | Output contains only URL-safe base64 characters |
| `test_dispatches_cloudflare` | `make_dns_provider` | Factory returns `CloudflareDnsProvider` for `DNS_PROVIDER=cloudflare` |
| `test_dispatches_route53` | `make_dns_provider` | Factory returns `Route53DnsProvider` for `DNS_PROVIDER=route53` |
| `test_dispatches_google` | `make_dns_provider` | Factory returns `GoogleCloudDnsProvider` for `DNS_PROVIDER=google` |
| `test_unknown_provider_raises` | `make_dns_provider` | Raises `ValueError` for unrecognised provider name |
| `test_cloudflare_importerror_hint` | `make_dns_provider` | `CloudflareDnsProvider` raises `ImportError` with `uv sync --extra dns-cloudflare` hint |
| `test_route53_importerror_hint` | `make_dns_provider` | `Route53DnsProvider` raises `ImportError` with `uv sync --extra dns-route53` hint |
| `test_google_importerror_hint` | `make_dns_provider` | `GoogleCloudDnsProvider` raises `ImportError` with `uv sync --extra dns-google` hint |
| `test_create_txt_record_explicit_zone` | `CloudflareDnsProvider` | Uses explicit `zone_id` without zone discovery |
| `test_create_txt_record_auto_discover_zone` | `CloudflareDnsProvider` | Auto-discovers zone via `zones.list()` when `zone_id` is empty |
| `test_create_txt_record_idempotent` | `CloudflareDnsProvider` | Skips create when identical TXT record already exists |
| `test_delete_txt_record_finds_and_deletes` | `CloudflareDnsProvider` | Finds matching record by name+content and deletes it |
| `test_delete_txt_record_swallows_errors` | `CloudflareDnsProvider` | Delete errors are swallowed (best-effort cleanup) |
| `test_delete_txt_record_missing_record_silent` | `CloudflareDnsProvider` | Silently does nothing when record not found |
| `test_create_txt_record_upsert_with_quotes` | `Route53DnsProvider` | TXT value is wrapped in double-quotes as required by Route53 |
| `test_create_txt_record_uses_explicit_zone_id` | `Route53DnsProvider` | Uses explicit `hosted_zone_id` without zone discovery |
| `test_create_txt_record_auto_discover_zone` | `Route53DnsProvider` | Auto-discovers zone via `list_hosted_zones_by_name()` when `hosted_zone_id` is empty |
| `test_delete_txt_record_uses_delete_action` | `Route53DnsProvider` | Uses `Action: DELETE` in change batch |
| `test_delete_txt_record_swallows_errors` | `Route53DnsProvider` | Route53 errors during delete are swallowed |
| `test_create_txt_record_calls_add_and_create` | `GoogleCloudDnsProvider` | Calls `add_record_set()` then `changes.create()` |
| `test_delete_txt_record_calls_delete_and_create` | `GoogleCloudDnsProvider` | Calls `delete_record_set()` then `changes.create()` |
| `test_delete_txt_record_swallows_errors` | `GoogleCloudDnsProvider` | GCP errors during delete are swallowed |
| `test_dns01_challenge_selected` | `order_initializer` | Selects `dns-01` challenge URL when `HTTP_CHALLENGE_MODE=dns` |
| `test_dns01_populates_auth_domains` | `order_initializer` | `auth_domains` populated from `authz["identifier"]["value"]` |
| `test_dns01_populates_dns_txt_values` | `order_initializer` | `dns_txt_values` contains correct `compute_dns_txt_value` output |
| `test_http01_dns_txt_values_empty` | `order_initializer` | `dns_txt_values` is empty list for HTTP-01 modes |
| `test_missing_dns01_challenge_returns_error` | `order_initializer` | Returns `error_log` entry when no `dns-01` challenge found in authz |
| `test_create_txt_record_called_for_each_domain` | `challenge_setup` | `create_txt_record()` called once per domain (all domains covered) |
| `test_propagation_sleep_called_when_positive` | `challenge_setup` | `time.sleep()` called with `DNS_PROPAGATION_WAIT_SECONDS` when > 0 |
| `test_propagation_sleep_skipped_when_zero` | `challenge_setup` | `time.sleep()` not called when `DNS_PROPAGATION_WAIT_SECONDS=0` |
| `test_returns_empty_dict` | `challenge_setup` | Returns `{}` on success (no state mutation needed) |
| `test_delete_called_for_each_domain` | `_cleanup_challenge` | `delete_txt_record()` called once per domain; `_dns_provider` cleared to `None` |
| `test_continues_on_partial_failure` | `_cleanup_challenge` | Continues deleting remaining domains even after one raises |
| `test_safe_when_no_provider` | `_cleanup_challenge` | Does not raise when `_dns_provider` is `None` |
| `test_dns_mode_accepted` | Config | `HTTP_CHALLENGE_MODE='dns'` passes `validate_challenge_mode` |
| `test_invalid_mode_rejected` | Config | Invalid mode value raises `ValidationError` |
| `test_cloudflare_missing_token_raises` | Config | `validate_dns_config` rejects empty `CLOUDFLARE_API_TOKEN` in dns+cloudflare mode |
| `test_google_missing_project_id_raises` | Config | `validate_dns_config` rejects empty `GOOGLE_PROJECT_ID` in dns+google mode |
| `test_route53_no_mandatory_fields` | Config | Route53 requires no mandatory fields (uses credential chain / instance role) |
| `test_standalone_mode_unchanged` | Config | Existing `standalone` mode validation is unaffected |
| `test_webroot_mode_unchanged` | Config | Existing `webroot` mode validation (requires `WEBROOT_PATH`) is unaffected |

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
| `test_post_as_get_empty_payload_jws` | `acme/jws.py` | RFC 8555 §6.2 POST-as-GET: `_post_signed(None, ...)` produces JWS with empty payload field |
| `test_post_as_get_sign_request_compliance` | `acme/jws.py` | RFC 8555 §6.2 POST-as-GET: `sign_request(None, ...)` generates valid JWS structure (empty payload, correct headers) |
| `test_post_with_payload_vs_post_as_get` | `acme/jws.py` | Contrast: normal POST (with payload) vs POST-as-GET (empty payload); both produce valid JWS |
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
| `test_finalize_order_malformed_json_response` | `acme/client.py` → `finalize_order` | Server returns malformed JSON in finalize response; exception propagates |
| `test_rate_limit_429_with_retry_after` | `acme/client.py` → rate limit handling | Server returns 429 with `Retry-After` header; exception propagates (consumer decides retry) |

---

### Planner Validation Tests — `tests/test_planner_validation.py`

LLM output validation and hallucinated domain stripping for the renewal planner.
No network or external services required; LLM output is mocked.

| Test | Group | What it verifies |
|---|---|---|
| `test_invalid_json_falls_back_to_renew_all` | Parse & Validate | Invalid JSON from LLM triggers fallback: all domains go to `routine_renewals` |
| `test_hallucinated_domain_in_urgent_stripped` | Parse & Validate | Hallucinated domain in `urgent_renewals` is stripped (only `managed_domains` allowed) |
| `test_hallucinated_domain_in_routine_stripped` | Parse & Validate | Hallucinated domain in `routine_renewals` is stripped |
| `test_hallucinated_domain_in_skip_stripped` | Parse & Validate | Hallucinated domain in `skip` is stripped |
| `test_mixed_real_and_hallucinated_preserves_real` | Parse & Validate | Real domains preserved; only hallucinated ones removed |
| `test_lookalike_domain_stripped` | Parse & Validate | Domains that don't exactly match `managed_domains` are stripped (typo protection) |
| `test_missing_domain_added_to_routine` | Parse & Validate | If managed domain is missing from planner output, it's added to `routine_renewals` |
| `test_all_missing_domains_added_to_routine` | Parse & Validate | All missing managed domains are recovered via fallback mechanism |
| `test_all_hallucinated_triggers_missing_domain_fallback` | Parse & Validate | If all domains are hallucinated, all managed domains added to `routine_renewals` |
| `test_planner_node_strips_hallucinated_from_pending_renewals` | Node-Level | `renewal_planner` node invocation: hallucinated domains stripped from state |
| `test_planner_node_invalid_json_queues_all_domains` | Node-Level | Invalid JSON from LLM causes node to queue all domains for renewal |
| `test_planner_node_urgent_before_routine_in_pending` | Node-Level | Urgent renewals appear before routine in `pending_renewals` queue |

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
Exercises the full LangGraph agent graph end-to-end. LLM nodes are mocked.

| Test | What it verifies |
|---|---|
| `test_full_renewal_flow` | Happy-path: scanner → planner → account → order → challenge → CSR → finalize → download → storage → reporter. All PEM files written; `privkey.pem` mode `0o600`; metadata populated. |
| `test_second_run_reuses_account` | Second run loads existing account key and calls `POST /newAccount onlyReturnExisting` instead of registering a new account. |
| `test_no_renewal_needed` | When planner returns `skip: [domain]`, `pending_renewals` stays empty; agent exits via `no_renewals` path with empty `completed_renewals` and `failed_renewals`. |
| `test_full_renewal_flow_dns01` | DNS-01 happy-path: full graph run with `HTTP_CHALLENGE_MODE=dns` and a mocked DNS provider. Verifies `create_txt_record()` called once (challenge setup), `delete_txt_record()` called once (cleanup), and `cert.pem` written to disk with a valid expiry. |

---

### Revocation Tests — `tests/test_revocation.py`

Unit and graph topology tests for certificate revocation — no Pebble, all ACME mocked.

| Test | Group | What it verifies |
|---|---|---|
| `test_pick_next_revocation_domain_pops_first_domain` | Router | Pops first domain from `revocation_targets`; sets `current_revocation_domain` |
| `test_pick_next_revocation_domain_last_domain` | Router | Handles single remaining domain correctly |
| `test_pick_next_revocation_domain_empty_targets` | Router | Empty targets leaves `current_revocation_domain` as `None` |
| `test_revocation_loop_router_more_targets` | Router | Routes to `next_domain` when `revocation_targets` is non-empty |
| `test_revocation_loop_router_no_targets` | Router | Routes to `all_done` when `revocation_targets` is empty |
| `test_cert_revoker_success` | Revoker | `POST /revokeCert` succeeds; domain added to `revoked_domains` |
| `test_cert_revoker_missing_cert` | Revoker | Missing cert file adds domain to `failed_revocations` without raising |
| `test_cert_revoker_acme_error` | Revoker | ACME error during revocation adds domain to `failed_revocations` |
| `test_revocation_reporter_success` | Reporter | LLM summary generated; `revoked_domains` reflected in message |
| `test_revocation_reporter_with_failures` | Reporter | Reporter includes failed domains in summary |
| `test_revocation_reporter_llm_failure` | Reporter | Reporter continues gracefully when LLM call fails |
| `test_revocation_graph_topology` | Graph | Graph has correct nodes and edges; compiles without error |
| `test_revocation_graph_single_domain_flow` | Graph | Single-domain revocation completes; domain in `revoked_domains` |
| `test_revocation_graph_multi_domain_flow` | Graph | Multi-domain revocation loops correctly; all domains revoked |
| `test_revocation_graph_partial_failure` | Graph | One failed revocation doesn't block remaining domains |

---

### Revocation Pebble Tests — `tests/test_revocation_pebble.py`

Requires Pebble running on `https://localhost:14000`. LLM nodes are mocked.

| Test | What it verifies |
|---|---|
| `test_revocation_graph_basic_against_pebble` | Issues a cert via the main graph, then revokes it via the revocation graph (reason=0); domain appears in `revoked_domains`. |
| `test_revocation_reason_codes_against_pebble` | Same flow with reason=1 (keyCompromise); Pebble accepts the reason code. |
| `test_revocation_nonexistent_cert_against_pebble` | Revocation attempted for a domain with no cert file on disk; domain lands in `failed_revocations` with a non-empty `error_log`. |

---

## Infrastructure

```
docker compose -f docker-compose.pebble.yml up -d
```

| Service | Image | Port | Config |
|---|---|---|---|
| `pebble` | `ghcr.io/letsencrypt/pebble:latest` | `14000` (ACME) · `15000` (mgmt) | `PEBBLE_VA_NOSLEEP=1` · `PEBBLE_VA_ALWAYS_VALID=1` |

`PEBBLE_VA_ALWAYS_VALID=1` auto-approves all HTTP-01 and DNS-01 challenges, so
tests run without real DNS records, TXT records, or port-80 access.
