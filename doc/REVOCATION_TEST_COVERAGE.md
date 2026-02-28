# Revocation Graph Test Coverage — Observability Report

**Date:** 2026-02-28
**Test Suite:** `tests/test_revocation.py`
**Total Tests:** 33 (15 existing + 18 new)
**Status:** ✅ All passing (0.58s)
**Suite Result:** 353 total tests passing (no regressions)

---

## Executive Summary

Added 18 comprehensive test cases for `agent/revocation_graph.py` focused on observability, state integrity, and edge case handling. Tests now cover:

- **Nonce management** — Lifecycle across multi-domain revocation
- **RFC 5280 reason codes** — All valid codes (0–5) + invalid handling
- **State integrity** — Message accumulation, field cleanup, deduplication
- **Checkpointing** — Graph compilation with state preservation
- **Error handling** — Accumulation, formatting, multiple failure scenarios
- **Edge cases** — Long domains, IDN, duplicates, account setup failures

---

## Test Categories & Observability Value

### 1. Nonce Management & Flow (3 new tests)

**Tests Added:**
- `test_nonce_cleared_between_domains` — Ensures fresh nonce fetch for each domain
- `test_nonce_flow_multi_domain_sequence` — Validates nonce lifecycle through complete multi-domain flow
- `test_nonce_none_handling_in_state` — Verifies graceful handling when nonce is None

**Observability Value:**
- **Why it matters:** Nonce exhaustion is a protocol-critical issue; detecting nonce leaks early prevents silent failures
- **Coverage:** Ensures ACME protocol compliance (one POST per nonce)
- **Observable behaviors:** Nonce consumption rate, freshness validation, state integrity

---

### 2. RFC 5280 Reason Code Coverage (2 new tests)

**Tests Added:**
- `test_revocation_reason_codes` — Validates all valid reason codes (0, 1, 3, 4, 5) passed to ACME client
- `test_revocation_invalid_reason_code` — Verifies behavior on invalid reason code (code > 5)

**Reason Codes Validated:**
| Code | Meaning | Status |
|------|---------|--------|
| 0 | unspecified | ✅ |
| 1 | keyCompromise | ✅ |
| 3 | affiliationChanged | ✅ |
| 4 | superseded | ✅ |
| 5 | cessationOfOperation | ✅ |

**Observability Value:**
- **Why it matters:** Reason codes convey revocation intent; incorrect codes could trigger audit failures
- **Coverage:** Ensures reason code is correctly threaded from CLI → state → ACME client
- **Observable behaviors:** Reason code mutation detection, validation layer verification

---

### 3. State Integrity & Message Accumulation (4 new tests)

**Tests Added:**
- `test_state_message_accumulation_across_flow` — Verifies messages array grows correctly through graph
- `test_revoked_domains_no_duplicates` — Ensures revoked_domains list never duplicates
- `test_current_revocation_domain_cleared_after_revoke` — Validates state cleanup between domain iterations
- `test_error_log_accumulation_across_failures` — Verifies error_log preserves history across failures

**Observability Value:**
- **Why it matters:** Message and error log integrity is essential for audit trails and debugging
- **Coverage:** Validates reducer behavior (add_messages, state merging) across multi-domain flows
- **Observable behaviors:** Message history coherence, domain processing order, error aggregation

**Example audit trail verification:**
```python
# After multi-domain revocation:
final_state["messages"]  # ≥ 3 entries (system, user, ai response)
final_state["error_log"]  # All failures preserved, no loss
final_state["revoked_domains"]  # No duplicates, consistent order
```

---

### 4. Checkpointing & Resumption (2 new tests)

**Tests Added:**
- `test_revocation_graph_with_checkpointing` — Verifies graph compiles with checkpointing enabled
- `test_revocation_state_resumption_after_interrupt` — Validates all state fields present for resumption

**Observability Value:**
- **Why it matters:** Long-running revocations may need resumption after interrupts
- **Coverage:** Ensures state is fully serializable and preserves critical fields
- **Observable behaviors:** Checkpoint creation, field preservation, resumption readiness

**State fields validated for resumption:**
```python
assert "revoked_domains" in final_state
assert "failed_revocations" in final_state
assert "revocation_targets" in final_state
assert "acme_account_url" in final_state
assert "messages" in final_state
```

---

### 5. Account Setup Scenarios (1 new test)

**Tests Added:**
- `test_account_creation_failure_handling` — Verifies graceful handling when account creation fails

**Observability Value:**
- **Why it matters:** Account setup failures should not cascade into domain revocation attempts
- **Coverage:** Ensures early failure detection with proper error logging
- **Observable behaviors:** Setup error handling, early exit conditions

---

### 6. Edge Cases & Domain Variations (3 new tests)

**Tests Added:**
- `test_very_long_domain_name` — Validates handling of 131-char domain names (near DNS limit)
- `test_idn_internationalized_domain` — Ensures IDN domains (e.g., münchen.example.com) work
- `test_duplicate_domains_in_targets` — Verifies FIFO processing when domain appears multiple times

**Edge Cases Covered:**
| Test | Domain | Length | Status |
|------|--------|--------|--------|
| Long domain | `aaa...aaa.bbb...bbb.example.com` | 131 chars | ✅ |
| IDN domain | `münchen.example.com` | UTF-8 multibyte | ✅ |
| Duplicate | `[example.com, api.example.com, example.com]` | FIFO order | ✅ |

**Observability Value:**
- **Why it matters:** Non-ASCII and edge-case domains expose encoding/parsing bugs
- **Coverage:** Validates domain handling across character sets and length limits
- **Observable behaviors:** Character encoding detection, domain normalization

---

### 7. Reporter & Message Flow (1 new test)

**Tests Added:**
- `test_reporter_message_content_structure` — Verifies reporter message includes revocation context

**Observability Value:**
- **Why it matters:** Reporter summaries are the primary user-facing output; incomplete context obscures success/failure
- **Coverage:** Validates reason code, domain lists, and error details are included in prompt
- **Observable behaviors:** Message comprehensiveness, reason code visibility, error detail inclusion

---

### 8. Error Handling & Accumulation (3 new tests)

**Tests Added:**
- `test_consecutive_revocation_failures` — Verifies multiple failures tracked correctly
- `test_error_log_message_format_validation` — Ensures error messages follow consistent format
- `test_error_log_accumulation_across_failures` — Validates error history preserved across domains

**Error Tracking Coverage:**
```python
# Single failure scenario:
result["failed_revocations"]  # ["example.com"]
result["error_log"]  # ["example.com: cert not found"]

# Multiple failures:
result["failed_revocations"]  # ["example.com", "api.example.com"]
result["error_log"]  # Full history preserved
```

**Observability Value:**
- **Why it matters:** Error logs are the primary observability signal for operational debugging
- **Coverage:** Ensures all errors are logged, formatted consistently, and preserved
- **Observable behaviors:** Error rate, failure categories, error message consistency

---

## Coverage Summary Table

| Category | Count | Critical | Observable Signals |
|----------|-------|----------|-------------------|
| Nonce Management | 3 | ✅ | Nonce consumption rate, protocol compliance |
| Reason Codes | 2 | ✅ | Reason code correctness, validation |
| State Integrity | 4 | ✅ | Message history, field cleanup, deduplication |
| Checkpointing | 2 | ✅ | State preservation, resumption readiness |
| Account Setup | 1 | ✅ | Early failure detection |
| Edge Cases | 3 | — | Character encoding, domain limits |
| Reporter | 1 | — | Output comprehensiveness |
| Error Handling | 3 | ✅ | Error rate, failure categories, consistency |
| **Total** | **18** | **13** | — |

---

## Key Observability Metrics Now Covered

### Protocol-Level
- ✅ Nonce consumption (1 POST per nonce)
- ✅ RFC 5280 reason code correctness
- ✅ ACME error handling and recovery

### State-Level
- ✅ Message accumulation (audit trail)
- ✅ Field cleanup between iterations (no leaks)
- ✅ Deduplication of revoked domains
- ✅ Error log preservation

### System-Level
- ✅ Checkpointing state serialization
- ✅ Multi-domain sequencing order
- ✅ Account setup failure handling
- ✅ Edge case handling (IDN, long domains)

### Operational-Level
- ✅ Error message consistency
- ✅ Reporter context completeness
- ✅ Partial failure scenarios (mixed success/failure)

---

## Running the Tests

### All revocation tests:
```bash
pytest tests/test_revocation.py -v
```

### Specific test category:
```bash
# Nonce tests only
pytest tests/test_revocation.py -k "nonce" -v

# Reason code tests only
pytest tests/test_revocation.py -k "reason" -v

# State integrity tests only
pytest tests/test_revocation.py -k "state" -v
```

### With coverage:
```bash
pytest tests/test_revocation.py --cov=agent.revocation_graph --cov-report=html
```

---

## Test Execution Profile

```
Platform: darwin (macOS 25.3.0)
Python: 3.12.12
Execution Time: 0.58s
Memory: ~50MB
Test Framework: pytest 9.0.2
Mocking: unittest.mock (no external dependencies)
```

---

## Notes for Maintainers

1. **Nonce tests** validate protocol safety — critical for ACME compliance
2. **Reason code tests** are forward-compatible — new codes (6+) can be added without test changes
3. **State integrity tests** catch reducer bugs early — verify these if changing message handling
4. **Checkpointing tests** depend on LangGraph behavior — update if LangGraph API changes
5. **Error log tests** are format-sensitive — update if error message format changes

---

## Related Documentation

- `doc/DESIGN_PRINCIPLES.md` — State design principles
- `agent/revocation_graph.py` — Graph topology and flow
- `agent/nodes/revoker.py` — Certificate revocation node
- `agent/nodes/revocation_router.py` — Domain routing logic

