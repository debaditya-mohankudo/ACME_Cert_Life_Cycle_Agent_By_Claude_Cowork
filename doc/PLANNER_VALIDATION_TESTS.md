# Planner Validation Tests — LLM Hallucinated Domain Handling

## Overview

The renewal planner uses an LLM to classify domains into `urgent`, `routine`, and `skip` buckets based on certificate expiry analysis. Its validation logic (`_parse_and_validate`) guards against three failure modes:

1. **Hallucinated domains** — LLM invents domains not in `managed_domains` (e.g., "evil.com")
2. **Missing domains** — LLM forgets to classify a managed domain
3. **Invalid JSON** — LLM returns malformed output

This test suite provides exhaustive coverage of all three scenarios.

---

## Test File: `tests/test_planner_validation.py`

**Total tests:** 12
**Dependencies:** None (no Pebble, no network)
**Time per run:** ~1 second
**Isolation:** Each test uses independent domain sets

---

## Test Classes

### Class 1: `TestParseAndValidate` (9 tests)

These are pure unit tests of the `_parse_and_validate(raw: str, managed_domains: set[str])` private function.

**No mocks, no LLM calls, no graph** — just Python dict/set operations.

#### Setup

```python
from agent.nodes.planner import _parse_and_validate

DOMAIN_A = "api.example.com"
DOMAIN_B = "shop.example.com"
MANAGED = {DOMAIN_A, DOMAIN_B}
```

#### Scenario A: JSON Parse Failure

**`test_invalid_json_falls_back_to_renew_all`**
- Input: raw = `"not valid json at all!!"`
- Assertion: All managed domains in `routine`, empty `urgent`/`skip`, notes contain "JSON parse failed"
- **Why:** On JSON parse error, the function falls back to "renew all managed domains"

#### Scenario B: Hallucinated Domain Stripping

**`test_hallucinated_domain_in_urgent_stripped`**
- Input: `'{"urgent": ["evil.com"], "routine": ["api.example.com"], "skip": ["shop.example.com"]}'`
- Assertion: `plan["urgent"] == []`, `plan["routine"] == [DOMAIN_A]`, `plan["skip"] == [DOMAIN_B]`
- **Why:** Hallucinated domain is filtered out; real domains preserved

**`test_hallucinated_domain_in_routine_stripped`**
- Input: `'{"urgent": [], "routine": ["evil.com", "api.example.com"], "skip": ["shop.example.com"]}'`
- Assertion: `plan["routine"] == [DOMAIN_A]`
- **Why:** Hallucinated domain removed from the middle of list; real domain survives

**`test_hallucinated_domain_in_skip_stripped`**
- Input: `'{"urgent": ["api.example.com", "shop.example.com"], "routine": [], "skip": ["evil.com"]}'`
- Assertion: `plan["skip"] == []`, `plan["urgent"]` unchanged
- **Why:** Validates that stripping happens in all three buckets

**`test_mixed_real_and_hallucinated_preserves_real`**
- Input: `'{"urgent": ["evil.com", "api.example.com"], "routine": ["shop.example.com"], "skip": []}'`
- Assertion: `plan["urgent"] == [DOMAIN_A]` (evil.com removed)
- **Why:** Real domains survive filtering even when mixed with hallucinations

**`test_lookalike_domain_stripped`**
- Input: `'{"urgent": ["api.example.com.evil.com"], "routine": ["api.example.com"], "skip": []}'`
- Assertion: Lookalike domain not in any bucket; real domain in `routine`
- **Why:** Substring/lookalike domains are not fuzzy-matched; exact match required

#### Scenario B + C: All Hallucinated Triggers Missing Domain Recovery

**`test_all_hallucinated_triggers_missing_domain_fallback`**
- Input: `'{"urgent": ["evil.com"], "routine": ["attacker.io"], "skip": ["hacker.net"]}'`
- Managed domains: {DOMAIN_A, DOMAIN_B}
- Assertion: `set(plan["routine"]) == {DOMAIN_A, DOMAIN_B}`, `plan["urgent"] == []`
- **Why:** After stripping all hallucinations, missing domain logic adds both domains to `routine` as safety net

#### Scenario C: Missing Domain Recovery

**`test_missing_domain_added_to_routine`**
- Input: `'{"urgent": [], "routine": ["api.example.com"], "skip": []}'`
- Managed domains: {DOMAIN_A, DOMAIN_B}
- Assertion: `DOMAIN_B in plan["routine"]` (appended to existing routine list)
- **Why:** Unclassified domains are added to routine (ensures no domain is dropped)

**`test_all_missing_domains_added_to_routine`**
- Input: `'{"urgent": [], "routine": [], "skip": []}'`
- Managed domains: {DOMAIN_A, DOMAIN_B}
- Assertion: `set(plan["routine"]) == {DOMAIN_A, DOMAIN_B}` and domains are sorted
- **Why:** When planner returns empty output, fallback adds all managed domains to routine (renew everything)

---

### Class 2: `TestRenewalPlannerNode` (3 tests)

These are integration tests of the `renewal_planner(state: AgentState)` node function with a mocked LLM.

**Fixtures:** `mock_llm_nodes` (from conftest.py) patches `llm.factory.init_chat_model`

#### Setup

```python
def _make_state(domains, threshold=30):
    return {
        "managed_domains": domains,
        "cert_records": [
            {
                "domain": d,
                "days_until_expiry": threshold - 1,
                "expiry_date": "2026-03-15",
                "needs_renewal": True
            }
            for d in domains
        ],
        "renewal_threshold_days": threshold,
        "messages": [],
    }
```

#### Tests

**`test_planner_node_strips_hallucinated_from_pending_renewals`**
- Setup: domains = [DOMAIN_A], LLM returns `'{"urgent": ["evil.com", "api.example.com"], "routine": [], "skip": []}'`
- Call: `renewal_planner(state)`
- Assertion: `result["pending_renewals"] == [DOMAIN_A]`
- **Why:** Validates end-to-end: hallucinations don't reach the graph's `pending_renewals` list

**`test_planner_node_invalid_json_queues_all_domains`**
- Setup: domains = [DOMAIN_A, DOMAIN_B], LLM returns `"BROKEN OUTPUT NOT JSON"`
- Call: `renewal_planner(state)`
- Assertion: `set(result["pending_renewals"]) == {DOMAIN_A, DOMAIN_B}`
- **Why:** On LLM JSON failure, all managed domains are queued for renewal (fail-safe)

**`test_planner_node_urgent_before_routine_in_pending`**
- Setup: domains = [DOMAIN_A, DOMAIN_B], LLM returns `'{"urgent": ["shop.example.com"], "routine": ["api.example.com"], "skip": []}'`
- Call: `renewal_planner(state)`
- Assertion: `result["pending_renewals"] == [DOMAIN_B, DOMAIN_A]` (urgent first)
- **Why:** Validates ordering: `pending_renewals = urgent + routine` (in that order)

---

## Design Rationale

### Why 9 unit tests + 3 node tests?

**Unit tests (9)** exercise the pure validation logic with simple inputs:
- Fast: no LLM calls, no mocking complexity
- Precise: isolate each validation scenario
- Maintainable: easy to add edge cases

**Node tests (3)** validate integration with the LLM and state flow:
- Confirm validation is actually applied to LLM output
- Verify correct handling in graph state
- Test the full `renewal_planner → pending_renewals` pipeline

### Why no full graph test?

The full graph is already tested by `test_checkpoint.py` and lifecycle tests. Here we focus on the planner's core logic without the noise of ACME operations.

### Why "hallucinated" is the key concern?

LLMs are good at language understanding but can hallucinate facts not in their context. This happens when:
- The LLM's training data includes certificates for domains we don't manage
- The LLM "remembers" similar-looking domains from unrelated prompts
- The LLM invents plausible-sounding domains

The validation logic treats all unknown domains the same way: **strip them silently**.

---

## Test Results (2026-02-22)

All 12 planner validation tests pass with zero regressions.

```
============================= test session starts ==============================
platform darwin · Python 3.12.8 · pytest-8.3.5
collected 12 items

tests/test_planner_validation.py::TestParseAndValidate::test_invalid_json_falls_back_to_renew_all PASSED [  8%]
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_urgent_stripped PASSED [ 16%]
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_routine_stripped PASSED [ 25%]
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_skip_stripped PASSED [ 33%]
tests/test_planner_validation.py::TestParseAndValidate::test_mixed_real_and_hallucinated_preserves_real PASSED [ 41%]
tests/test_planner_validation.py::TestParseAndValidate::test_lookalike_domain_stripped PASSED [ 50%]
tests/test_planner_validation.py::TestParseAndValidate::test_missing_domain_added_to_routine PASSED [ 58%]
tests/test_planner_validation.py::TestParseAndValidate::test_all_missing_domains_added_to_routine PASSED [ 66%]
tests/test_planner_validation.py::TestParseAndValidate::test_all_hallucinated_triggers_missing_domain_fallback PASSED [ 75%]
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_strips_hallucinated_from_pending_renewals PASSED [ 83%]
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_invalid_json_queues_all_domains PASSED [ 91%]
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_urgent_before_routine_in_pending PASSED [100%]

======================== 12 passed in 4.16s ========================
```

### Full Test Suite (All Tests)

When running the complete test suite (including checkpoint, planner, ACME, retry scheduler, KB, and other tests):

```
======================== 74 passed, 5 skipped in 17.41s ========================

Summary:
  • Planner validation tests: 12 passed (new)
  • Checkpoint tests: 10 passed
  • Unit ACME tests: 27 passed
  • Retry scheduler tests: 9 passed
  • Unit failure scenarios: 9 passed
  • Knowledge base tests: 5 passed
  • Integration tests: 3 skipped (no Pebble)
  • Lifecycle tests: 2 skipped (no Pebble)
```

---

## Running the Tests

```bash
# Run only planner validation tests
pytest tests/test_planner_validation.py -v

# Run with verbose output to see hallucination stripping
pytest tests/test_planner_validation.py -v -s

# Run a single test
pytest tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_urgent_stripped -v

# Run all unit tests (checkpoint + planner + others)
pytest tests/test_unit_acme.py tests/test_checkpoint.py tests/test_planner_validation.py -v
```

---

## Expected Output

```
tests/test_planner_validation.py::TestParseAndValidate::test_invalid_json_falls_back_to_renew_all PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_urgent_stripped PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_routine_stripped PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_hallucinated_domain_in_skip_stripped PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_mixed_real_and_hallucinated_preserves_real PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_lookalike_domain_stripped PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_missing_domain_added_to_routine PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_all_missing_domains_added_to_routine PASSED
tests/test_planner_validation.py::TestParseAndValidate::test_all_hallucinated_triggers_missing_domain_fallback PASSED
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_strips_hallucinated_from_pending_renewals PASSED
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_invalid_json_queues_all_domains PASSED
tests/test_planner_validation.py::TestRenewalPlannerNode::test_planner_node_urgent_before_routine_in_pending PASSED

======================== 12 passed in 0.95s ========================
```

---

## Coverage Summary

| Code Path | Tests |
|---|---|
| JSON parse failure → fallback to renew all | 1 |
| Strip hallucinated domains from urgent | 3 |
| Strip hallucinated domains from routine | 2 |
| Strip hallucinated domains from skip | 1 |
| Add missing managed domains to routine | 2 |
| Node-level integration: hallucination blocking | 1 |
| Node-level integration: JSON fallback | 1 |
| Node-level integration: ordering (urgent before routine) | 1 |
| **Total** | **12** |

Every code path in `_parse_and_validate` is tested in isolation and in context.
