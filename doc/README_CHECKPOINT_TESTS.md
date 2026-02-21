# Checkpoint / Interrupt / Resume Test Suite

## Overview

This document describes the checkpoint test suite for the ACME certificate lifecycle agent. The tests verify that LangGraph's `MemorySaver` checkpoint mechanism correctly saves and resumes graph state, enabling resilient runs that can survive process interruptions.

**Key feature:** If the agent crashes mid-run, it can resume from the last saved checkpoint without losing progress or retrying completed work.

---

## Test File: `tests/test_checkpoint.py`

**Total tests:** 10
**Dependencies:** None (no Pebble required)
**Time per run:** ~1–2 seconds
**Isolation:** Each test uses a unique `thread_id` to prevent cross-contamination

---

## Test Scenarios

### Group 1: Basic Checkpoint Mechanics

These tests verify that checkpointing is enabled and checkpoints are created at each step.

#### `test_complete_run_creates_checkpoint`
- **Purpose:** Verify that a complete graph run produces a valid checkpoint.
- **Setup:** Run graph with `use_checkpointing=True`.
- **Assertions:**
  - `graph.get_state(config).next == ()` — graph has finished (no next nodes)
  - `values["completed_renewals"] == [DOMAIN]` — domain was successfully renewed
- **Key API:** `graph.invoke(state, config)`, `graph.get_state(config)`

#### `test_checkpoint_history_non_empty`
- **Purpose:** Verify that checkpoint history is preserved and contains all node executions.
- **Setup:** Run complete graph, then inspect history.
- **Assertions:**
  - `graph.get_state_history(config)` yields at least 5+ snapshots (one per node executed)
  - Snapshots include expected node names: `"renewal_planner"`, `"acme_account_setup"`, `"challenge_verifier"`, etc.
  - Each snapshot has a `metadata["step"]` counter that increases monotonically
- **Key API:** `graph.get_state_history(config)`, `StateSnapshot.metadata`

---

### Group 2: Interrupt and Resume

These tests verify that a graph can be interrupted at a specific node, inspected, and then resumed cleanly.

#### `test_interrupt_before_acme_account_setup`
- **Purpose:** Verify that `interrupt_before` pauses execution before a specified node.
- **Setup:** Call `graph.stream(state, config, interrupt_before=["acme_account_setup"])`.
- **Assertions:**
  - `graph.get_state(config).next == ("acme_account_setup",)` — paused before account setup
  - `values["pending_renewals"] == [DOMAIN]` — planner ran, account setup did not
  - `values["current_nonce"]` is not `None` — earlier nodes (scanner, planner) ran
- **Key API:** `graph.stream(..., interrupt_before=[...])`, stream yields `{'__interrupt__': ()}`

#### `test_resume_after_interrupt_completes`
- **Purpose:** Verify that a resumed graph completes successfully from an interrupt point.
- **Setup:**
  1. Stream with `interrupt_before=["acme_account_setup"]`
  2. Call `graph.stream(None, config)` to resume (pass `None` for input)
- **Assertions:**
  - Final `graph.get_state(config).next == ()` — run finished
  - `values["completed_renewals"] == [DOMAIN]` — domain completed renewal
- **Key API:** `graph.stream(None, config)` — `None` input signals resume from checkpoint

#### `test_interrupt_before_challenge_verifier`
- **Purpose:** Verify interrupt at a node deep in the renewal pipeline.
- **Setup:** Stream with `interrupt_before=["challenge_verifier"]`.
- **Assertions:**
  - `snapshot.next == ("challenge_verifier",)`
  - `values["current_domain"] == DOMAIN`
  - `values["current_order"]` is not `None` (order was created, pending verification)
  - `values["current_order"]["status"] == "pending"` (not yet valid)
- **Key API:** Confirm that per-domain state is preserved at deep interrupt points

---

### Group 3: State Integrity

These tests verify that state fields are preserved correctly across checkpoints and that no data is lost during interrupt/resume cycles.

#### `test_critical_config_fields_preserved_through_checkpoint`
- **Purpose:** Ensure configuration fields never mutate during checkpoint history.
- **Setup:** Run full graph, inspect all snapshots in history.
- **Assertions:**
  - `managed_domains`, `cert_store_path`, `account_key_path`, `max_retries` are identical in every snapshot
  - These fields are read-only for the agent and should never change
- **Key API:** Walk `graph.get_state_history(config)` and compare `snapshot.values` across steps

#### `test_completed_renewals_in_final_checkpoint`
- **Purpose:** Verify that progress tracking fields are correct at the end of a run.
- **Setup:** Complete a full graph run.
- **Assertions:**
  - `values["completed_renewals"] == [DOMAIN]` — success
  - `values["pending_renewals"] == []` — all domains consumed
  - `values["failed_renewals"] == []` — no failures
  - `values["error_log"] == []` — no errors logged
- **Key API:** `graph.get_state(config).values` for final state inspection

#### `test_messages_accumulate_across_checkpoints`
- **Purpose:** Verify that LLM message history accumulates via the `add_messages` reducer.
- **Setup:** Complete a full graph run.
- **Assertions:**
  - `values["messages"]` is a non-empty list
  - At least 2 messages present (planner and reporter both append via `add_messages`)
  - Each message is a `BaseMessage` (validated by type)
- **Key API:** `add_messages` reducer in `AgentState` — messages append, don't replace

---

### Group 4: Thread Isolation

These tests verify that different `thread_id` values maintain independent checkpoint histories.

#### `test_two_threads_are_independent`
- **Purpose:** Ensure two concurrent/sequential runs with different `thread_id` values don't interfere.
- **Setup:**
  1. Create `config_a = {"configurable": {"thread_id": "test-run-a"}}`
  2. Create `config_b = {"configurable": {"thread_id": "test-run-b"}}`
  3. Run `graph.invoke(state, config_a)` and `graph.invoke(state, config_b)` sequentially
- **Assertions:**
  - `graph.get_state(config_a).values["completed_renewals"] == [DOMAIN]`
  - `graph.get_state(config_b).values["completed_renewals"] == [DOMAIN]`
  - `len(list(graph.get_state_history(config_a))) != len(list(graph.get_state_history(config_b)))` OR histories are different (thread histories don't mix)
- **Key API:** `config` dict with different `thread_id` values isolate state

---

### Group 5: Advanced Operations

These tests verify that checkpoint state can be programmatically modified before resuming.

#### `test_update_state_injects_domain_before_resume`
- **Purpose:** Verify that `graph.update_state()` can inject modified state that affects subsequent execution.
- **Setup:**
  1. Interrupt before `acme_account_setup` with `pending_renewals == [DOMAIN]`
  2. Call `graph.update_state(config, {"pending_renewals": []}, as_node="renewal_planner")`
  3. Resume with `graph.stream(None, config)`
- **Assertions:**
  - `graph.get_state(config).values["completed_renewals"] == []` — no domain was processed
  - Run ended (no execution loop) because `domain_loop_router` saw empty `pending_renewals` and routed to `summary_reporter`
- **Key API:** `graph.update_state(config, values, as_node=...)` — injects state, optionally claiming it came from a specific node

---

## Fixtures

### `checkpoint_settings(tmp_path)`
Mutates the global `settings` singleton for the duration of the test, then restores original values.

**Configured values:**
```python
settings.MANAGED_DOMAINS = ["checkpoint.test"]
settings.CERT_STORE_PATH = tmp_path / "certs"
settings.ACCOUNT_KEY_PATH = tmp_path / "account.key"
settings.HTTP_CHALLENGE_MODE = "webroot"
settings.WEBROOT_PATH = tmp_path / "webroot"
settings.ANTHROPIC_API_KEY = "dummy-key"
settings.MAX_RETRIES = 1
```

### `mock_checkpoint_llm`
Patches `llm.factory.init_chat_model` to return a mock LLM that produces a domain-aware planner response:

```json
{
  "urgent": [],
  "routine": ["checkpoint.test"],
  "skip": [],
  "notes": "checkpoint test"
}
```

This response populates `pending_renewals` with `["checkpoint.test"]`.

### `mocked_acme_nodes`
Patches all network-calling nodes with minimal valid returns:

| Node | Return |
|------|--------|
| `acme_account_setup` | `{"acme_account_url": "https://mock.acme/acc/1", "current_nonce": "nonce-1"}` |
| `order_initializer` | `{"current_order": MOCK_ORDER, "current_nonce": "nonce-2"}` |
| `challenge_setup` | `{"current_order": MOCK_ORDER_SETUP, "current_nonce": "nonce-3"}` |
| `challenge_verifier` | `{"current_order": MOCK_ORDER_READY, "current_nonce": "nonce-4"}` |
| `csr_generator` | `{"current_order": MOCK_ORDER_CSR, "current_nonce": "nonce-5"}` |
| `order_finalizer` | `{"current_order": MOCK_ORDER_FINAL, "current_nonce": "nonce-6"}` |
| `cert_downloader` | `{"current_order": MOCK_ORDER_CERT, "current_nonce": "nonce-7"}` |
| `storage_manager` | `{"completed_renewals": [current_domain], "cert_metadata": {...}}` (dynamic via `side_effect`) |

Each mock increments the `current_nonce` to verify that nonce values flow through state correctly.

### `run_checkpoint_graph`
Helper function that builds graph and initial state. Returns tuple `(graph, state, config)`:

```python
def run_checkpoint_graph(checkpoint_settings):
    graph = build_graph(use_checkpointing=True)
    state = initial_state(
        managed_domains=["checkpoint.test"],
        cert_store_path=checkpoint_settings.CERT_STORE_PATH,
        account_key_path=checkpoint_settings.ACCOUNT_KEY_PATH,
        renewal_threshold_days=30,
        max_retries=1,
        webroot_path=checkpoint_settings.WEBROOT_PATH,
    )
    config = {"configurable": {"thread_id": f"test-{uuid4().hex[:8]}"}}
    return graph, state, config
```

---

## Implementation Notes

### No code changes required
The test suite does NOT modify any existing code:
- `build_graph(use_checkpointing=True)` already exists
- `interrupt_before` is passed at `.stream()` call time (LangGraph API)
- All mocking uses `unittest.mock.patch` on module paths

### Thread ID uniqueness
Each test generates a unique `thread_id` using `uuid4().hex[:8]` to prevent cross-test state leakage. Tests are completely isolated.

### Node mocking strategy
Nodes are mocked at their module path (e.g., `agent.nodes.account.acme_account_setup`) rather than by import alias. This ensures the patch matches the `add_node()` registration in `graph.py`.

### Real nodes
- **`certificate_scanner`:** Runs for real. With an empty `tmp_path / "certs"`, no existing certs are found, so all domains have `needs_renewal=True`.
- **Router nodes** (`pick_next_domain`, `renewal_router`, etc.): Run for real (pure logic, no network).

### LLM response domain
The mocked planner response must include `"checkpoint.test"` in the `"routine"` list. This populates `pending_renewals` so the test domain is queued for renewal.

---

## Running the Tests

```bash
# Run only checkpoint tests
pytest tests/test_checkpoint.py -v

# Run with output
pytest tests/test_checkpoint.py -v -s

# Run a single test
pytest tests/test_checkpoint.py::TestBasicCheckpointing::test_complete_run_creates_checkpoint -v

# Run all unit tests (checkpoint + others)
pytest tests/test_unit_acme.py tests/test_unit_failure_scenarios.py tests/test_checkpoint.py -v
```

**Expected output:**
```
tests/test_checkpoint.py::TestBasicCheckpointing::test_complete_run_creates_checkpoint PASSED
tests/test_checkpoint.py::TestBasicCheckpointing::test_checkpoint_history_non_empty PASSED
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_acme_account_setup PASSED
tests/test_checkpoint.py::TestInterruptResume::test_resume_after_interrupt_completes PASSED
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_challenge_verifier PASSED
tests/test_checkpoint.py::TestStateIntegrity::test_critical_config_fields_preserved_through_checkpoint PASSED
tests/test_checkpoint.py::TestStateIntegrity::test_completed_renewals_in_final_checkpoint PASSED
tests/test_checkpoint.py::TestStateIntegrity::test_messages_accumulate_across_checkpoints PASSED
tests/test_checkpoint.py::TestThreadIsolation::test_two_threads_are_independent PASSED
tests/test_checkpoint.py::TestAdvancedCheckpoint::test_update_state_injects_domain_before_resume PASSED

========= 10 passed in 1.23s =========
```

---

## Test Results (2026-02-22)

All 10 checkpoint tests pass with zero regressions.

```
============================= test session starts ==============================
platform darwin · Python 3.12.8 · pytest-8.3.5
collected 10 items

tests/test_checkpoint.py::TestBasicCheckpointing::test_complete_run_creates_checkpoint PASSED [ 10%]
tests/test_checkpoint.py::TestBasicCheckpointing::test_checkpoint_history_non_empty PASSED [ 20%]
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_acme_account_setup PASSED [ 30%]
tests/test_checkpoint.py::TestInterruptResume::test_resume_after_interrupt_completes PASSED [ 40%]
tests/test_checkpoint.py::TestInterruptResume::test_interrupt_before_challenge_verifier PASSED [ 50%]
tests/test_checkpoint.py::TestStateIntegrity::test_critical_config_fields_preserved_through_checkpoint PASSED [ 60%]
tests/test_checkpoint.py::TestStateIntegrity::test_completed_renewals_in_final_checkpoint PASSED [ 70%]
tests/test_checkpoint.py::TestStateIntegrity::test_messages_accumulate_across_checkpoints PASSED [ 80%]
tests/test_checkpoint.py::TestThreadIsolation::test_two_threads_are_independent PASSED [ 90%]
tests/test_checkpoint.py::TestAdvancedCheckpoint::test_update_state_injects_domain_before_resume PASSED [100%]

======================== 10 passed in 3.99s ========================
```

### Full Test Suite (All Tests)

When running the complete test suite (including all unit tests, retry scheduler, KB, and checkpoint tests):

```
======================== 60 passed, 5 skipped in 22.64s ========================

Summary:
  • Checkpoint tests: 10 passed (new)
  • Unit ACME tests: 27 passed
  • Retry scheduler tests: 9 passed
  • Unit failure scenarios: 9 passed
  • Knowledge base tests: 5 passed
  • Integration tests: 3 skipped (no Pebble)
  • Lifecycle tests: 2 skipped (no Pebble)
```

---

## Design Rationale

### Why no Pebble?
Checkpoint mechanics are orthogonal to ACME protocol details. Mocking ACME nodes lets us test checkpointing independently, faster, and without external dependencies.

### Why multiple test groups?
- **Group 1** validates the checkpoint infrastructure exists
- **Group 2** exercises the interrupt/resume workflow
- **Group 3** verifies data integrity (no silent data loss)
- **Group 4** ensures thread isolation (important for concurrent runs)
- **Group 5** explores advanced use cases (state injection)

### Why per-test thread IDs?
Each test generates a unique `thread_id` so they don't share checkpoint history. This is essential for parallel test runners and prevents flaky tests caused by state leakage.

---

## Future Enhancements

- **Async checkpoint tests:** Add async resumption tests if Phase 4 adds async support
- **Checkpoint persistence:** Test integration with `PostgresSaver` for production durability
- **Multi-domain checkpoint:** Test interrupt/resume with SAN certificates (multiple domains in one order)
- **Checkpoint cleanup:** Test checkpoint garbage collection / history limits
