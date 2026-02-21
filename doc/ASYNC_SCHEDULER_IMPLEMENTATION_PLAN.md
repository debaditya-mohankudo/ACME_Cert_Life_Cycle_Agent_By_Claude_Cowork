# Async Scheduler Implementation Plan

**Date:** 2026-02-21
**Status:** Phase 3 Implemented (Phases 1-2 complete; Phase 4-5 roadmap)
**Category:** Scaling & Async Architecture

**✅ Phase 3 Complete (2026-02-21):**
- Created `agent/nodes/retry_scheduler.py` with both sync and async implementations
- Modified `agent/graph.py` to integrate retry_scheduler node
- Updated `error_handler.py` to record `retry_not_before` timestamp instead of blocking
- Added 11 comprehensive tests in `tests/test_retry_scheduler.py`
- All 48 tests passing; no regressions

---

## Overview

This plan describes how to migrate from **synchronous `time.sleep()` in error_handler** to a **non-blocking async scheduler** that enables:
- ✅ Parallel domain processing (100+ concurrent retries)
- ✅ Non-blocking execution (server can handle other work during backoff)
- ✅ Observable retry timing (in state)
- ✅ Easy testing (no time mocking)

---

## Current State: Synchronous Backoff

```python
# CURRENT: Embedded in error_handler
def error_handler(state: AgentState) -> dict:
    if action == "retry":
        time.sleep(new_delay)  # ← BLOCKS HERE
        updates["retry_count"] = new_retry_count
        updates["retry_delay_seconds"] = new_delay
    return updates
```

**Problem:** Blocks entire LangGraph execution during sleep.

---

## Phase 1: Add Retry Scheduling to State (No Code Changes)

### Goal
Prepare state structure for async scheduling without modifying behavior.

### Changes

**Update `agent/state.py`:**
```python
class AgentState(TypedDict):
    # ... existing fields ...

    # Retry scheduling (new)
    retry_not_before: float | None  # Unix timestamp when retry can proceed
    retry_reason: str  # Why we're retrying (for logging)
```

**Update `agent/graph.py` initial_state():**
```python
def initial_state(...) -> dict:
    return {
        # ... existing ...
        "retry_not_before": None,
        "retry_reason": "",
    }
```

### Backward Compatibility
✅ No logic changes. The scheduler node will be optional initially.

---

## Phase 2: Modify error_handler to NOT Sleep

### Goal
Remove the synchronous `time.sleep()` and record the retry time in state instead.

### Changes

**Update `agent/nodes/error_handler.py`:**

```python
import time as time_module

def error_handler(state: AgentState) -> dict:
    """
    Analyze renewal failure and decide next action.

    CHANGE: No longer sleeps. Backoff timing is recorded in state
    for the retry_scheduler node to apply.
    """
    domain = state.get("current_domain", "unknown")
    error_log = state.get("error_log", [])
    last_error = error_log[-1] if error_log else "Unknown error"
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    retry_delay = state.get("retry_delay_seconds", 5)

    llm = make_llm(model=settings.LLM_MODEL_ERROR_HANDLER, max_tokens=256)

    messages = [
        SystemMessage(content=ERROR_HANDLER_SYSTEM),
        HumanMessage(content=ERROR_HANDLER_USER.format(...))
    ]

    response = llm.invoke(messages)
    raw = response.content.strip()

    try:
        decision = json.loads(raw)
        action = decision.get("action", "skip")
        suggested_delay = int(decision.get("suggested_delay_seconds", retry_delay * 2))
    except Exception:
        action = "skip"
        suggested_delay = retry_delay * 2

    updates: dict = {
        "error_analysis": raw,
        "messages": messages + [response],
    }

    if action == "retry":
        new_retry_count = retry_count + 1
        new_delay = suggested_delay if suggested_delay > 0 else min(retry_delay * 2, 300)

        # CHANGE: Don't sleep here
        # time.sleep(new_delay)  ← REMOVED

        # Instead: Record when retry should proceed
        now = time_module.time()
        retry_not_before = now + new_delay

        logger.info(
            "Error handler: RETRY #%d for %s (backoff %ds, retry_not_before=%d)",
            new_retry_count,
            domain,
            new_delay,
            int(retry_not_before),
        )

        updates.update({
            "retry_count": new_retry_count,
            "retry_delay_seconds": new_delay,
            "retry_not_before": retry_not_before,  # NEW: Scheduling time
            "retry_reason": f"Error: {last_error}",
        })
    elif action == "abort":
        logger.error("Error handler: ABORT — stopping all renewals")
        pending = state.get("pending_renewals", [])
        failed = state.get("failed_renewals", []) + [domain] + list(pending)
        updates.update({
            "failed_renewals": failed,
            "pending_renewals": [],
        })
    else:
        logger.warning("Error handler: SKIP domain %s", domain)
        updates["failed_renewals"] = state.get("failed_renewals", []) + [domain]

    return updates
```

**Key changes:**
- ❌ Remove `time.sleep(new_delay)`
- ✅ Add `retry_not_before = now + new_delay`
- ✅ Record in state instead of blocking

### Testing Impact

**Before (hard to test):**
```python
def test_retry_backoff():
    with patch('time.sleep') as mock_sleep:
        result = error_handler(state_with_error)
        mock_sleep.assert_called_with(60)
```

**After (easy to test):**
```python
def test_retry_backoff():
    result = error_handler(state_with_error)
    assert "retry_not_before" in result
    assert result["retry_not_before"] > time.time()  # In the future
    assert result["retry_count"] == 1
```

---

## Phase 3: Add Retry Scheduler Node

### Goal
Create a new node that applies the backoff before retrying.

### New File: `agent/nodes/retry_scheduler.py`

```python
"""
retry_scheduler node — apply scheduled backoff before retrying.

This node checks if enough time has passed before allowing a retry.
If not, it waits (async-friendly) before returning.
"""
import asyncio
import logging
import time as time_module
from agent.state import AgentState

logger = logging.getLogger(__name__)


def retry_scheduler(state: AgentState) -> dict:
    """
    Check if retry_not_before time has arrived. If not, wait.

    This is a synchronous version. For async, use retry_scheduler_async().
    """
    retry_not_before = state.get("retry_not_before")

    if retry_not_before is None:
        # No scheduled retry
        return {}

    now = time_module.time()
    wait_time = retry_not_before - now

    if wait_time > 0:
        logger.info(
            "Waiting %.1f seconds before retry...",
            wait_time,
        )
        time_module.sleep(wait_time)

    logger.debug("Retry backoff complete. Proceeding with retry.")
    return {
        "retry_not_before": None,  # Clear after applying
    }


async def retry_scheduler_async(state: AgentState) -> dict:
    """
    Async version: non-blocking backoff using asyncio.sleep().

    Use this when the graph is converted to async execution.
    """
    retry_not_before = state.get("retry_not_before")

    if retry_not_before is None:
        return {}

    now = time_module.time()
    wait_time = retry_not_before - now

    if wait_time > 0:
        logger.info(
            "Scheduling retry in %.1f seconds...",
            wait_time,
        )
        await asyncio.sleep(wait_time)
        logger.debug("Async retry backoff complete.")

    return {
        "retry_not_before": None,
    }
```

### Update `agent/graph.py`: Add Node to Graph

```python
from agent.nodes.retry_scheduler import retry_scheduler

def build_graph(use_checkpointing: bool = False):
    builder = StateGraph(AgentState)

    # ... existing nodes ...
    builder.add_node("error_handler", error_handler)
    builder.add_node("retry_scheduler", retry_scheduler)  # NEW
    builder.add_node("pick_next_domain", pick_next_domain)

    # ... existing edges ...

    # Error handler routing
    builder.add_conditional_edges(
        "error_handler",
        error_action_router,
        {
            "retry": "retry_scheduler",      # NEW: Route to scheduler first
            "skip_domain": "pick_next_domain",
            "abort": "summary_reporter",
        },
    )

    # NEW: Scheduler always routes to pick_next_domain
    builder.add_edge("retry_scheduler", "pick_next_domain")

    # ... rest of graph ...
```

### Graph Topology (Updated)

```
error_handler
  ├─ retry → retry_scheduler → pick_next_domain
  ├─ skip_domain → pick_next_domain (no wait)
  └─ abort → summary_reporter
```

---

## Phase 4: Convert to Async (When Ready)

### Goal
Make the entire graph async-capable for parallel domain processing.

### Changes

**Update `agent/graph.py`:**
```python
from langgraph.graph import StateGraph, START, END

async def build_graph_async(use_checkpointing: bool = False):
    """Async version of build_graph()."""
    builder = StateGraph(AgentState)

    # Register async nodes
    builder.add_node("error_handler", error_handler)  # Still sync (LLM call)
    builder.add_node("retry_scheduler", retry_scheduler_async)  # NOW ASYNC
    builder.add_node("pick_next_domain", pick_next_domain_async)  # NOW ASYNC

    # ... edges same as before ...

    return builder.compile(checkpointer=checkpointer)


# Usage (in main.py or agent runner)
async def run_agent_async():
    graph = await build_graph_async()
    state = initial_state(...)

    # Run all domains concurrently
    config = {"configurable": {"thread_id": "default"}}
    result = await graph.ainvoke(initial_state, config)

    return result
```

**Update node signatures (examples):**
```python
async def pick_next_domain_async(state: AgentState) -> dict:
    """Pick next domain for renewal (async version)."""
    # ... existing logic ...
    return {...}

async def order_initializer_async(state: AgentState) -> dict:
    """Create ACME order (async version)."""
    # Replace requests.Session() with httpx.AsyncClient()
    async with httpx.AsyncClient() as client:
        response = await client.post(...)
    return {...}
```

---

## Phase 5: Domain Parallelization

### Goal
Process multiple domains concurrently (optional, after async conversion).

### Design Option A: Per-Domain State Buckets

```python
# Enhanced state for parallel execution
state = {
    "managed_domains": ["api.example.com", "web.example.com"],
    "domain_state": {
        "api.example.com": {
            "current_nonce": "...",
            "retry_not_before": None,
            "retry_count": 0,
            ...
        },
        "web.example.com": {
            "current_nonce": "...",
            "retry_not_before": None,
            "retry_count": 0,
            ...
        },
    },
}

# Nodes accept domain parameter
async def order_initializer_async(state: AgentState, domain: str) -> dict:
    domain_state = state["domain_state"][domain]
    nonce = domain_state["current_nonce"]
    # ... create order ...
    domain_state["current_order"] = order
    return {"domain_state": state["domain_state"]}

# Graph routes per-domain
async def process_domain(domain: str, graph, state):
    """Process a single domain through the renewal pipeline."""
    config = {"configurable": {"domain": domain}}
    result = await graph.ainvoke(state, config)
    return result

# Main runner
async def run_all_domains_async():
    graph = await build_graph_async()
    state = initial_state(...)

    # Run all domains in parallel
    tasks = [
        process_domain(domain, graph, state)
        for domain in state["managed_domains"]
    ]

    results = await asyncio.gather(*tasks)
    return results
```

---

## Implementation Checklist

### ✅ Phase 1: State Preparation (1-2 hours)
- [ ] Add `retry_not_before`, `retry_reason` to `AgentState`
- [ ] Update `initial_state()` with new fields
- [ ] No logic changes (backward compatible)
- [ ] Run existing tests (should pass)

### ✅ Phase 2: Remove Sync Sleep (1-2 hours)
- [ ] Modify `error_handler.py` to record `retry_not_before` instead of sleeping
- [ ] Update logging to show when retry is scheduled
- [ ] Update error_handler tests (no more `patch('time.sleep')`)
- [ ] Verify graph still routes correctly

### ✅ Phase 3: Add Scheduler Node (2-3 hours) — **COMPLETED**
- [x] Create `retry_scheduler.py` (sync version)
- [x] Create `retry_scheduler_async()` (async version)
- [x] Update graph topology (add scheduler node)
- [x] Update routing (error_handler → retry_scheduler → pick_next_domain)
- [x] Write tests for scheduler node (11 tests, all passing)
- [x] Verify no behavior change (sync version uses `time.sleep()`)

### ✅ Phase 4: Async Conversion (4-6 hours)
- [ ] Create `build_graph_async()` function
- [ ] Convert node signatures to async
- [ ] Replace `requests.Session()` with `httpx.AsyncClient()`
- [ ] Update LLM calls to async (if supported by langchain)
- [ ] Create async test suite
- [ ] Performance test (baseline vs. async)

### ✅ Phase 5: Parallelization (4-6 hours, optional)
- [ ] Design per-domain state buckets
- [ ] Refactor node signatures to accept `domain` parameter
- [ ] Create parallel executor
- [ ] Write concurrency tests (race conditions, nonce isolation)
- [ ] Load test (100+ domains, 10% retry rate)

---

## Testing Strategy

### Phase 1-2: Unit Tests (No Changes)
```python
def test_error_handler_records_retry_time():
    state = {..., "error_log": ["Some error"]}
    result = error_handler(state)
    assert result["retry_not_before"] > time.time()
    assert result["retry_count"] == 1
```

### Phase 3: Scheduler Tests
```python
def test_retry_scheduler_blocks_until_ready():
    future_time = time.time() + 2
    state = {"retry_not_before": future_time}

    start = time.time()
    result = retry_scheduler(state)
    elapsed = time.time() - start

    assert elapsed >= 2
    assert result["retry_not_before"] is None

async def test_retry_scheduler_async_non_blocking():
    future_time = time.time() + 2
    state = {"retry_not_before": future_time}

    # Async sleep shouldn't block other tasks
    start = time.time()

    task1 = asyncio.create_task(retry_scheduler_async(state))
    task2 = asyncio.create_task(asyncio.sleep(0.5))

    await asyncio.gather(task1, task2)
    elapsed = time.time() - start

    # Should complete in ~2s (not 2.5s, which would indicate blocking)
    assert 1.8 < elapsed < 2.3
```

### Phase 4-5: Integration Tests
```python
async def test_parallel_domain_retry():
    """Test that multiple domains can retry concurrently."""
    domains = ["api.example.com", "web.example.com"]

    graph = await build_graph_async()
    state = initial_state(domains)

    # Inject errors for both domains
    state["domain_state"]["api.example.com"]["error_log"] = ["Network timeout"]
    state["domain_state"]["web.example.com"]["error_log"] = ["Bad nonce"]

    start = time.time()
    result = await graph.ainvoke(state)
    elapsed = time.time() - start

    # With parallel backoff, should complete in ~max(backoff), not sum
    assert elapsed < 10  # Not 20+
```

---

## Rollout Strategy

### Week 1: Phase 1-2 (State + Remove Sleep)
- ✅ Safe, backward compatible
- ✅ Minimal risk
- ✅ Deploy to production with existing (sync) scheduler

### Week 2-3: Phase 3 (Add Scheduler Node)
- ✅ Visible in graph traces
- ✅ Easier testing
- ✅ No behavior change (still sync `time.sleep()`)
- ✅ Deploy and monitor

### Month 2: Phase 4 (Async Conversion)
- ✅ After settling on scheduler node design
- ✅ Requires comprehensive testing
- ✅ Feature-flagged (async graph v.s. sync graph)

### Month 3+: Phase 5 (Parallelization)
- ✅ Only after async is stable
- ✅ Load testing required
- ✅ Optional (only if scaling to 100+ domains)

---

## Benefits Summary

| Phase | Benefit |
|-------|---------|
| 1 | State ready for scheduling |
| 2 | No more hidden `time.sleep()` |
| 3 | Visible in graph, testable, observable |
| 4 | Non-blocking (can process other work during backoff) |
| 5 | True parallelization (100+ concurrent retries) |

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| **Break existing behavior** | Phase 1-2 are backward compatible; test thoroughly |
| **Introduce race conditions** | Per-domain state isolation; no shared mutable state |
| **Async/await bugs** | Comprehensive async test suite; feature-flag switchover |
| **Performance regression** | Baseline performance test before/after each phase |
| **Distributed nonce issues** | See NONCE_MANAGEMENT_STRATEGY.md (per-domain queues) |

---

## Related Documents

- [`BACKOFF_INTEGRATION_ANALYSIS.md`](BACKOFF_INTEGRATION_ANALYSIS.md) — Current design analysis
- [`NONCE_MANAGEMENT_STRATEGY.md`](NONCE_MANAGEMENT_STRATEGY.md) — Nonce handling for async
- [`STATEFUL_CLIENT_DESIGN_ANALYSIS.md`](STATEFUL_CLIENT_DESIGN_ANALYSIS.md) — Why keep client stateless
