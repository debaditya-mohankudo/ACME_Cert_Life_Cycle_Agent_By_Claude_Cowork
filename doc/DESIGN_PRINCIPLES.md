# Design Principles

This is the architectural constitution for the ACME Certificate Lifecycle Agent.
Each principle is a deliberate trade-off, documented with rationale and a link to the full analysis.

---

## 1. Stateless ACME Client — All State in LangGraph

The `AcmeClient` holds no mutable state. Every value the client needs — the current nonce, the account URL, the order URL — lives in `AgentState` and is passed in explicitly.

**Why:** A stateless client is trivially testable, reproducible, and safe to recreate across nodes or machines. Hiding nonce in a client instance breaks checkpoint/restore and makes parallelization unsafe. The small cost of passing one extra argument is worth the gains in debuggability.

**Nonce ownership:** `AgentState.current_nonce` is the single source of truth for nonces between graph node boundaries. The `AcmeClient` must never store a nonce as instance state (`self.*`). Method-local nonce handling is acceptable and in two cases RFC-required:
- `_post_signed` consumes a fresh nonce from a `badNonce` error response within the same call (RFC 8555 § 6.5)
- `get_authorization` / `get_order` fetch a one-shot nonce for a single POST-as-GET poll iteration

Instance-level nonce caching across calls is never acceptable, regardless of perceived performance benefit.

→ Full analysis: [DESIGN_STATEFUL_CLIENT_ANALYSIS.md](DESIGN_STATEFUL_CLIENT_ANALYSIS.md)

---

## 2. Sequential Domain Processing — Parallelism is an Explicit Non-Goal

Domains are renewed one at a time through the LangGraph state machine. Concurrent domain processing is not supported.

**Why:** ACME nonces are single-use per connection. Parallel domains sharing a nonce would violate RFC 8555 § 6.5 and cause `badNonce` rejections. The sequential design keeps nonce flow simple and correct. If parallelism is ever needed, the migration path is per-domain nonce queues — not a stateful client.

→ Full analysis: [DESIGN_NONCE_MANAGEMENT_STRATEGY.md](DESIGN_NONCE_MANAGEMENT_STRATEGY.md)

---

## 3. LLM Advisory, Never Authoritative

The LLM (planner node) produces a renewal priority plan. Its output is always passed through a deterministic validation layer before any action is taken.

**Why:** LLMs can hallucinate domains not under management, drop domains silently, or return unparseable output. The validation layer strips hallucinated domains, recovers missing ones, and falls back to "renew everything" on JSON parse failure. The LLM's job is classification and observability — not access control over which domains get renewed.

→ Full analysis: [DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md](DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md)

---

## 4. Every Node is Idempotent

The graph is safe to resume or re-run at any node boundary. A crash at any point — before, during, or after any node — converges to correct state after resume or re-run.

**Why:** LangGraph checkpoints after each node. ACME operations (account creation, finalization, certificate download) are replay-safe by protocol design. Atomic writes ensure no corrupt intermediate state is ever visible on disk. Together these make the system robust for unattended, long-running ops.

→ Full analysis: [DESIGN_STATEFUL_CLIENT_ANALYSIS.md — Idempotency Philosophy](DESIGN_STATEFUL_CLIENT_ANALYSIS.md#idempotency-philosophy)

---

## 5. Retry Logic Isolated from Business Logic

The `error_handler` node decides *whether* to retry and *when* (sets `retry_not_before` timestamp). The `retry_scheduler` node *waits* for that time. No business logic node sleeps or loops.

**Why:** Mixing backoff sleep into ACME nodes makes them untestable without real time delays, unobservable in LangGraph traces, and impossible to interrupt cleanly. Separation means each node is a pure function of state, and the scheduler can be swapped for an async version without touching protocol code.

→ Full analysis: [DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md](DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md)

---

## 6. Atomic Writes for All Cert Artifacts

Every PEM file write (cert, key, chain, metadata) uses the pattern: write to temp file → fsync → `os.replace()`.

**Why:** A crash during a plain `write_text()` call leaves a truncated, corrupt file in place. The old file is gone. The atomic rename means a crash at any point leaves either the old file intact or the new file complete — never a partial state visible to readers.

→ Full analysis: [CERTIFICATE_STORAGE.md — Atomic Writes](README_CERTIFICATE_STORAGE.md#atomic-writes-for-data-safety)

---

## 7. Account Key Never in State

The ACME account private key is loaded from disk at the node that needs it and never stored in `AgentState`.

**Why:** LangGraph state can be persisted to LangSmith traces, database checkpoints, and log output. A private key in state would leak into all of these surfaces. The key lives at `ACCOUNT_KEY_PATH`, is read at the `acme_account_setup` node, used in-memory, and discarded. No risk of accidental exposure.

→ See: [CLAUDE.md — State & Security](../CLAUDE.md)

---

## 8. Determinism Over Throughput

When there is a choice between processing domains concurrently (faster) and processing them sequentially (simpler, correct), this system chooses sequential.

**Why:** Cert renewal is a low-frequency, high-reliability operation — typically once per domain per 60–90 days. Throughput is not the constraint. Correctness and operational predictability are. A single cert renewed successfully in 5 minutes is better than three renewals attempted in parallel with a 20% chance of nonce collisions.

**Determinism is load-bearing, not a preference.** Nonce sequencing (RFC 8555 § 6.5), LangGraph checkpoint reproducibility, and LLM output validation all depend on a deterministic execution order. Treating sequentiality as optional — even for a subset of domains — unravels multiple invariants simultaneously. This is why Hard Invariant 4 in CLAUDE.md (no concurrent ACME operations) admits no exceptions.

---

## 9. Configuration over Code for Provider Differences

All CA-specific behavior (directory URL, EAB requirement, key format) is isolated in the `AcmeClient` class hierarchy. All LLM-provider-specific behavior is isolated in `llm/factory.py`. Node code never branches on provider identity.

**Why:** Provider-specific branches in business logic make nodes harder to test in isolation, create hidden dependencies, and cause subtle bugs when a new provider is added. The factory pattern means adding a new CA or LLM provider requires changing exactly two files (`acme/client.py`, `llm/factory.py`) and zero node files.

→ See: [acme/client.py](../acme/client.py), [llm/factory.py](../llm/factory.py)

---

## 10. All Network Effects Explicitly Routed

Every node that makes a network call is a named node in the LangGraph graph. No network calls are buried in utility functions called silently from within a node.

**Why:** Named nodes appear in LangSmith traces, checkpoint history, and interrupt/resume boundaries. A network call hidden in a helper function is invisible to the graph — it can't be interrupted, observed, or retried independently. The graph topology *is* the program's visible behavior.

→ See: [HOW_IT_WORKS.md](README_HOW_IT_WORKS.md), [agent/graph.py](../agent/graph.py)

---

## 11. Revocation as a Separate Subgraph

Certificate revocation uses a dedicated LangGraph state machine (`agent/revocation_graph.py`) rather than being integrated into the renewal graph. The revocation subgraph is simpler: account setup → loop through domains → revoke each → reporter.

**Why:** Revocation has different semantics from renewal. It loops at domain granularity (no retry handler), produces no new certificates, and is typically triggered on-demand rather than scheduled. A separate graph keeps the renewal graph focused and makes revocation behavior explicit.

**No retry logic:** Revocation failures (404 Not Found, 403 Unauthorized) are logged and the loop continues (best-effort). Unlike renewal, which retries transient errors, revocation failures typically indicate protocol or policy violations that retrying won't fix.

→ See: [agent/revocation_graph.py](../agent/revocation_graph.py), [agent/nodes/revoker.py](../agent/nodes/revoker.py), [main.py](../main.py) (`run_revocation()`)

---

## Quick Reference

| Principle | Short Form | Key File |
|-----------|-----------|----------|
| Stateless client | `AcmeClient` is a function, not an object | `acme/client.py` |
| Sequential domains | One domain at a time | `agent/nodes/router.py` |
| LLM advisory only | Validate every LLM output | `agent/nodes/planner.py` |
| Idempotent nodes | Safe to resume at any boundary | `agent/graph.py` |
| Isolated retry logic | error_handler → retry_scheduler | `agent/nodes/retry_scheduler.py` |
| Atomic writes | temp + fsync + rename | `storage/atomic.py` |
| Key off state | Account key on disk only | `agent/nodes/account.py` |
| Sequential > parallel | Correctness first | `DESIGN_NONCE_MANAGEMENT_STRATEGY.md` |
| Factory pattern | No provider branches in nodes | `llm/factory.py` |
| Network calls named | All side effects in graph | `agent/graph.py` |
