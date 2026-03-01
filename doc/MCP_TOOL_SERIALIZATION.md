# MCP Tool Serialization Benefits

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- MCP usage guide: [MCP_SERVER.md](MCP_SERVER.md)
- MCP implementation details: [MCP_IMPLEMENTATION_DETAILS.md](MCP_IMPLEMENTATION_DETAILS.md)

This document explains why serializing MCP tool execution is beneficial for the ACME Certificate Lifecycle Agent.

## Context

The MCP server exposes tools that run in a single Python process and can:

- mutate process-level configuration (`config.settings`)
- execute ACME protocol operations (`renew_once`, `revoke_cert`)
- read certificate state (`list_managed_domains`, `expiring_in_30_days`, `expiring_within`, `domain_status`, `read_cert_details`)

Because some tools share global process state, concurrent execution can create race conditions unless coordinated.

## Why Serialization Helps

## 1) Preserves Deterministic Behavior

A core project principle is deterministic execution. Serializing tool calls avoids request interleaving that can produce non-deterministic outcomes (different results from the same inputs depending on timing).

## 2) Protects ACME Nonce/Protocol Safety Assumptions

ACME operations are intentionally designed for sequential processing in this project. Serialization reinforces this model at the MCP boundary so concurrent tool requests do not undermine protocol safety assumptions.

## 3) Prevents Configuration Override Races

Some tools temporarily override runtime settings for a single request. Without serialization, overlapping requests can read/write shared process configuration at the same time, causing cross-request contamination.

Serialization ensures each request sees a coherent settings snapshot for its full critical section.

### Why this still matters with Python's GIL

`config.settings` is a process-wide singleton (`config.settings = config.Settings()`).
The risk is not creating multiple singleton objects; the risk is concurrent mutation of one shared global reference.

In MCP execution, one request may temporarily override environment/config while another request is reading or reloading settings.
The GIL does not provide semantic isolation for this workflow:

- network and file I/O release the GIL, so request execution can interleave
- `config.settings` is shared process state
- overlapping overrides can cause cross-request configuration bleed

Process-wide serialization protects this critical section and keeps per-request configuration deterministic.

## 4) Improves Operational Predictability

When only one mutating operation runs at a time:

- logs are easier to reason about
- failures are easier to triage
- replay/debug behavior is more reproducible

This aligns with the project’s auditability and safety-first posture.

## 5) Reduces Risk of Hidden Side Effects

Concurrent mutations to global state can create subtle bugs that are hard to reproduce. A process-wide lock turns those hazards into explicit sequencing, reducing “heisenbugs” in production-like workflows.

## 6) Aligns with Existing Architecture Principles

Serialization directly supports the architectural constraints documented in `CLAUDE.md` and `doc/DESIGN_PRINCIPLES.md`:

- determinism over throughput
- sequential ACME operations
- explicit, auditable behavior over clever concurrency

## Trade-off

The main trade-off is reduced throughput for concurrent requests. In this project, that is an acceptable trade because certificate lifecycle operations prioritize correctness, auditability, and safety over parallel performance.

## Current Policy

Mutating tools are serialized with a process-wide `asyncio.Lock`:
- `health`, `renew_once`, `revoke_cert`, `generate_test_cert`

Read-only tools skip the lock and execute concurrently:
- `list_managed_domains`, `expiring_in_30_days`, `expiring_within`, `domain_status`, `read_cert_details`

Read-only tools are safe to run concurrently because they only read `config.settings` and `CERT_STORE_PATH` without mutating shared state or ACME protocol resources.

## Why asyncio-lock instead of threading-lock

FastMCP executes tool calls on an async path (tool dispatch, `call_tool`, and tool
execution are awaited). Our tool handlers are `async def` and can run as
concurrent asyncio tasks within the same process.

For this execution model, `asyncio.Lock` is the correct synchronization primitive:

1) Task-level mutual exclusion
	- We need to serialize async tasks handling MCP requests.
	- `asyncio.Lock` coordinates coroutine scheduling directly.

2) Prevents cross-request config bleed in async interleavings
	- Requests share process-global `config.settings`.
	- Even in one OS thread, task switches can occur at `await` points and
	  interleave critical sections unless guarded.

3) Matches FastMCP runtime semantics
	- FastMCP internals await tool execution; lock acquisition should therefore be
	  `async with ...` to avoid blocking the event loop.

4) Avoids event-loop blocking behavior
	- Threading locks are designed for thread contention and can block in ways
	  that are less natural for coroutine scheduling.
	- `asyncio.Lock` yields control while waiting, preserving event-loop health.

5) Determinism and auditability
	- The project prioritizes deterministic, auditable operations over throughput.
	- Serializing all tools with an async lock enforces predictable request order
	  at the MCP boundary.
