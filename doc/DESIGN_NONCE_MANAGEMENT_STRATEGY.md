# Nonce Management Strategy & Parallelization Risk

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- RFC compliance: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- Design principles: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)

**Date:** 2026-02-21
**Status:** Design Decision & Risk Analysis
**Category:** ACME Protocol & Concurrency

---

## Concurrency is an Explicit Non-Goal

**Parallel domain renewal is intentionally not supported in this architecture.**

This is a deliberate design decision, not an oversight or a limitation waiting to be fixed.

The nonce model in ACME (RFC 8555) requires every signed POST to carry a single-use nonce obtained from a previous response. A shared `current_nonce` in state is fundamentally incompatible with concurrent domain processing — two domains reading the same nonce and each attempting to use it will result in `badNonce` rejections from the CA.

Making parallelism work correctly requires a non-trivial change to the state structure (per-domain nonce queues) and node signatures. That change is documented as a future migration path if throughput ever becomes a constraint, but it will not be made speculatively.

> **Any future refactor that processes multiple domains concurrently MUST first implement per-domain nonce isolation. Skipping this step will silently break ACME compliance.**

The migration path is documented in the [Migration Path](#migration-path-when-parallelization-is-needed) section below.

---

## Overview

The agent uses **stateful nonce management** where `current_nonce` flows through the LangGraph state during sequential domain processing. This document explains the design, identifies parallelization risks, and provides migration paths for future multi-domain parallelization.

---

## Current Design (Sequential Processing)

### How It Works

```
State flow through the graph:
┌─────────────────────────────────────────────────────────┐
│ initial_state()                                         │
│   current_nonce = client.get_nonce(directory)          │
│   managed_domains = ["api.example.com", ...]           │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│ scanner (per domain)                                    │
│   current_nonce = state["current_nonce"]  ✓ read-only  │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│ planner (LLM)                                           │
│   pending_renewals = ["api.example.com"]               │
│   current_nonce = state["current_nonce"]  ✓ unchanged  │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│ For each domain in pending_renewals:                    │
│   account → order → challenge → csr → finalize → ...   │
│   Each node updates: current_nonce = resp.headers[...]  │
│   Next node reads the updated nonce                     │
└────────────────────┬────────────────────────────────────┘
```

### Code Example

```python
def account_registration(state: AgentState) -> dict:
    """Register ACME account."""
    client = make_client()

    # Read current nonce from state (immutable)
    current_nonce = state["current_nonce"]

    # Use it for this request
    account_url, new_nonce = client.create_account(
        account_key=account_key,
        nonce=current_nonce,
        directory=directory,
    )

    # Return new nonce for next node
    return {
        "account_url": account_url,
        "current_nonce": new_nonce,  # Updated for next node
    }
```

**Key property:** Each node receives a fresh nonce from the previous node, and passes it forward. No global state, no race conditions (yet).

---

## Why This Design Works (Currently)

### ✅ Sequential Execution
- Domains are processed **one at a time** through the state machine
- Each domain's renewal flow is atomic within its domain:
  ```
  domain_A: scan → plan → account → order → ... (complete)
  domain_B: scan → plan → account → order → ... (starts after domain_A finishes)
  ```
- Nonce freshness is maintained: each ACME call gets a unique nonce

### ✅ Nonce Freshness
- `current_nonce` is **never reused** within a single domain's flow
- Each ACME call returns a fresh nonce via `Replay-Nonce` header
- The nonce flows forward through the state atomically

### ✅ ACME RFC 8555 Compliance
- RFC 8555 § 6.5 requires: *"Each request must have a fresh nonce"*
- Current design satisfies this: one nonce per POST request, updated from response

---

## The Parallelization Problem

### ⚠️ Scenario: Parallel Domain Processing

**Hypothetical future design:**

```python
# Conceptual (NOT REAL, WOULD BE BROKEN)
async def process_domains_parallel(state: AgentState):
    """Process multiple domains simultaneously."""
    tasks = []
    for domain in state["pending_renewals"]:
        task = asyncio.create_task(
            process_single_domain(domain, state)  # ← DANGEROUS
        )
        tasks.append(task)

    results = await asyncio.gather(*tasks)
    return combine_results(results)
```

### 🔴 Problem 1: Nonce Reuse Between Domains

**Timeline:**
```
Time T0:
  - domain_A reads state["current_nonce"] = "nonce123"
  - domain_B reads state["current_nonce"] = "nonce123"  ← SAME nonce!

Time T1:
  - domain_A sends POST /newAccount with nonce123
  - domain_B sends POST /newOrder with nonce123  ← VIOLATION!

ACME server:
  - Accepts domain_A's request, returns fresh nonce456
  - Rejects domain_B's request: "badNonce — nonce already used"
```

**Result:** Domain B fails with `urn:ietf:params:acme:error:badNonce` (state 400).

### 🔴 Problem 2: Race Condition on Nonce Update

**Timeline:**
```
Time T0:
  - domain_A gets response with Replay-Nonce: "nonce456"
  - domain_B gets response with Replay-Nonce: "nonce789"

Time T1:
  - domain_A: state["current_nonce"] = "nonce456"  (write)
  - domain_B: state["current_nonce"] = "nonce789"  (write)  ← racing!

Result: state["current_nonce"] = "nonce789" or "nonce456"?
Next node (domain_C) uses whichever write won the race.
```

**Result:** Nonce state is inconsistent; domain_C uses stale or wrong nonce.

### 🔴 Problem 3: Ordering Guarantee Lost

**Timeline:**
```
domain_A: account → order → challenge → finalize
domain_B: account → order → challenge → finalize

Parallel execution:
  T0: domain_A.account() reads nonce123
  T0: domain_B.account() reads nonce123
  T1: domain_B.account() completes, updates nonce456
  T2: domain_A.order() tries to use nonce from domain_B's response!
```

**Result:** Nonce streams are tangled; ACME protocol breaks.

---

## Why This Hasn't Been a Problem

1. **Sequential by design:** LangGraph routes through a single domain's lifecycle at a time
2. **No parallelization attempt yet:** No code tries to process multiple domains concurrently
3. **Defensive nonce retry:** If a nonce is reused, ACME returns `badNonce`, and `_post_signed()` retries with a fresh nonce (automatic recovery)

---

## Risk Assessment

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| Nonce reuse between domains | 🔴 High | 🟢 Low (no parallelization today) | Per-domain nonce queues |
| Race condition on state update | 🔴 High | 🟢 Low (sequential execution) | Thread-safe nonce manager |
| ACME protocol violation | 🔴 High | 🟢 Low (defensive retry) | Structured nonce handoff |
| Undetected nonce corruption | 🟡 Medium | 🟡 Medium (under high load) | Assertions & monitoring |

**Current risk level: LOW** (sequential execution is safe)
**Future risk level: HIGH** (if parallelization is added without refactoring)

---

## Migration Path: When Parallelization Is Needed

### Option 1: Domain-Specific Nonce Queues (Recommended)

Keep parallelization but ensure each domain has its own nonce state:

```python
# Enhanced state for parallel execution
state = {
    "managed_domains": ["api.example.com", "web.example.com"],
    "nonce_queue": {
        "api.example.com": "nonce123_for_api",
        "web.example.com": "nonce456_for_web",
    },
    "pending_renewals": {
        "api.example.com": AcmeOrder(...),
        "web.example.com": AcmeOrder(...),
    },
}

# Each domain's nodes read/write its own nonce
def account_registration(state: AgentState, domain: str) -> dict:
    domain_nonce = state["nonce_queue"][domain]

    account_url, new_nonce = client.create_account(nonce=domain_nonce, ...)

    # Update only this domain's nonce
    state["nonce_queue"][domain] = new_nonce

    return {"account_url": account_url}
```

**Pros:**
- ✅ Domains are truly independent
- ✅ No cross-domain interference
- ✅ Scales to 100+ domains
- ✅ Minimal refactoring needed

**Cons:**
- ⚠️ State structure changes
- ⚠️ Node signature changes (need to pass domain context)

### Option 2: Nonce Manager Service (Enterprise Scale)

For very high-scale scenarios, use a dedicated nonce service:

```python
class NonceManager:
    """Thread-safe nonce manager for parallel domains."""

    def __init__(self, client: AcmeClient, directory: dict):
        self.client = client
        self.directory = directory
        self.nonces: Dict[str, str] = {}  # domain → nonce
        self.lock = asyncio.Lock()  # protect concurrent access

    async def get_fresh_nonce(self, domain: str) -> str:
        """Get a fresh nonce for this domain (thread-safe)."""
        async with self.lock:
            if domain not in self.nonces:
                self.nonces[domain] = self.client.get_nonce(self.directory)
            return self.nonces[domain]

    async def update_nonce(self, domain: str, new_nonce: str):
        """Update nonce after ACME call (thread-safe)."""
        async with self.lock:
            self.nonces[domain] = new_nonce
```

**Pros:**
- ✅ Handles many domains safely
- ✅ Automatic nonce refresh
- ✅ Observable (metrics, logging)

**Cons:**
- ⚠️ Added infrastructure
- ⚠️ More complex testing
- ⚠️ Overkill for < 10 domains

### Option 3: Immutable Nonce Per Domain (Functional Approach)

Treat each domain's nonce as immutable within its lifecycle:

```python
# Create a "domain context" that includes its nonce
@dataclass
class DomainContext:
    domain: str
    current_nonce: str
    account_key: JWKRSA
    account_url: str

# Nodes receive domain context, return updated context
def order_creation(context: DomainContext) -> DomainContext:
    order, order_url, new_nonce = client.create_order(
        nonce=context.current_nonce, ...
    )
    return DomainContext(
        domain=context.domain,
        current_nonce=new_nonce,  # Return new context
        account_key=context.account_key,
        account_url=context.account_url,
    )
```

**Pros:**
- ✅ Functional, side-effect free
- ✅ Composes naturally with async
- ✅ Testable in isolation

**Cons:**
- ⚠️ More data copying
- ⚠️ Changes node interfaces

---

## Recommendation

### Short-term (Now)
✅ **Keep current sequential design.** It's correct, safe, and maintainable.

### Medium-term (When Parallelization Is Needed)
🎯 **Option 1: Domain-Specific Nonce Queues**
- Minimal code changes
- Scales well
- Still leverages LangGraph's state management

### Long-term (Enterprise Multi-Tenant)
🏢 **Option 2: Nonce Manager Service**
- If you hit thousands of domains
- If latency becomes a factor
- If observability/metrics are critical

---

## Safeguards (Current Code)

The current implementation has defensive safeguards:

### 1. Pre-Signing Nonce Validation
```python
# From acme/jws.py — sign_request()
if not nonce or not nonce.strip():
    raise ValueError("nonce must not be empty — call get_nonce() before signing")
if not url or not url.strip():
    raise ValueError("url must not be empty")
```

**Effect:** An empty or whitespace-only nonce is caught at the call site — before
any JWS is built and before any network call is made. Failure surfaces as a
`ValueError` in the signing layer rather than a `badNonce` response from the CA.
The URL guard is symmetric: an empty URL would produce a JWS bound to no endpoint.

### 2. Nonce Retry Logic
```python
# From acme/client.py
if "badNonce" in error_body.get("type", "") and attempt < _NONCE_RETRIES - 1:
    # Automatically retry with fresh nonce
    fresh = resp.headers.get("Replay-Nonce")
    current_nonce = fresh
    continue
```

**Effect:** If a nonce is reused, ACME rejects it, and the client automatically retries with a fresh nonce from the error response.

### 3. Assertion on Nonce Presence in Response
```python
# From acme/client.py
if not nonce:
    raise AcmeError(resp.status_code, {"detail": "No Replay-Nonce header"})
```

**Effect:** Missing nonce in a CA response is detected immediately; never silently ignored.

---

## Testing & Validation

### Current Tests
- ✅ `test_unit_acme.py` — nonce handling in sequential calls
- ✅ `test_unit_acme.py` — `test_sign_request_rejects_empty_nonce` / `test_sign_request_rejects_whitespace_nonce` — pre-signing guard
- ✅ `test_unit_acme.py` — `test_sign_request_rejects_empty_url` / `test_sign_request_rejects_whitespace_url` — URL pre-condition guard
- ✅ `test_unit_failure_scenarios.py` — `test_bad_nonce_retries_and_succeeds` — nonce retry logic
- ✅ `test_integration_pebble.py` — full lifecycle with real nonce exchange

### Tests Needed for Parallelization
- ❌ Concurrent nonce handling (N domains, M concurrent requests)
- ❌ Race condition detection
- ❌ Nonce state consistency under load
- ❌ Per-domain nonce isolation

---

## Decision

**Current design is correct and safe for sequential processing.**

**If parallelization is added:**
1. Implement **domain-specific nonce queues** (Option 1)
2. Add concurrent nonce handling tests
3. Use `asyncio.Lock()` or similar for nonce manager thread safety
4. Monitor nonce reuse/badNonce rate in production

**Do NOT attempt parallel domain processing without first refactoring nonce management.**

---

## Related Documents

- [`ACME_AGENT_PLAN.md`](ACME_AGENT_PLAN.md) — Agent architecture
- [`agent/state.py`](../agent/state.py) — State definition
- [`acme/client.py`](../acme/client.py) — Nonce handling & retry logic
- [`CLAUDE.md`](../CLAUDE.md) — Account key security (why not in state)
