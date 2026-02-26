# Stateful Client Design Analysis: Per-Domain AcmeClient with Private Nonce

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Nonce management: [DESIGN_NONCE_MANAGEMENT_STRATEGY.md](DESIGN_NONCE_MANAGEMENT_STRATEGY.md)
- Certificate storage: [CERTIFICATE_STORAGE.md](CERTIFICATE_STORAGE.md)

**Date:** 2026-02-21
**Status:** Design Exploration & Trade-off Analysis
**Category:** Architecture Alternative

---

## Proposal

Instead of the current design:
```python
# Current: Stateless client, nonce flows through state
client = AcmeClient(directory_url)  # Instantiated once
nonce = state["current_nonce"]
response = client.create_account(nonce=nonce, ...)
state["current_nonce"] = response.headers["Replay-Nonce"]
```

Propose a stateful alternative:
```python
# Proposed: Stateful client, nonce encapsulated
client = AcmeClient(directory_url)  # Per-domain instance
client._nonce = ...  # Private, managed by client
response = client.create_account(...)  # Nonce handled internally
# No nonce in state
```

---

## Benefits of Stateful Client Design

### ✅ 1. Natural Parallelization Support

Each domain gets its own client instance with its own nonce:

```python
# Pseudo-code: concurrent domain processing
clients = {
    "api.example.com": AcmeClient(directory_url, _nonce="nonce_api"),
    "web.example.com": AcmeClient(directory_url, _nonce="nonce_web"),
}

async def process_domain(domain, client):
    await client.create_account(...)  # Uses client._nonce internally
    await client.create_order(...)    # Gets fresh nonce from response
    # No race conditions, no nonce reuse between domains

# Run all domains in parallel
await asyncio.gather(
    process_domain("api.example.com", clients["api.example.com"]),
    process_domain("web.example.com", clients["web.example.com"]),
)
```

**No synchronization needed.** Each client is independent.

### ✅ 2. Simpler Node Signatures

**Current (complex):**
```python
def account_registration(state: AgentState) -> dict:
    client = make_client()
    current_nonce = state["current_nonce"]  # Extract from state
    directory = state["directory"]

    account_url, new_nonce = client.create_account(
        nonce=current_nonce,
        directory=directory,
        ...
    )

    return {
        "account_url": account_url,
        "current_nonce": new_nonce,  # Put back in state
        "messages": ...,
    }
```

**Proposed (simpler):**
```python
def account_registration(state: AgentState) -> dict:
    client = state["domain_client"]  # Client manages its own nonce

    account_url = client.create_account(...)  # Nonce handled internally

    return {
        "account_url": account_url,
        "messages": ...,
    }
```

**Benefits:**
- ✅ Fewer state field passing
- ✅ Client encapsulates nonce logic
- ✅ Less error-prone

### ✅ 3. Encapsulation & Separation of Concerns

```python
class AcmeClient:
    def __init__(self, directory_url: str):
        self.directory_url = directory_url
        self._nonce = None  # PRIVATE
        self._session = requests.Session()

    def _ensure_nonce(self) -> str:
        """Get fresh nonce if needed."""
        if self._nonce is None:
            self._nonce = self.get_nonce(self.get_directory())
        return self._nonce

    def _update_nonce(self, new_nonce: str):
        """Update nonce from ACME response."""
        self._nonce = new_nonce

    def create_account(self, account_key: JWKRSA, ...):
        """Nonce handling is opaque to caller."""
        nonce = self._ensure_nonce()
        resp = self._post_signed(payload, nonce=nonce, ...)
        self._update_nonce(resp.headers.get("Replay-Nonce"))
        return resp.json()
```

**Result:** Nonce management is internal implementation detail, not caller concern.

### ✅ 4. Automatic Nonce Freshness

Client can proactively refresh nonce before use:

```python
def _ensure_nonce(self) -> str:
    """Refresh nonce if it's getting stale."""
    if self._nonce is None or self._nonce_age > timedelta(minutes=10):
        self._nonce = self.get_nonce(self.get_directory())
        self._nonce_created = datetime.now()
    return self._nonce
```

---

## Drawbacks & Challenges

### 🔴 1. Breaks Stateless Client Philosophy

Current design principle: **client is stateless, all state flows through LangGraph**.

```python
# Current: Stateless (testable, reproducible)
client1 = AcmeClient(url)
client2 = AcmeClient(url)
# Both identical, no hidden state

# Proposed: Stateful (harder to reason about)
client1 = AcmeClient(url)
client1._nonce = "nonce123"
client2 = AcmeClient(url)
client2._nonce = "nonce456"
# Different behavior even though they look the same
```

**Impact:** Code becomes less predictable, harder to test in isolation.

### 🔴 2. Testing Becomes Harder

**Current (easy to test):**
```python
def test_account_creation():
    client = AcmeClient(directory_url)
    # Mock HTTP
    nonce = "test_nonce"
    account_url, new_nonce = client.create_account(
        account_key=key,
        nonce=nonce,  # Explicit, easy to control
        directory=directory,
    )
    assert account_url == "..."
```

**Proposed (harder to test):**
```python
def test_account_creation():
    client = AcmeClient(directory_url)
    client._nonce = "test_nonce"  # Hidden dependency
    # Mock HTTP
    account_url = client.create_account(account_key=key, ...)
    # Which nonce was used? Have to inspect client._nonce or mock internals
```

**Issues:**
- ❌ Testing internal state (`client._nonce`)
- ❌ Hidden dependencies in test setup
- ❌ Harder to verify correct nonce flow
- ❌ More brittle to refactoring

### 🔴 3. Loss of State Visibility in LangGraph

**Current:**
```python
state["current_nonce"]  # Visible in state, can inspect/debug
```

**Proposed:**
```python
state["domain_client"]._nonce  # Hidden in client, not visible
```

**Impact:**
- ❌ LangSmith traces don't show nonce (important for debugging)
- ❌ State snapshots don't capture nonce (can't replay runs)
- ❌ Harder to debug across node boundaries
- ❌ Loss of audit trail

### 🔴 4. Nonce Persistence Across Runs

**Current (simple):**
```python
# Save state to disk
state_json = {
    "current_nonce": "nonce123",
    "account_url": "...",
    ...
}
save_to_disk(state_json)

# Later: restore
loaded_state = load_from_disk()
nonce = loaded_state["current_nonce"]
```

**Proposed (complex):**
```python
# Save state to disk
state_json = {
    "domain_client": ??? # How do you serialize a client?
}

# Can't easily serialize client._nonce without custom serialization
```

**Issues:**
- ❌ Requires custom serialization/deserialization
- ❌ Checkpoint/recovery becomes harder
- ❌ LangGraph's built-in state persistence doesn't work

### 🔴 5. Multiple Instances Overhead

**Current:**
```python
client = make_client()  # Reused across all nodes
# One HTTP session, one TLS context
```

**Proposed:**
```python
# Create one client per domain
clients = {}
for domain in managed_domains:
    clients[domain] = AcmeClient(directory_url)

# Result: N clients = N HTTP sessions, N TLS contexts
# Memory overhead, connection pool complexity
```

**Impact on 100 domains:**
- 100 separate HTTP connections
- 100 TLS handshakes
- 100× memory for client objects
- Connection pool fragmentation

### 🔴 6. Distributed Execution Becomes Unsafe

If you scale to **multi-machine deployment** (worker nodes):

**Current (safe):**
```python
# Each worker gets state, creates fresh client
state = load_from_central_store()
client = AcmeClient(url)  # Fresh, no nonce yet
response = client.create_account(nonce=state["current_nonce"], ...)
# Safe to distribute
```

**Proposed (unsafe):**
```python
# Client instance can't be serialized across machines
client = AcmeClient(url)
client._nonce = "nonce123"
# Send to another machine? Serialize client._nonce separately?
# Risk of deserialization bugs, version mismatches
```

---

## Comparison: Current vs. Proposed

| Dimension | Current (Stateless) | Proposed (Stateful) |
|-----------|---|---|
| **Parallelization support** | 🔴 Requires per-domain nonce queue | 🟢 Natural, one client per domain |
| **Node signatures** | 🔴 Complex (nonce in state) | 🟢 Simple (nonce in client) |
| **Encapsulation** | 🟡 Nonce explicit to caller | 🟢 Nonce hidden in client |
| **Testing** | 🟢 Easy, explicit dependencies | 🔴 Hard, hidden state |
| **State visibility** | 🟢 Full visibility in LangGraph | 🔴 Hidden from state |
| **Persistence** | 🟢 Built-in (state serializable) | 🔴 Custom (client not serializable) |
| **Memory overhead** | 🟢 One client | 🔴 N clients (one per domain) |
| **Distributed execution** | 🟢 Safe (stateless) | 🔴 Risky (client objects) |
| **Debuggability** | 🟢 Full nonce trace in logs | 🔴 Nonce hidden in client |
| **Checkpoint/recovery** | 🟢 Easy (state is checkpoint) | 🔴 Requires custom logic |

---

## Hybrid Approach (Best of Both Worlds)

Keep stateless client, but prepare for parallelization with **per-domain state buckets**:

```python
# State structure ready for parallelization
state = {
    "managed_domains": ["api.example.com", "web.example.com"],
    "domain_state": {
        "api.example.com": {
            "current_nonce": "nonce_api",
            "account_url": "...",
            "order": {...},
        },
        "web.example.com": {
            "current_nonce": "nonce_web",
            "account_url": "...",
            "order": {...},
        },
    },
}

# Nodes pass domain context
def account_registration(state: AgentState, domain: str) -> dict:
    client = make_client()  # Stateless
    domain_state = state["domain_state"][domain]

    account_url, new_nonce = client.create_account(
        nonce=domain_state["current_nonce"],
        ...
    )

    # Update domain-specific state
    domain_state["account_url"] = account_url
    domain_state["current_nonce"] = new_nonce

    return {"domain_state": state["domain_state"]}
```

**Advantages:**
- ✅ Keeps stateless client (testable, debuggable)
- ✅ Prepares for parallelization (per-domain state)
- ✅ State remains visible in LangGraph
- ✅ Easy serialization
- ✅ Easy distributed execution
- ⚠️ Requires passing domain context to nodes

---

## Recommendation

### ❌ Do NOT Use Stateful Client Design

**Reasons:**
1. **Loss of debuggability** — nonce hidden, harder to trace ACME flow
2. **Testing nightmare** — state-dependent tests, hard to mock
3. **Persistence problems** — can't easily checkpoint/restore
4. **Distributed execution risk** — unsafe for multi-machine deployment
5. **Memory overhead** — N clients for N domains
6. **LangGraph integration** — breaks state visibility, tracing

### ✅ Use Hybrid Approach Instead

**If parallelization is needed:**

```python
state["domain_state"] = {
    domain: {
        "current_nonce": nonce,
        "account_url": url,
        ...
    }
    for domain in managed_domains
}

# Nodes work with domain-specific state
def renewal_node(state: AgentState, domain: str) -> dict:
    client = make_client()  # Stateless, testable
    nonce = state["domain_state"][domain]["current_nonce"]
    ...
```

**Benefits:**
- ✅ Keep stateless, testable client
- ✅ State visible in LangGraph (debuggable)
- ✅ Easy serialization & persistence
- ✅ Safe for distributed execution
- ✅ Scales to 1000+ domains without overhead
- ✅ Ready for parallelization without design change

---

## Decision

**Current design (stateless client + nonce in state) is optimal.**

**For parallelization:** Use per-domain state buckets (hybrid), NOT stateful client.

**Reasoning:**
- Testability > convenience
- Debuggability > encapsulation
- Persistence > simplicity
- State visibility > hidden state

The small cost of passing `domain` context to nodes is worth the gains in debuggability, testability, and distributed safety.

---

---

## Idempotency Philosophy

The graph is designed to be **safe to resume or re-run at any node boundary**.

This is a first-class design goal, not an afterthought. It matters for:
- **Crash recovery** — resume a failed run from checkpoint without double-billing or duplicate certs
- **Operator confidence** — running the agent twice is safe; it won't break things
- **Long-term ops** — scheduled daily runs are sound even if a previous run crashed partway through

---

### What Happens if the Agent is Run Twice?

The certificate scanner (`certificate_scanner` node) reads existing certs from disk and computes days until expiry. On a re-run:

- If the cert was **successfully renewed on the first run**, it has a fresh expiry far in the future → `needs_renewal=False` → planner assigns it to `skip` → it never reaches the ACME pipeline
- If the first run **never completed renewal**, the cert is still near-expiry → `needs_renewal=True` → renewal proceeds normally

**Result:** Running twice is a no-op for domains already renewed. No duplicate orders, no wasted API calls.

---

### What Happens if the Agent Crashes After `cert_downloader` but Before `storage_manager`?

This is the most dangerous crash window. The CA has issued a certificate (order status = `valid`), but it hasn't been persisted to disk yet.

**On checkpoint resume:**

1. LangGraph restores state from the last checkpoint — the `current_order` still contains `certificate_url`
2. `cert_downloader` re-runs and re-fetches the certificate from `certificate_url` (ACME servers keep issued certs accessible)
3. `storage_manager` then writes all PEM files **atomically** (temp + fsync + rename — see [CERTIFICATE_STORAGE.md](CERTIFICATE_STORAGE.md))

**Without checkpointing (`--once` mode):**

1. The process restarts from scratch
2. `certificate_scanner` sees the old (near-expiry) cert still on disk
3. A new ACME order is created — the CA issues a fresh cert (valid operation, CAs allow this)
4. All files are written atomically, replacing the old cert

**Result:** Either path converges to a valid, consistent cert on disk. No window where a partial write creates a corrupt PEM file.

---

### Is Storage Atomic?

**Yes.** All PEM file writes use the atomic pattern:

```
write → temp file in same dir
         ↓
       fsync()  (flush to disk)
         ↓
       os.replace()  (atomic POSIX rename)
```

Covered files:
- `cert.pem`, `chain.pem`, `fullchain.pem`, `metadata.json` — via `storage/filesystem.py:_write()`
- `privkey.pem` (domain key) — via `agent/nodes/csr.py:csr_generator()`
- `account.key` — via `acme/jws.py:save_account_key()`

A crash at any point in the write sequence leaves the **previous file intact**. There is no state where a corrupt half-written file is visible to readers.

See [CERTIFICATE_STORAGE.md](CERTIFICATE_STORAGE.md) for full details and test coverage.

---

### Is Order Finalization Idempotent?

**Yes — ACME (RFC 8555) is designed for safe replays at every step.**

| Operation | Server behavior on replay |
|-----------|--------------------------|
| `newAccount` | Returns `200 OK` with existing account URL if key already registered |
| `newOrder` | CA may return an existing pending order or create a new one; both are valid |
| `newAuthz` / challenge response | Authorization objects persist on CA; re-posting a challenge response is safe |
| `finalize` | If order already `valid`, server returns the existing `certificate_url`; no new cert is issued |
| `certificate` (download) | Certificate URL remains accessible; downloading it again returns the same cert |

The only operation that is **not** replay-safe is the nonce: every signed ACME request requires a **fresh nonce** that has never been used. This is why `current_nonce` flows through state — so each node picks up a nonce from the previous response, never reusing one.

---

### Node-Level Idempotency Summary

| Node | Idempotent? | Notes |
|------|-------------|-------|
| `certificate_scanner` | ✅ Yes | Read-only; re-reads disk certs |
| `renewal_planner` | ✅ Yes | LLM call; same input → same plan (with validation guard) |
| `acme_account_setup` | ✅ Yes | ACME `newAccount` returns existing account on replay |
| `order_initializer` | ✅ Yes | Creates new order or returns existing; both valid |
| `challenge_setup` | ✅ Yes | Writing challenge token file is idempotent (atomic overwrite) |
| `challenge_verifier` | ✅ Yes | Re-posting challenge response is safe; CA re-validates |
| `csr_generator` | ⚠️ Partial | Generates a new key on each call; key is overwritten atomically |
| `order_finalizer` | ✅ Yes | `finalize` on a `valid` order is a no-op on the CA side |
| `cert_downloader` | ✅ Yes | Certificate URL is stable; re-downloading returns same cert |
| `storage_manager` | ✅ Yes | Atomic writes; re-running overwrites cleanly without corruption |
| `error_handler` | ✅ Yes | Pure state transformation; no side effects |
| `retry_scheduler` | ✅ Yes | Waits for scheduled retry time; safe to repeat |
| `summary_reporter` | ✅ Yes | LLM call; no side effects |

**csr_generator note:** Generating a new domain private key on replay is intentional. A fresh key is cryptographically safer than reusing a key from a previous failed run. The old `privkey.pem` is overwritten atomically so no corruption window exists.

---

### Philosophy: Resume-Safe Graph Design

**Every node boundary is a safe checkpoint.**

This follows naturally from:

1. **ACME is replay-safe** — The protocol is designed for unreliable networks and crashed clients. Retrying any ACME operation (with a fresh nonce) is always safe.

2. **Stateless client + state in LangGraph** — Because the `AcmeClient` holds no mutable state, any node can reconstruct it from scratch using the current LangGraph state. There is no "resume from inside a node" problem.

3. **Atomic writes** — Node outputs that touch disk are atomic. A crash after `os.replace()` leaves a valid file. A crash before leaves the old file intact. There is no intermediate corrupt state.

4. **LangGraph `MemorySaver`** — The checkpoint is written *after* each node completes, so the resume point is always at a clean node boundary.

5. **Nonce freshness** — If a run resumes, the first ACME call fetches a fresh nonce via `get_nonce()`. Stale nonces from the previous run are never replayed.

Together these properties mean:

> **A crash at any point in the graph — before, during, or after any node — converges to correct state after resume or re-run.**

---

## Related Documents

- [`DESIGN_NONCE_MANAGEMENT_STRATEGY.md`](DESIGN_NONCE_MANAGEMENT_STRATEGY.md) — Current design deep-dive
- [`CERTIFICATE_STORAGE.md`](CERTIFICATE_STORAGE.md) — Atomic write implementation
- [`acme/client.py`](../acme/client.py) — Stateless client implementation
- [`ACME_AGENT_PLAN.md`](ACME_AGENT_PLAN.md) — Agent architecture
