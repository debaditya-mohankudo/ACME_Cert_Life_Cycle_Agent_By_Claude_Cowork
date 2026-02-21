# Stateful Client Design Analysis: Per-Domain AcmeClient with Private Nonce

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

## Related Documents

- [`NONCE_MANAGEMENT_STRATEGY.md`](NONCE_MANAGEMENT_STRATEGY.md) — Current design deep-dive
- [`acme/client.py`](../acme/client.py) — Stateless client implementation
- [`ACME_AGENT_PLAN.md`](ACME_AGENT_PLAN.md) — Agent architecture
