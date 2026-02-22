# ACME Certificate Lifecycle Agent — Claude Code Guide

---

<!--
  DOCUMENT LAYERS
  ───────────────────────────────────────────────────────
  I.  CONSTITUTIONAL LAYER   — Mental model, invariants, pre-implementation checklist
  II. OPERATIONAL LAYER      — Commands, structure, config, state, retry, KB
  III. COGNITIVE GUARDRAILS  — Architectural discipline, LLM boundaries, safety rules
  IV. MAINTENANCE PROTOCOLS  — Testing discipline, documentation maintenance
  ───────────────────────────────────────────────────────
-->

---

<!-- ═══════════════════════════════════════════════════════════
     I. CONSTITUTIONAL LAYER
     Non-negotiable rules. Read before any code change.
     ═══════════════════════════════════════════════════════════ -->

# ⚠️ Read This First

This file is the persistent architectural memory for this project.

Before modifying code, read:

**[doc/DESIGN_PRINCIPLES.md](doc/DESIGN_PRINCIPLES.md)**

That document is the constitutional layer.
This file is the operational + cognitive guardrail layer.

If a change conflicts with a design principle, it must be explicitly justified.

---

# 🧠 Mental Model (Non-Negotiable)

This project is a **deterministic LangGraph state machine** orchestrating a **stateless ACME client**.

Core model:

* All workflow state lives in `AgentState`
* ACME client is stateless
* Each network operation is a graph node
* LLMs are advisory only
* Domain processing is sequential by design

If a change violates this mental model, stop and reassess.

---

# 🔒 Hard Invariants (Must Never Change)

1. One ACME POST → exactly one nonce consumed
2. Account private key is never stored in AgentState
3. LLM output must be validated before any action
4. No concurrent ACME operations
5. Retry logic lives only in `error_handler` + `retry_scheduler`
6. Certificate writes must be atomic
7. Graph topology changes require updating DESIGN_PRINCIPLES.md
8. Every network call must be represented as a named node
9. ACME client must not contain hidden mutable state
10. Planner must never introduce new domains

These are architectural safety rails, not suggestions.

---

<!-- ═══════════════════════════════════════════════════════════
     II. OPERATIONAL LAYER
     How to run, build, configure, and understand the system.
     ═══════════════════════════════════════════════════════════ -->

# 📦 Project Overview

LangGraph `StateGraph` + Claude-powered agent that automates TLS certificate renewal via ACME RFC 8555.

Supports:

* DigiCert
* ZeroSSL
* Sectigo (EAB)
* Let's Encrypt
* Let's Encrypt Staging
* Custom ACME CAs

HTTP-01 challenge modes:

* Standalone (port 80)
* Webroot

---

# ▶️ Commands

### Run the agent

```bash
python main.py --once
python main.py --schedule
python main.py --once --domains api.example.com
python main.py --once --checkpoint
```

### Install dependencies

```bash
uv sync
```

Never use `pip` directly.

### Run tests

Unit tests:

```bash
pytest tests/test_unit_acme.py -v
```

Integration tests (requires Pebble):

```bash
docker compose -f docker-compose.pebble.yml up -d
pytest tests/test_integration_pebble.py tests/test_lifecycle_pebble.py -v
```

All tests:

```bash
pytest -v
```

---

# 🏗 Project Structure

→ See [`doc/README_PROJECT_STRUCTURE.md`](doc/README_PROJECT_STRUCTURE.md) for the full annotated file tree.

```
config.py       main.py

llm/factory.py

agent/state.py  agent/graph.py  agent/prompts.py
agent/nodes/    planner  scanner  account  order  challenge
                csr  finalizer  storage  reporter  error_handler
                retry_scheduler  router

acme/client.py  acme/jws.py  acme/crypto.py  acme/http_challenge.py
storage/atomic.py  storage/filesystem.py

tests/  doc/  kb/
```

---

# 🧭 Architectural Discipline

## Sequential Processing (Intentional)

Do NOT:

* Parallelize domain handling
* Introduce async ACME calls
* Share nonce state between domains

Sequential ACME operations are required for protocol safety.

---

## LLM Authority Boundaries

LLM may:

* Classify domains for renewal
* Suggest retry / skip / abort
* Generate human-readable summaries

LLM may NOT:

* Introduce new domains
* Modify configuration
* Change file paths
* Trigger side effects
* Alter ACME protocol flow
* Change retry limits

LLM is advisory, never authoritative.

---

## Failure Philosophy

* Deterministic protocol errors handled without LLM
* Ambiguous cases may route to LLM
* Retries must be bounded
* Never retry indefinitely
* Prefer deferring to next scheduled run over aggressive retry

---

# 🔁 Retry System

* Exponential backoff; cap: 300 seconds
* `MAX_RETRIES` default: 3
* Routing: `error_handler → retry_scheduler → pick_next_domain`

Retry logic must not be embedded in business nodes.

---

# 🗃 State Design

* `AcmeOrder` supports multi-SAN certs (`List[str]` for auth/challenge/token/key_auth fields)
* CSR stored as hex string in order dict (travels through state safely)
* `current_nonce` flows through state so every node picks up a fresh nonce
* Account key remains on disk only (`ACCOUNT_KEY_PATH`)

State must remain serializable and deterministic.

---

# ⚙️ Configuration (.env)

→ Full reference with defaults and valid values: [`doc/README_CONFIGURATION.md`](doc/README_CONFIGURATION.md)

Core fields:

```
CA_PROVIDER                   # digicert | letsencrypt | letsencrypt_staging | zerossl | sectigo | custom
ACME_EAB_KEY_ID / HMAC_KEY    # required for DigiCert, ZeroSSL, Sectigo
MANAGED_DOMAINS               # comma-separated
CERT_STORE_PATH / ACCOUNT_KEY_PATH
HTTP_CHALLENGE_MODE           # standalone | webroot
LLM_PROVIDER                  # anthropic | openai | ollama
LLM_MODEL_PLANNER / REPORTER / ERROR_HANDLER
MAX_RETRIES / RENEWAL_THRESHOLD_DAYS
```

Never change `MANAGED_DOMAINS` parsing logic (`_CommaFallbackMixin` in `config.py`).
Never enable `ACME_INSECURE` in production.

---

# 📚 Knowledge Base

Current: JSON storage (`kb/chunks.json`) — human-readable, version-control friendly.

Revisit when: > 50k entries or metadata filtering required.
Future options: Qdrant · SQLite + FAISS · Parquet + index.

Do not prematurely optimize storage.

---

<!-- ═══════════════════════════════════════════════════════════
     III. COGNITIVE GUARDRAILS
     Rules that prevent the most common architectural mistakes.
     ═══════════════════════════════════════════════════════════ -->

# 🚦 Before Implementing a New Feature

Ask:

1. Does this introduce hidden state?
2. Does this bypass graph routing?
3. Does this introduce concurrency?
4. Does this give LLM authority over side effects?
5. Does this change nonce lifecycle guarantees?
6. Does this alter retry semantics?
7. Does this require a new design document?

If any answer is yes → pause and consult [doc/DESIGN_PRINCIPLES.md](doc/DESIGN_PRINCIPLES.md).

---

# 🧪 Testing Discipline

Any change that adds a node, changes routing, modifies retry logic, alters ACME protocol behavior, or changes `AgentState` shape must update:

* Unit tests (`tests/test_unit_acme.py`)
* Integration tests if protocol is affected (`tests/test_integration_pebble.py`, `tests/test_lifecycle_pebble.py`)
* `TEST_RESULTS.md` — paste full `pytest -v` output
* `TEST_SUMMARY.md` — update counts and prose descriptions

Use `pebble_settings` fixture to mutate the settings singleton in tests (restores via teardown).
Use `mock_llm_nodes` fixture to patch `llm.factory.init_chat_model` — no API key needed.
LLM mocks must return `AIMessage` objects so LangGraph's `add_messages` reducer accepts them.

Documentation must stay synchronized with code.

---

# 📊 Performance Stance

Throughput is secondary to determinism, safety, auditability, and protocol correctness.

Do not optimize prematurely.

---

# 📈 Scaling Guidance

If domain count grows:

* Keep sequential ACME operations
* Consider splitting planning and execution graphs
* Do not introduce concurrency without redesigning nonce management

Scaling must preserve determinism.

---

# 🔐 What NOT To Do

* Never put private keys in `AgentState`
* Never allow planner to invent domains
* Never hide network calls in helper functions
* Never mix retry logic into business nodes
* Never bypass LLM validation layer
* Never introduce background threads for ACME operations
* Never use `pip` — always `uv sync`

---

<!-- ═══════════════════════════════════════════════════════════
     IV. MAINTENANCE PROTOCOLS
     How to keep code, tests, and docs synchronized.
     ═══════════════════════════════════════════════════════════ -->

# 📖 Documentation Maintenance

After modifying architecture or node behavior:

* Update [`doc/DESIGN_PRINCIPLES.md`](doc/DESIGN_PRINCIPLES.md) if a principle changes
* Update [`doc/README_ACME_AGENT_PLAN.md`](doc/README_ACME_AGENT_PLAN.md) if topology changes
* Update `README.md` if CLI or configuration changes
* Update `CLAUDE.md` if project structure or invariants change

After running tests:

* Update `TEST_RESULTS.md` — full `pytest -v` output
* Update `TEST_SUMMARY.md` — counts and descriptions

---

# 🏁 Final Reminder

This project prioritizes:

1. Determinism
2. Protocol correctness
3. Safety over speed
4. Explicit state over hidden state
5. Architectural clarity over cleverness

If a change makes the system "smarter" but less predictable — it is likely wrong.

When in doubt, preserve the graph.
