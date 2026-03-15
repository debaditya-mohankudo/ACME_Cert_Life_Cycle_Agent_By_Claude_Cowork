# Plan: Make LLM Fully Optional — Zero-Dependency Deterministic Mode

**Status:** Implemented
**Priority:** High
**Scope:** All LLM nodes + import guards + dependency restructure + tests + docs
**Driver:** Server maintainers do not want to install LLM / Anthropic / OpenAI packages

---

## 1. Objective

Make all LLM packages (`langchain`, `langchain-core`, `langchain-anthropic`, `openai`, etc.) **fully optional**. A server maintainer running `uv sync` (no extras) gets a working, fully deterministic agent with zero LLM dependency.

LLM remains available as an opt-in extra for teams that want it.

---

## 2. Two Layers of Coupling to Solve

### Layer 1 — Runtime coupling (nodes call LLM at runtime)

Three nodes already had `LLM_DISABLED` guards with full deterministic paths. One node was missing:

| Node | File | LLM_DISABLED support before | After |
|------|------|------------------------------|-------|
| `RenewalPlannerNode` | planner.py | ✅ YES | ✅ YES |
| `ErrorHandlerNode` | error_handler.py | ✅ YES | ✅ YES |
| `SummaryReporterNode` | reporter.py | ✅ YES | ✅ YES |
| `RevocationReporterNode` | reporter.py | ❌ **NO** | ✅ **FIXED** |

### Layer 2 — Import-time coupling (hard module-level imports)

Even with `LLM_DISABLED=True`, the process previously **failed to start** if `langchain-core` was not installed, because these files imported it at module level:

| File | Hard import removed |
|------|---------------------|
| `agent/nodes/planner.py` | `HumanMessage, SystemMessage`, `make_llm`, prompts |
| `agent/nodes/error_handler.py` | `HumanMessage, SystemMessage`, `make_llm`, prompts |
| `agent/nodes/reporter.py` | `HumanMessage, SystemMessage`, `make_llm`, prompts |
| `agent/state.py` | `BaseMessage` from `langchain_core` |
| `llm/factory.py` | `init_chat_model`, `BaseChatModel` from `langchain*` |

---

## 3. Design Constraints (from DESIGN_PRINCIPLES.md)

1. **RFC compliance** — no change to nonce handling, ACME flow, or cert storage
2. **Deterministic behavior** — when LLM disabled, output is fully predictable
3. **LLM advisory, never authoritative** — bypassing LLM must not introduce side effects
4. **No graph topology changes** — `AgentState`, `build_graph()`, routing untouched
5. **`langgraph` is NOT optional** — it IS the state machine engine and must remain a core dependency

---

## 4. Changes Implemented

### 4.1 `agent/nodes/reporter.py` — Fix `RevocationReporterNode`

Split `run()` into `_run_llm()` / `_run_deterministic()`, matching the existing `SummaryReporterNode` pattern.

Added `_revocation_reporter_deterministic()` helper:

```python
def _revocation_reporter_deterministic(revoked, failed, reason, error_log):
    _REASON_NAMES = {0: "unspecified", 1: "keyCompromise", 2: "cACompromise",
                     3: "affiliationChanged", 4: "superseded",
                     5: "cessationOfOperation", 9: "privilegeWithdrawn"}
    reason_name = _REASON_NAMES.get(reason, f"code-{reason}")
    status = "SUCCESS" if not failed else ("PARTIAL" if revoked else "FAILED")
    summary = (
        "═" * 50 + "\n" +
        "ACME Certificate Revocation Summary\n" +
        "═" * 50 + "\n" +
        f"Revoked:  {len(revoked)}: {', '.join(revoked) or '(none)'}\n" +
        f"Failed:   {len(failed)}: {', '.join(failed) or '(none)'}\n" +
        f"Reason:   {reason} ({reason_name})\n" +
        f"Errors:   {len(error_log)}\n" +
        f"Status:   {status}\n" +
        "═" * 50
    )
    return summary
```

All LLM imports (`HumanMessage`, `SystemMessage`, `make_llm`, prompts) moved inside `_run_llm()`.

---

### 4.2 `agent/nodes/planner.py` — Lazy LLM Imports

All three LLM imports moved inside `_run_llm()`:

```python
def _run_llm(self, state):
    from langchain_core.messages import HumanMessage, SystemMessage
    from agent.prompts import PLANNER_SYSTEM, PLANNER_USER
    from llm.factory import make_llm
    ...
```

---

### 4.3 `agent/nodes/error_handler.py` — Lazy LLM Imports

Same pattern as planner — imports moved inside `_run_llm()`.

---

### 4.4 `agent/state.py` — Guard `BaseMessage` Import

```python
try:
    from langchain_core.messages import BaseMessage as _BaseMessage
except ImportError:
    _BaseMessage = dict  # type: ignore[assignment,misc]

class AgentState(TypedDict):
    ...
    messages: Annotated[List[_BaseMessage], add_messages]
```

`add_messages` (from `langgraph`) handles both `BaseMessage` instances and plain dicts. `langgraph` is always installed.

---

### 4.5 `llm/factory.py` — Guard Against Missing Packages

```python
try:
    from langchain.chat_models import init_chat_model
    from langchain_core.language_models.chat_models import BaseChatModel
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    init_chat_model = None   # type: ignore
    BaseChatModel = object   # type: ignore

def make_llm(model, max_tokens):
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LLM packages are not installed. "
            "Install with: uv sync --extra llm-anthropic\n"
            "Or set LLM_DISABLED=true in .env to run without LLM."
        )
    ...
```

---

### 4.6 `config.py` — Default `LLM_DISABLED=True` + Startup Validator

```python
LLM_DISABLED: bool = True  # default: deterministic; set False + install llm extra to enable
```

New `model_validator` catches misconfiguration at startup:

```python
@model_validator(mode="after")
def validate_llm_available(self) -> "Settings":
    if not self.LLM_DISABLED:
        try:
            import langchain.chat_models  # noqa: F401
        except ImportError:
            raise ValueError(
                "LLM_DISABLED=false but langchain is not installed. "
                "Run: uv sync --extra llm-anthropic  OR  set LLM_DISABLED=true"
            )
    return self
```

---

### 4.7 `pyproject.toml` — Restructure Dependencies

LLM packages moved out of `[dependency-groups] dev` into `[project.optional-dependencies]` LLM extras, and promoted to `[project] dependencies` for core packages:

```toml
[project]
dependencies = [
    "cryptography>=44.0",
    "josepy>=1.14",
    "langgraph>=0.2",           # graph engine — always required
    "langgraph-checkpoint>=2.1",
    "pydantic-settings>=2.8",
    "schedule>=1.2",
    "structlog>=25.1",
]

[project.optional-dependencies]
llm-anthropic = ["langchain>=0.3", "langchain-core>=1.2", "langchain-anthropic>=0.3", "anthropic>=0.82"]
llm-openai    = ["langchain>=0.3", "langchain-core>=1.2", "openai>=1.0"]
llm-ollama    = ["langchain>=0.3", "langchain-core>=1.2", "langchain-ollama>=1.0"]
llm-all       = ["langchain>=0.3", "langchain-core>=1.2", "langchain-anthropic>=0.3", "langchain-ollama>=1.0", "anthropic>=0.82"]
dns-cloudflare = [...]   # unchanged
```

```
# Minimal install (no LLM)
uv sync

# With Anthropic LLM support
uv sync --extra llm-anthropic

# Developer install (everything)
uv sync   # dev group includes llm-all + dns-all automatically
```

---

### 4.8 `tests/conftest.py` — Track `LLM_DISABLED` in `pebble_settings`

`LLM_DISABLED` added to `originals` dict in `pebble_settings` fixture so it is restored after each test.

---

## 5. Deterministic Behavior Summary

When `LLM_DISABLED=true` (now the default):

| Node | Deterministic Algorithm |
|------|-------------------------|
| **RenewalPlanner** | Renew: (1) all no-cert domains, (2) certs expiring ≤ threshold, sorted by days ascending |
| **ErrorHandler** | Retry with exponential backoff `delay * 2^(retry+1)` capped at 300s; skip at `MAX_RETRIES` |
| **SummaryReporter** | Fixed box format: Renewed/Failed/Skipped counts + SUCCESS/PARTIAL/FAILED status |
| **RevocationReporter** | Fixed box format: Revoked/Failed counts + reason name + SUCCESS/PARTIAL/FAILED status |

No LLM messages are added to `AgentState` in deterministic mode (returns `{"messages": []}`).

---

## 6. Testing

### New test file

`tests/test_revocation_reporter_deterministic.py` — ~20 tests covering:
- Status logic (SUCCESS / PARTIAL / FAILED)
- Reason code name mapping (0→unspecified, 1→keyCompromise, 4→superseded, 99→code-99)
- Box border formatting
- Error log count
- `RevocationReporterNode.run()` routing (LLM_DISABLED=True → deterministic, =False → LLM)
- `make_llm` is never called when `LLM_DISABLED=True`

### Existing tests

All 526 existing unit tests continue to pass. Tests that exercise LLM paths use `mock_llm_nodes` fixture or explicitly set `LLM_DISABLED=False`.

---

## 7. Installation Modes

```
# Server / production (no LLM):
uv sync
LLM_DISABLED=true   ← now the default, no .env entry needed

# With Anthropic:
uv sync --extra llm-anthropic
LLM_DISABLED=false
ANTHROPIC_API_KEY=sk-ant-...

# With OpenAI:
uv sync --extra llm-openai
LLM_DISABLED=false
OPENAI_API_KEY=sk-...

# Local Ollama:
uv sync --extra llm-ollama
LLM_DISABLED=false
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434

# Developer (everything):
uv sync   # dev group already includes llm-all + dns-all
```

---

## 8. Edge Cases

| Scenario | Behavior |
|----------|----------|
| `LLM_DISABLED=true`, no langchain installed | ✅ Works — no import attempted |
| `LLM_DISABLED=false`, no langchain installed | ❌ Clear `ValueError` at startup with install hint |
| `LLM_DISABLED=true`, langchain IS installed | ✅ Works — lazy imports never executed |
| `--revoke-cert` with `LLM_DISABLED=true` | ✅ `RevocationReporterNode` uses deterministic path |
| Empty `MANAGED_DOMAINS` | ✅ Renew nothing (consistent across both modes) |
| `MAX_RETRIES` exceeded, deterministic mode | Skip domain (no abort; operator must intervene manually) |

---

## 9. Future Extensions

- [ ] Per-domain priority hints via config (e.g. `api.example.com:urgent`)
- [ ] Custom retry policy (max delay, backoff formula via env)
- [ ] Structured reporter output formats (JSON, YAML) as alternatives to plain text
- [ ] LangSmith tracing extra (`uv sync --extra langsmith`)
