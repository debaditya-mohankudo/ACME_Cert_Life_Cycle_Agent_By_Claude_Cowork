# Node Migration to Callable Classes — COMPLETED ✓

## Goal
Migrate function-based graph nodes to class-based callable nodes with a minimal structural contract while preserving deterministic behavior, graph topology, and current test outcomes.

## Branch
- `feature/abstract-node-migration`

## Status
**COMPLETED** — All nodes migrated to callable class pattern. Full test suite green (291 tests + 9 Pebble tests).

## Final Architecture
- **Pattern**: Callable classes with `NodeCallable` Protocol (structural typing, no inheritance)
- **Contract**: Classes must implement `__call__(self, state: AgentState) -> dict`
- **Graph Integration**: Direct instance registration: `builder.add_node("name", SomeNode())`
- **No Adapters**: Eliminated inheritance hierarchy and adapter wrappers in favor of simple Protocol

## Constraints (Preserved)
- No hidden mutable state in node instances.
- No graph topology changes during migration.
- Retry semantics stay in `error_handler` + `retry_scheduler`.
- LLM remains advisory only.

---

## What We Actually Did

### Architecture Evolution

**Initial Plan**: Abstract base class (`AbstractNode`) + adapter pattern (`FunctionNodeAdapter`)  
**Final Implementation**: Callable classes + structural Protocol (`NodeCallable`)

**Why the change**: The ABC + adapter approach added unnecessary complexity. The callable class pattern with Protocol provides:
- Simpler mental model (just implement `__call__`)
- No inheritance hierarchy to maintain
- No adapter layer to debug
- Direct instance registration in graphs
- Structural typing (duck typing with type checking)

### Phase 1 — Minimal Structural Contract ✓

**File**: `agent/nodes/base.py`

**Implementation**:
```python
from typing import Protocol
from agent.state import AgentState

class NodeCallable(Protocol):
    """Structural contract for LangGraph-compatible node callables."""
    def __call__(self, state: AgentState) -> dict: ...
```

**Rationale**: Protocol uses structural subtyping — any class with a `__call__(state) -> dict` signature is automatically compatible. No inheritance needed.

**Testing**: `tests/test_node_base.py` validates the structural contract (3 tests).

---

### Phase 2 — Graph Integration ✓

**Files**: `agent/graph.py`, `agent/revocation_graph.py`

**Changes**:
- Changed imports from functions to class types
- Changed registration from `builder.add_node("name", function_name)` to `builder.add_node("name", ClassName())`
- Example: `builder.add_node("acme_account_setup", AcmeAccountSetupNode())`

**Preserved**:
- All node names unchanged
- All routing logic unchanged
- All conditional edges unchanged

**Testing**: Topology validated through checkpoint tests and full suite.

---

### Phase 3 — Node Class Migration ✓

**Pattern Applied to All Nodes**:
```python
class SomeNode:
    """Node description."""
    
    def __call__(self, state: AgentState) -> dict:
        """LangGraph entry point."""
        return self.run(state)
    
    def run(self, state: AgentState) -> dict:
        """Business logic."""
        # ... implementation
        return {"key": value}
```

**Migrated Nodes** (15 total):

| Module | Classes | Notes |
|--------|---------|-------|
| `scanner.py` | `CertificateScannerNode` | Cert expiry scanning |
| `account.py` | `AcmeAccountSetupNode` | ACME account registration |
| `order.py` | `AcmeOrderInitializerNode` | Order creation |
| `csr.py` | `CsrGeneratorNode` | CSR + key generation |
| `challenge.py` | `AcmeHttpChallengeSetupNode`, `AcmeHttpChallengeVerifierNode` | HTTP-01 challenge flow |
| `finalizer.py` | `AcmeOrderFinalizerNode`, `AcmeCertDownloaderNode` | Certificate finalization |
| `storage.py` | `CertStorageNode` | Atomic PEM writes |
| `planner.py` | `RenewalPlannerNode` | LLM-based planning |
| `error_handler.py` | `ErrorHandlerNode` | LLM-based error analysis |
| `reporter.py` | `SummaryReporterNode`, `RevocationSummaryReporterNode` | Final reports |
| `retry_scheduler.py` | `RetrySchedulerNode` | Backoff delay handling |
| `revoker.py` | `RevokerNode` | Certificate revocation |

**Function Wrappers**: All original node functions preserved as thin wrappers calling class instances.

**Testing**: `tests/test_node_parity.py` validates function wrapper → class delegation (15 tests).

---

### Phase 4 — Router Treatment ✓

**Decision**: Keep routers as pure functions.

**Files**: `agent/nodes/router.py`, `agent/nodes/revocation_router.py`

**Rationale**: Routers are simple conditional logic with no side effects. Converting to classes adds no value. Functions are clearer for pure routing logic.

**Preserved**:
- `pick_next_domain()` - Domain iteration logic
- `route_error_decision()` - Error routing based on LLM decision
- `route_revocation_result()` - Revocation success/failure routing

---

### Phase 5 — Validation ✓

**Test Results**:
- Unit + Integration: **291 tests passed** in 23.40s
- Pebble Integration: **9 tests passed** in 12.49s
- Node Parity: **15 tests passed**
- Structural Contract: **3 tests passed**

**Validation Commands**:
```bash
uv run pytest -q                    # Full suite
uv run pytest -q tests/*pebble*.py  # Pebble integration
uv run pytest -v tests/test_node_parity.py tests/test_node_base.py  # Node architecture
```

**No Regressions**: All existing test outcomes preserved.

---

## Key Architectural Decisions

### Why Protocol Over ABC?

**ABC Approach** (initial plan):
- Requires explicit inheritance: `class SomeNode(AbstractNode)`
- Requires implementing abstract methods
- Requires adapter layer for existing functions
- More boilerplate, more files, more complexity

**Protocol Approach** (final implementation):
- Uses structural subtyping (duck typing with type safety)
- Any class with `__call__(state) -> dict` is automatically compatible
- No inheritance requirement
- No adapter layer needed
- Simpler mental model: "just implement `__call__`"

**Alignment with Python Philosophy**: "We're all consenting adults here" — Protocol trusts developers to implement the contract without enforcing inheritance.

### Why Keep Function Wrappers?

**Rationale**: Backward compatibility and gradual migration path.

**Function wrappers**:
- Allow existing imports to continue working
- Enable incremental migration (not required but enables flexibility)
- Add negligible runtime overhead (one function call)
- Provide clear migration documentation through code

**Future**: Wrappers can be removed in a future cleanup pass if desired.

### Why No `name` Property?

**Initial plan** included `name` property on abstract base.

**Eliminated because**:
- LangGraph requires node names at registration time: `builder.add_node("name", callable)`
- Node instance doesn't need to know its own name
- Eliminates one source of truth synchronization (name in class vs name in graph)
- Simpler: name is declared once at graph registration

---

## Mocking Strategy for Callable Classes

**Challenge**: Checkpoint tests mock nodes to avoid network calls.

**Old Approach** (function-based):
```python
patch("agent.graph.some_function_name", lambda state: {...})
```

**New Approach** (callable classes):
```python
mock_instance = MagicMock(return_value={...})
mock_cls = MagicMock(return_value=mock_instance)
patch("agent.graph.SomeNodeClass", mock_cls)
```

**Rationale**: Graph registers `SomeNodeClass()` instances, so mocking must patch the class constructor to return a mock instance.

**Implementation**: `tests/conftest.py` provides `mock_nodes_for_checkpoint` fixture.

---

## Documentation Updates

**Files Updated**:
- [x] `doc/TASK_ABSTRACT_NODE_MIGRATION.md` (this file)
- [x] `doc/DESIGN_PRINCIPLES.md` — Added Principle 13: Node Architecture
- [x] `tests/test_node_parity.py` — Comprehensive delegation tests
- [x] `tests/test_node_base.py` — Structural contract tests
- [x] `tests/conftest.py` — Updated checkpoint mocking fixture

---

## Migration Lessons

**What Worked Well**:
1. Starting with minimal Protocol instead of full ABC saved significant complexity
2. Direct instance registration (`SomeNode()`) is cleaner than adapter wrappers
3. Keeping function wrappers preserved backward compatibility with zero cost
4. Test-driven migration caught all behavioral changes immediately

**What We Avoided**:
1. Over-engineering with abstract base classes
2. Adapter pattern complexity
3. Breaking existing imports
4. Graph topology changes

**Future Improvements**:
- Remove function wrappers if backward compatibility no longer needed
- Add optional validation hooks to node classes (e.g., `validate_input()`)
- Consider adding common utilities in a node base class (opt-in, not required by Protocol)

---

## Suggested PR Slices

Migration was completed in a single branch but could be broken into PRs:

1. **PR-1**: Protocol definition + graph integration (direct instances)
2. **PR-2**: Pilot migrations (scanner, storage, reporter) + parity tests
3. **PR-3**: ACME protocol nodes (account, order, challenge, csr, finalizer)
4. **PR-4**: Control flow nodes (planner, error_handler, retry_scheduler)
5. **PR-5**: Revocation nodes (revoker, revocation_router)
6. **PR-6**: Documentation updates + final validation

---

## Conclusion

The callable class pattern with `NodeCallable` Protocol provides a **simpler, more Pythonic architecture** than the original AbstractNode + adapter plan.

**Key Benefits**:
- Minimal structural contract (one method: `__call__`)
- No inheritance hierarchy to maintain
- No adapter layer complexity
- Direct graph integration
- Full type safety through Protocol
- Zero behavioral regressions

**Validation**: 291 + 9 tests passing, no regressions, simpler codebase.

**Status**: ✅ **COMPLETED** and production-ready.

