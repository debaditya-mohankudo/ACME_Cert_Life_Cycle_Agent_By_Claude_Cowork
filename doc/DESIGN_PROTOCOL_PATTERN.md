# Protocol Design Pattern for Node Architecture

## Overview

This project uses Python's `Protocol` (PEP 544) for structural subtyping instead of traditional inheritance-based polymorphism. This document explains why, how it works, and what advantages it provides.

---

## What is a Protocol?

A `Protocol` defines a **structural contract** — a set of method signatures that a class must implement to be considered compatible. Unlike traditional inheritance, there is **no explicit relationship** required between the Protocol and implementing classes.

### Traditional Inheritance (Nominal Typing)

```python
from abc import ABC, abstractmethod

class BaseNode(ABC):
    @abstractmethod
    def run(self, state) -> dict:
        """Subclasses must implement this."""
        ...

class SomeNode(BaseNode):  # ← Explicit inheritance required
    def run(self, state) -> dict:
        return {}

# Runtime relationship exists
isinstance(SomeNode(), BaseNode)  # True
```

**Characteristics:**
- Explicit `class Child(Parent)` declaration
- Runtime type checking via `isinstance()`
- Method Resolution Order (MRO) matters
- Tight coupling between base and child

### Protocol (Structural Typing)

```python
from typing import Protocol

class NodeCallable(Protocol):
    def __call__(self, state) -> dict:
        """Any class with this signature is compatible."""
        ...

class SomeNode:  # ← NO inheritance, NO base class
    def __call__(self, state) -> dict:
        return {}

# NO runtime relationship
isinstance(SomeNode(), NodeCallable)  # False

# But type checkers validate the signature
def register_node(node: NodeCallable) -> None:
    ...

register_node(SomeNode())  # ✓ Type checker accepts this
```

**Characteristics:**
- No explicit inheritance needed
- Type checking happens **at compile time** (static analysis)
- No runtime overhead
- Loose coupling — classes are independent

---

## Why Protocol Over Inheritance?

### Problem with Inheritance-Based Design

Initial design considered an abstract base class:

```python
class AbstractNode(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Node name for graph registration."""
        ...
    
    @abstractmethod
    def run(self, state: AgentState) -> dict:
        """Execute node logic."""
        ...
```

**Issues:**
1. **Boilerplate:** Every node must inherit and implement abstract methods
2. **Rigid:** Hard to make router functions compatible (they don't need a class)
3. **Coupling:** Changes to base class affect all children
4. **Adapter Layer:** Required `FunctionNodeAdapter` to wrap existing functions
5. **Name Duplication:** `name` property must match graph registration string

### Benefits of Protocol Design

```python
class NodeCallable(Protocol):
    def __call__(self, state: AgentState) -> dict: ...
```

**Advantages:**
1. **Minimal Contract:** Only one method signature required
2. **Flexibility:** Classes and functions both work (functions are naturally callable)
3. **No Coupling:** Node classes know nothing about `NodeCallable`
4. **No Adapters:** Direct registration without wrappers
5. **Single Source of Truth:** Node names live in registry, not in classes

---

## How Protocol Works in This Project

### 1. The Contract (base.py)

```python
# agent/nodes/base.py
from typing import Protocol
from agent.state import AgentState

class NodeCallable(Protocol):
    """Structural contract for LangGraph-compatible node callables."""
    
    def __call__(self, state: AgentState) -> dict:
        """Execute node logic and return partial state updates."""
        ...
```

This file exists **purely for documentation and type checking**. It is never imported by production code.

### 2. Node Implementation (NO imports from base)

```python
# agent/nodes/account.py
# Notice: NO import of NodeCallable

class AcmeAccountSetupNode:
    """Callable account-setup node implementation."""
    
    def __call__(self, state: AgentState) -> dict:
        return self.run(state)
    
    def run(self, state: AgentState) -> dict:
        # Business logic here
        return {"acme_account_url": "..."}
```

**Key Point:** `AcmeAccountSetupNode` has **zero knowledge** of `NodeCallable`. It just happens to have a compatible signature.

### 3. Registry and Factory

```python
# agent/nodes/registry.py
NODE_REGISTRY = {
    "acme_account_setup": AcmeAccountSetupNode,
    "pick_next_domain": pick_next_domain,  # Function also works!
    # ... more nodes
}

def get_node(name: str):
    """Factory: instantiate node callable by name."""
    node_cls_or_fn = NODE_REGISTRY[name]
    # Classes need instantiation, functions don't
    return node_cls_or_fn() if isinstance(node_cls_or_fn, type) else node_cls_or_fn
```

**Notice:** `get_node()` doesn't explicitly return `NodeCallable`. The type checker infers compatibility.

### 4. Graph Registration

```python
# agent/graph.py
from agent.nodes.registry import get_node

def build_graph():
    builder = StateGraph(AgentState)
    
    for node_name in ["certificate_scanner", "renewal_planner", ...]:
        builder.add_node(node_name, get_node(node_name))
```

**Runtime Flow:**
```
get_node("certificate_scanner")
    └→ Returns CertificateScannerNode()
        └→ LangGraph calls: instance(state)
            └→ instance.__call__(state) executes
```

**No type checks happen at runtime.** LangGraph just calls the object — if it has `__call__`, it works.

---

## Protocol vs Runtime

### Compile-Time (Type Checker)

```python
def register(node: NodeCallable) -> None:
    ...

class ValidNode:
    def __call__(self, state: AgentState) -> dict:
        return {}

class InvalidNode:
    def process(self, state: AgentState) -> dict:  # ← Wrong method name
        return {}

register(ValidNode())    # ✓ Type checker: OK
register(InvalidNode())  # ✗ Type checker: Error
```

### Runtime (Python Interpreter)

```python
isinstance(ValidNode(), NodeCallable)    # False — NO runtime relationship
isinstance(InvalidNode(), NodeCallable)  # False — NO runtime relationship

# Both cases: NO error, NO check, NO overhead
```

**Protocol checking happens ONLY during static analysis** (mypy, pyright, IDE type checkers). At runtime, Python treats `NodeCallable` as a regular class with no special behavior.

---

## Verification: No Runtime Dependencies

Let's verify that nodes have zero dependency on `NodeCallable`:

```bash
$ grep -r "from agent.nodes.base" agent/nodes/*.py
# (no results)

$ grep -r "NodeCallable" agent/nodes/*.py
# (no results)

$ grep -r "NodeCallable" agent/graph.py agent/revocation_graph.py
# (no results)
```

**Only found in:**
- `agent/nodes/base.py` — definition
- `tests/test_node_base.py` — test file (type casting for validation)

---

## Design Evolution

### Phase 1: Function-Based (Original)

```python
def acme_account_setup(state: AgentState) -> dict:
    # Logic here
    return {}

builder.add_node("acme_account_setup", acme_account_setup)
```

**Issues:** Hard to test, no encapsulation, no state management.

### Phase 2: AbstractNode + Adapter (Attempted)

```python
class AbstractNode(ABC):
    @abstractmethod
    def run(self, state) -> dict: ...

class AcmeAccountSetupNode(AbstractNode):  # Explicit inheritance
    def run(self, state) -> dict:
        return {}

# Required adapter layer
builder.add_node("acme_account_setup", adapt_function_node(AcmeAccountSetupNode()).run)
```

**Issues:** Too much boilerplate, adapter complexity, tight coupling.

### Phase 3: Callable Classes + Protocol (Final)

```python
class NodeCallable(Protocol):
    def __call__(self, state) -> dict: ...

class AcmeAccountSetupNode:  # NO inheritance
    def __call__(self, state) -> dict:
        return self.run(state)
    
    def run(self, state) -> dict:
        return {}

builder.add_node("acme_account_setup", AcmeAccountSetupNode())
```

**Benefits:** No boilerplate, no adapters, direct registration, loose coupling.

---

## When to Use Protocol

### Good Use Cases ✓

1. **Interface Definition:** Define contract without forcing inheritance
2. **Multiple Implementations:** Different classes implementing same behavior
3. **Library/Framework Boundaries:** Users implement your Protocol without subclassing
4. **Testing:** Easy to mock (just match signature)
5. **Flexibility:** Support both classes and functions

### When NOT to Use ✗

1. **Shared Implementation:** If you need common code in base, use inheritance
2. **Runtime Type Checks:** If you need `isinstance()` checks at runtime
3. **Stateful Hierarchies:** Complex inheritance trees with state management
4. **Simple Projects:** Plain functions might be simpler

---

## Testing Strategy

### Protocol Validation Test

```python
# tests/test_node_base.py
def test_node_conforms_to_protocol():
    """Verify a node class matches NodeCallable signature."""
    from agent.nodes.account import AcmeAccountSetupNode
    from agent.nodes.base import NodeCallable
    from typing import cast
    
    # Type cast verifies signature compatibility
    node = cast(NodeCallable, AcmeAccountSetupNode())
    
    # Call it to ensure runtime behavior works
    result = node({"managed_domains": []})
    assert isinstance(result, dict)
```

### Mocking Strategy

```python
# tests/test_checkpoint.py
def fixture_mocked_nodes():
    """Patch registry to inject mock callables."""
    from agent.nodes.registry import NODE_REGISTRY
    
    mock_account = MagicMock(return_value={"acme_account_url": "..."})
    
    # Directly patch registry dict
    NODE_REGISTRY["acme_account_setup"] = mock_account
    
    yield
    
    # Restore original (or use monkeypatch fixture)
```

**Key:** Mock the registry, not the Protocol. Protocol has no runtime presence to mock.

---

## Common Misconceptions

### Misconception 1: "Protocol is like an interface"

**Partially true.** Protocols define contracts like interfaces, but:
- Interfaces (Java, C#): Compile-time + runtime checks
- Protocols (Python): Compile-time ONLY, zero runtime checks

### Misconception 2: "You must import Protocol to implement it"

**False.** Implementing classes never import or reference the Protocol. They just happen to have matching signatures.

### Misconception 3: "isinstance() works with Protocols"

**False (by default).** `isinstance(obj, SomeProtocol)` returns `False` unless you use `@runtime_checkable` decorator (which we don't — adds overhead for no benefit).

### Misconception 4: "Protocol provides code reuse"

**False.** Protocols define **contracts**, not **implementations**. For shared code, use composition or inheritance.

---

## Further Reading

- **PEP 544:** Protocol: Structural subtyping (static duck typing)
  - https://peps.python.org/pep-0544/

- **Python Typing Docs:** Protocols and structural subtyping
  - https://docs.python.org/3/library/typing.html#typing.Protocol

- **Real Python:** Python Protocols
  - https://realpython.com/python-protocol/

---

## Summary

| Aspect | Traditional Inheritance | Protocol Pattern |
|--------|------------------------|------------------|
| Relationship | Explicit (`class Child(Parent)`) | Implicit (matching signature) |
| Coupling | Tight (child depends on parent) | Loose (no dependency) |
| Type Checking | Runtime + compile-time | Compile-time only |
| Boilerplate | High (inherit, implement abstracts) | Low (just match signature) |
| Flexibility | Low (rigid hierarchy) | High (classes + functions) |
| Testing | Mock base class | Mock registry/factory |
| Runtime Cost | Method lookup via MRO | None (direct call) |

**Our Choice:** Protocol pattern for **maximum simplicity** with **type safety** where it matters (development), and **zero overhead** where it matters (production).

---

## Implementation Checklist

When adding a new node using this pattern:

- [ ] Class has `__call__(self, state: AgentState) -> dict` method
- [ ] Class has `run(self, state: AgentState) -> dict` for business logic
- [ ] `__call__` delegates to `run()`
- [ ] **DO NOT** import `NodeCallable` in the node file
- [ ] Add entry to `NODE_REGISTRY` in `agent/nodes/registry.py`
- [ ] Add node name to graph builder's node list
- [ ] Add parity test in `tests/test_node_parity.py` if replacing a function
- [ ] Verify with `uv run pytest -v`

**That's it.** No inheritance, no adapters, no ceremony.
