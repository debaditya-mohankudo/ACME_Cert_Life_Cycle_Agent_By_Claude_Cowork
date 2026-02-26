from __future__ import annotations

import pytest
from typing import cast
from unittest.mock import MagicMock

import agent.graph as main_graph
from agent.nodes.base import NodeCallable
from agent.nodes.registry import get_node
from agent.state import AgentState


class _SampleNode:
    def __call__(self, state: AgentState) -> dict:
        return {"ok": True, "state": state}


def test_callable_node_structural_contract_runs():
    node = _SampleNode()
    callable_node = cast(NodeCallable, node)
    result = callable_node({"x": 1})
    assert result["ok"] is True


def test_callable_node_propagates_exceptions():
    class _FailingNode:
        def __call__(self, _state: AgentState) -> dict:
            raise RuntimeError("boom")

    node = cast(NodeCallable, _FailingNode())
    with pytest.raises(RuntimeError, match="boom"):
        node({})


def test_main_graph_uses_callable_registered_nodes(monkeypatch):
    """
    Verify graph uses node registry and callable class instances are invoked.
    Patches NODE_REGISTRY to inject fake node classes.
    """
    from agent.nodes import registry as node_registry

    calls: list[str] = []

    class _FakeScannerNode:
        def __call__(self, _state):
            calls.append("scanner")
            return {"pending_renewals": []}

    class _FakePlannerNode:
        def __call__(self, _state):
            calls.append("planner")
            return {"pending_renewals": []}

    class _FakeReporterNode:
        def __call__(self, _state):
            calls.append("reporter")
            return {}

    # Patch registry entries with fake node classes
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "certificate_scanner", _FakeScannerNode)
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "renewal_planner", _FakePlannerNode)
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "summary_reporter", _FakeReporterNode)

    graph = main_graph.build_graph(use_checkpointing=False)
    state = main_graph.initial_state(managed_domains=["example.com"])
    graph.invoke(state)

    assert calls == ["scanner", "planner", "reporter"]


def test_node_registry_all_entries_are_classes():
    """
    Verify NODE_REGISTRY architectural consistency after Protocol pattern migration.
    
    All entries must have:
    - String keys (node names)
    - Class values (not function instances)
    
    This ensures get_node() can consistently instantiate all nodes.
    """
    from agent.nodes.registry import NODE_REGISTRY
    
    for node_name, node_value in NODE_REGISTRY.items():
        # All keys must be strings
        assert isinstance(node_name, str), f"Registry key {node_name!r} is not a string"
        
        # All values must be classes (not function instances or other callables)
        assert isinstance(node_value, type), (
            f"Registry entry '{node_name}' is {type(node_value).__name__}, "
            f"expected a class. All nodes must follow the callable class pattern."
        )
        
        # Verify the class is instantiable (has __init__)
        assert hasattr(node_value, "__init__"), (
            f"Registry entry '{node_name}' class {node_value.__name__} "
            f"has no __init__ method"
        )


def test_get_node_rejects_function_registry_entry(monkeypatch):
    """Negative case: function values in NODE_REGISTRY are rejected."""
    from agent.nodes import registry as node_registry

    def _function_node(_state):
        return {}

    monkeypatch.setitem(node_registry.NODE_REGISTRY, "certificate_scanner", _function_node)

    with pytest.raises(TypeError, match="must be a class"):
        get_node("certificate_scanner")


def test_get_node_rejects_mock_callable_registry_entry(monkeypatch):
    """Negative case: callable objects that are not classes are rejected."""
    from agent.nodes import registry as node_registry

    mock_callable = MagicMock(return_value={})
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "certificate_scanner", mock_callable)

    with pytest.raises(TypeError, match="must be a class"):
        get_node("certificate_scanner")
