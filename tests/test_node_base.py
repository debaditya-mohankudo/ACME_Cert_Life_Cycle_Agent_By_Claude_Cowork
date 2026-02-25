from __future__ import annotations

import pytest
from typing import cast

import agent.graph as main_graph
from agent.nodes.base import NodeCallable
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
    Verify graph uses node registry and callable instances are invoked.
    Patches NODE_REGISTRY to inject fake callables.
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

    # Patch registry entries with fake callables (instances, not classes)
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "certificate_scanner", _FakeScannerNode())
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "renewal_planner", _FakePlannerNode())
    monkeypatch.setitem(node_registry.NODE_REGISTRY, "summary_reporter", _FakeReporterNode())

    graph = main_graph.build_graph(use_checkpointing=False)
    state = main_graph.initial_state(managed_domains=["example.com"])
    graph.invoke(state)

    assert calls == ["scanner", "planner", "reporter"]
