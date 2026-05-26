---
name: acme-agent-graph
description: LangGraph-based agent structure — nodes, routing, and state shape
metadata:
  type: project
  domain: acme
  priority: 10
  tags: langgraph, graph, nodes, state, routing
---

Agent is a deterministic LangGraph `StateGraph`. All workflow state lives in `AgentState` (`agent/state.py`).

Node order: planner → scanner → account → order → challenge → csr → finalizer → storage → reporter.
Error path: any node → error_handler → retry_scheduler → pick_next_domain (or abort).
Revocation is a separate graph: `agent/revocation_graph.py`.

**Why:** Sequential by design — ACME protocol requires one nonce per POST, concurrent operations would corrupt nonce state.

**How to apply:** Never parallelize domain handling. Never bypass graph routing. New features = new named nodes, not helper functions with hidden network calls. Graph topology changes require updating `doc/DESIGN_PRINCIPLES.md`.
