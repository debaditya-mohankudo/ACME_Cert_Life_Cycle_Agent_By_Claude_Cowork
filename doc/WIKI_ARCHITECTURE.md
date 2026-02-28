# Wiki Hub: Architecture

Use this hub for system design decisions, invariants, and protocol-level rationale.

---

## Agent Use Rules

- Start here for "why" and "design constraint" questions.
- Prefer [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for current flow descriptions, then validate constraints in [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md).
- Project Strcuture [PROJECT_STRUCTURE.md]
- Treat [ACME_AGENT_PLAN.md](ACME_AGENT_PLAN.md) as historical design context, not current implementation truth.

---

## Core Design

- Constitutional design rules: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)
- RFC constraints and protocol correctness: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- Current graph flow: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)
- Original design specification: [ACME_AGENT_PLAN.md](ACME_AGENT_PLAN.md)
- Protocol node pattern: [DESIGN_PROTOCOL_PATTERN.md](DESIGN_PROTOCOL_PATTERN.md)

---

## Architecture Deep Dives

- Nonce management strategy: [DESIGN_NONCE_MANAGEMENT_STRATEGY.md](DESIGN_NONCE_MANAGEMENT_STRATEGY.md)
- Retry/backoff analysis: [DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md](DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md)
- Async scheduler design notes: [DESIGN_ASYNC_SCHEDULER_PLAN.md](DESIGN_ASYNC_SCHEDULER_PLAN.md)
- Stateful vs stateless client analysis: [DESIGN_STATEFUL_CLIENT_ANALYSIS.md](DESIGN_STATEFUL_CLIENT_ANALYSIS.md)
- Planner rationale: [DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md](DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md)
- Node implementation analysis: [NODE_IMPLEMENTATION_ANALYSIS.md](NODE_IMPLEMENTATION_ANALYSIS.md)

---

## Node Architecture

- Node protocol design: [DESIGN_PROTOCOL_PATTERN.md](DESIGN_PROTOCOL_PATTERN.md)
- Node implementation verification: [NODE_IMPLEMENTATION_ANALYSIS.md](NODE_IMPLEMENTATION_ANALYSIS.md) (17 nodes, 100% compliance)
- Node registry and factory: [agent/nodes/registry.py](../agent/nodes/registry.py)

---

## Code Patterns & Implementation

- Python idioms and design patterns: [PYTHONIC_IDIOMS.md](PYTHONIC_IDIOMS.md) (19 patterns: TypedDict, ABC, Protocols, context managers, factories, etc.)
- Project file structure: [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)

---

## Retrieval keywords
architecture, design, invariants, protocol, graph, node, node implementation, protocol pattern, structural typing, callable, RFC, constraint, rationale, hub, agent, copilot, claude, wiki, navigation, see also
[negative keywords / not-this-doc]
backoff, retry, exponential, scheduler, error handler, integration, bounded, cap, MAX_RETRIES, deterministic, safety, pebble, langgraph, acme, workflow, async, concurrency, parallel, checkpoint, nonce, stateful, planner, LLM, CI, MCP, revoke, HTTP-01, DNS-01, EAB, CA, configuration, storage, atomic, certificate, account, key, private, TLS, docker, container, test, coverage, audit, compliance, scaling, throughput, performance, optimization, operator
## See also

- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
