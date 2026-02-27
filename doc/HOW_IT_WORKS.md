# How It Works

The agent is a LangGraph `StateGraph` that walks through the **ACME protocol (RFC 8555)** step-by-step, with three LLM decision points. Each named node corresponds to a distinct RFC 8555 operation — see [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md) for the full section-level mapping.

## When to use this page

- "How does the renewal workflow execute?"
- "What does each node in the graph do?"
- "What is the control flow of the agent?"
- "How are domains looped and retried?"

## Canonicality

- **Canonical for**: Current graph flow, node execution order, routing decisions, operator-visible behavior
- **Not canonical for**: Design principles (→ [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)), RFC protocol details (→ [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)), node implementation details (→ [NODE_IMPLEMENTATION_ANALYSIS.md](NODE_IMPLEMENTATION_ANALYSIS.md))

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Design principles: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)

## Retrieval keywords

`langgraph`, `stategraph`, `node flow`, `certificate_scanner`, `renewal_planner`, `acme_account_setup`, `order_initializer`, `challenge_verifier`, `retry_scheduler`, `summary_reporter`, `domain loop`
[negative keywords / not-this-doc]
async, concurrency, parallel, checkpoint, nonce, stateful, CI, MCP, revoke, configuration, storage, atomic, filesystem, docker, container, test, coverage, audit, performance, optimization, operator

```
START
  │
  ▼
[certificate_scanner]     — reads ./certs/<domain>/cert.pem, parses expiry
  │
  ▼
[renewal_planner] (LLM)   — classifies domains: urgent / routine / skip
  │
  ├── no renewals needed ──────────────────────────────────► [summary_reporter] ──► END
  │
  ▼
[acme_account_setup]      — registers or retrieves ACME account (EAB injected by CA subclass)
  │
  ▼
[pick_next_domain] ◄──────────────────────────────────────────────────────────┐
  │                                                                            │
  ▼                                                                            │
[order_initializer]       — POST /newOrder, fetch HTTP-01 challenge tokens    │
  │                                                                            │
  ▼                                                                            │
[challenge_setup]         — serve token (standalone server or webroot)        │
  │                                                                            │
  ▼                                                                            │
[challenge_verifier]      — trigger CA verification, poll until valid         │
  │                                                                            │
  ├── failed ──► [error_handler] (LLM) ─── retry ──► [retry_scheduler] ──────┤
  │                                    ├── skip  ────────────────────────────►│
  │                                    └── abort ──────────────────────────► [summary_reporter]
  ▼                                                                            │
[csr_generator]           — generate RSA-2048 private key + CSR               │
  │                                                                            │
  ▼                                                                            │
[order_finalizer]         — POST CSR to /finalize, poll for certificate URL   │
  │                                                                            │
  ▼                                                                            │
[cert_downloader]         — POST-as-GET certificate chain (PEM)               │
  │                                                                            │
  ▼                                                                            │
[storage_manager]         — write cert.pem, chain.pem, fullchain.pem,        │
  │                          privkey.pem, metadata.json to ./certs/<domain>/  │
  │                                                                            │
  ├── more domains ────────────────────────────────────────────────────────────┘
  │
  └── all done ──► [summary_reporter] (LLM) ──► END
```

---

## Metadata

- **Owner**: Architecture team
- **Status**: active (current implementation source)
- **Last reviewed**: 2026-02-27
- **Next review due**: 2026-05-27 (quarterly, or on graph topology changes)
