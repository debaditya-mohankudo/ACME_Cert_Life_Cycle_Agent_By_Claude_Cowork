# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

**Deterministic mode** (`LLM_DISABLED=true`): No LLM API calls; fully auditable renewal logic for air-gapped installations and cost optimization.

Designed for the coming **47-day TLS mandate (2029)**, where automated renewal is not optional.

---

## Team Memory POC (`feat/team-memory-poc`)

A three-layer context memory system that gives Claude persistent, structured knowledge about this codebase — surviving across sessions without re-deriving context from scratch.

| Layer | What | Signal |
| ----- | ---- | ------ |
| 2 — SQLite memory | 10 curated facts, gotchas, decisions | Keyword scoring |
| 3b — Code graph | 1,027 symbols · 3,943 call edges | Structural (ast) |
| 3a — RAG | 186 chunks from `doc/` + merged PRs | Semantic (embeddings) |

All three layers are unified behind a single CLI:

```bash
# Install extra dependencies
uv sync --extra team-memory

# Query all 3 layers at once
uv run python tools/context_query.py "how does JWS signing work"
```

**Example output for `"JWS signing nonce"`:**

```text
────────────────────────────────────────────────────────────
## Layer 2 — SQLite Memory (curated facts)
────────────────────────────────────────────────────────────
### [feedback] acme-jws-signing
JWS signing requires a fresh nonce for every ACME POST — nonces are single-use and server-issued.
Why: ACME RFC 8555 §6.5 — replay attack prevention. Reusing a nonce causes a `badNonce` error.
How to apply: Never cache or reuse `current_nonce`. It flows through `AgentState`...

────────────────────────────────────────────────────────────
## Layer 3b — Code Graph (structural)
────────────────────────────────────────────────────────────
Symbols matching 'JWS':
  acme/client.py:424  method _post_jws
  acme/jws.py:148     function create_eab_jws
  tests/test_unit_acme.py:360  function test_post_as_get_empty_payload_jws
  ...

────────────────────────────────────────────────────────────
## Layer 3a — RAG (semantic / docs + PRs)
────────────────────────────────────────────────────────────
### [1] doc/SECURITY.md — SECURITY (score: 0.065)
...nonce replay protection. Fresh nonce per request; `badNonce` retry logic...
```

Target specific layers, or get Claude-injection-ready output:

```bash
uv run python tools/context_query.py "RenewalPlannerNode" --layers graph
uv run python tools/context_query.py "atomic storage write" --layers memory rag
uv run python tools/context_query.py "nonce signing" --inject
```

See [memory/acme_team_memory_poc.md](memory/acme_team_memory_poc.md) for full setup, usage, and how to add new memories.

---

## Quality & Testing

[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](doc/CI_TEST_COVERAGE.md)
[![Unit Tests](https://img.shields.io/badge/unit_tests-527_passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](doc/CI_TEST_COVERAGE.md)
[![Integration Tests](https://img.shields.io/badge/integration_tests-9_pebble-blue?style=for-the-badge&logo=docker&logoColor=white)](doc/CI_TEST_COVERAGE.md)
[![CI Runtime](https://img.shields.io/badge/CI_runtime-~9s-blue?style=for-the-badge&logo=githubactions&logoColor=white)](doc/CI_TEST_COVERAGE.md)

| Metric | Value |
| --- | --- |
| Line coverage | **92%** — 6,338 / 6,884 statements |
| Unit tests (CI) | 527 · parallel via `xdist` · ~9 s |
| Integration tests | 9 against Pebble ACME mock server |
| Total | 536 tests |
| Modules at 100% | `router` · `planner` · `registry` · `state` · `graph` · `crypto` · `prompts` · `revocation_graph` |

Coverage lifts from targeted tests: `router` 60%→**100%** · `storage` 23%→**96%** · `error_handler` 26%→**98%** · `finalizer` 22%→**88%**

See [CI_TEST_COVERAGE.md](doc/CI_TEST_COVERAGE.md) for the full per-file breakdown.

## Documentation

| Topic | Link |
| --- | --- |
| Docs wiki home | [WIKI_HOME.md](doc/WIKI_HOME.md) |
| How it works | [HOW_IT_WORKS.md](doc/HOW_IT_WORKS.md) |
| Project structure | [PROJECT_STRUCTURE.md](doc/PROJECT_STRUCTURE.md) |
| Setup (includes prerequisites) | [SETUP.md](doc/SETUP.md) |
| Running with Docker | [DOCKER.md](doc/DOCKER.md) |
| Usage | [USAGE.md](doc/USAGE.md) |
| MCP server usage | [MCP_SERVER.md](doc/MCP_SERVER.md) |
| Pebble testing server | [PEBBLE_TESTING_SERVER.md](doc/PEBBLE_TESTING_SERVER.md) |
| Configuration reference | [CONFIGURATION.md](doc/CONFIGURATION.md) |
| Certificate revocation | [REVOCATION_IMPLEMENTATION.md](doc/REVOCATION_IMPLEMENTATION.md) |
| Certificate storage layout | [CERTIFICATE_STORAGE.md](doc/CERTIFICATE_STORAGE.md) |
| HTTP-01 challenge modes | [HTTP_CHALLENGE_MODES.md](doc/HTTP_CHALLENGE_MODES.md) |
| HTTP-01 validation explained | [HTTP_01_VALIDATION_EXPLAINED.md](doc/HTTP_01_VALIDATION_EXPLAINED.md) |
| LLM nodes and provider support | [LLM_NODES.md](doc/LLM_NODES.md) |
| Let's Encrypt | [LETS_ENCRYPT.md](doc/LETS_ENCRYPT.md) |
| Observability | [OBSERVABILITY.md](doc/OBSERVABILITY.md) |
| Security considerations | [SECURITY.md](doc/SECURITY.md) |
| Dependencies | [DEPENDENCIES.md](doc/DEPENDENCIES.md) |

## Quick CLI examples

```bash
python main.py --once
python main.py --schedule
python main.py --expiring-in-30-days
python main.py --domain-status my.local api.example.com
python main.py --generate-test-cert example.com --days 90
python main.py --revoke-cert example.com --reason 4
# Deterministic mode (no LLM API calls)
LLM_DISABLED=true python main.py --once
python mcp_server.py
```

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
