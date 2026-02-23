# Git Tag Summary

All tags are lightweight and local unless explicitly pushed with `git push --tags`.

Update this file whenever a new tag is added.
See [CLAUDE.md](../CLAUDE.md) for the maintenance protocol.

---

## How to work with tags

```bash
# List all tags
git tag -l

# Show what a tag points to
git show <tag>

# Jump to a tagged state
git checkout <tag>

# Diff between two milestones
git diff <tag-a> <tag-b>

# Push all tags to remote
git push --tags
```

---

## Tag Registry

Tags are ordered chronologically by commit date.

### 2026-02-19 — Core foundation

| Tag | Commit | What it marks |
|---|---|---|
| `jws-signing` | `341a61c` | JWK key generation, JWS signing, DigiCert EAB support via josepy — the entire crypto layer |
| `acme-client-core` | `733a245` | Full stateless RFC 8555 ACME client: directory → nonce → account → order → auth → finalize → download |
| `agent-state` | `5b0aac0` | `AgentState` TypedDict + `AcmeOrder` with multi-SAN `List[str]` fields — the core data model |
| `langgraph-agent` | `873f8d5` | LangGraph `StateGraph` fully wired: all nodes, conditional edges, checkpointer support — agent is alive |
| `filesystem-storage` | `bb4393c` | Filesystem backend for reading, writing, and listing PEM certificates and private keys |
| `cli-entrypoint` | `68b5e3e` | CLI: `--once`, `--schedule`, `--domains`, `--checkpoint` — first usable product |

---

### 2026-02-20 — Protocol hardening

| Tag | Commit | What it marks |
|---|---|---|
| `acme-client-base` | `9a517c6` | `AcmeClient` base class with `DigiCertAcmeClient` and `LetsEncryptAcmeClient` subclasses |
| `cert-revocation` | `7a4e0c5` | `revoke_certificate()` added to `AcmeClient` per RFC 8555 §7.6; reason code validation |

---

### 2026-02-21 — Extensibility

| Tag | Commit | What it marks |
|---|---|---|
| `retry-scheduler` | `6ef60bf` | `retry_scheduler` node with exponential backoff — robustness milestone |
| `docker-support` | `ea3c2fb` | Multi-stage Dockerfile: base → test-runner (gated) → production → test |
| `llm-provider-agnostic` | `f5bccd5` | LLM factory pattern — Anthropic, OpenAI, Ollama all work via `LLM_PROVIDER` |
| `knowledge-base` | `243e620` | FAISS-based KB with sentence-transformers (experimental, optional feature) |
| `multi-ca-support` | `5aa6327` | ZeroSSL + Sectigo via `EabAcmeClient` shared hierarchy; `make_client()` factory |
| `ollama-llm-provider` | `3a7be23` | Ollama (mistral:7b-instruct) configured as default local LLM provider |

---

### 2026-02-22 — Security, testing, and operations

| Tag | Commit | What it marks |
|---|---|---|
| `atomic-file-writes` | `b1be379` | Crash-safe PEM writes via temp + fsync + atomic rename (`storage/atomic.py`) |
| `claude-md-architecture` | `9e665ab` | CLAUDE.md restructured into 4-layer constitutional + operational guardrail document |
| `github-actions-ci` | `9d7d850` | GitHub Actions workflow: unit tests on every push/PR to `main` |
| `checkpoint-tests` | `2b45f35` | 10 LangGraph `MemorySaver` checkpoint/interrupt/resume tests |
| `planner-validation` | `9ce1c52` | 12 tests for LLM hallucination stripping and domain validation in planner node |
| `revocation-subgraph` | `0e058a0` | Full revocation `StateGraph` + CLI (`--revoke-cert`) — agent-level revocation flow |
| `dns-01-implementation` | `2c73ba4` | DNS-01 challenge: Cloudflare, Route53, Google Cloud DNS providers |
| `jws-nonce-validation` | `fbb25ce` | Pre-signing nonce and URL guards in `sign_request()` — silent `badNonce` prevention |

---

## Tag count: 22
