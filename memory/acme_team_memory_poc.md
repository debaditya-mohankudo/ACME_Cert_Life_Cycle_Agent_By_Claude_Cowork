---
name: acme-team-memory-poc
description: Three-layer team memory POC — SQLite memory, code graph, RAG — location and usage
metadata:
  type: project
  domain: acme
  priority: 10
  tags: team-memory, rag, code-graph, sqlite, tools, poc
---

Team memory POC lives on branch `feat/team-memory-poc`. Three layers implemented under `tools/`:

**Layer 2 — SQLite memory** (`tools/memory_sync.py`, `tools/memory_loader.py`):
- Seed files: `memory/*.md` (frontmatter: name, type, domain, priority, tags)
- Sync: `uv run python tools/memory_sync.py` → writes to `team_memory.sqlite`
- Query: `uv run python tools/memory_loader.py "your prompt" --top 5`

**Layer 3b — Code graph** (`tools/graph_extractor.py`, `tools/code_graph_query.py`):
- Extracts symbols/calls/imports from all `.py` files using stdlib `ast` (zero extra deps)
- Build: `uv run python tools/graph_extractor.py` → writes `code_graph.sqlite`
- Query: `uv run python tools/code_graph_query.py callers sign_request`
- GitHub Action: `.github/workflows/code-graph.yml` — triggers on every PR merge

**Layer 3a — RAG** (`tools/rag_indexer.py`, `tools/rag_query.py`):
- Indexes merged PR descriptions + `doc/` markdown via `sentence-transformers` + ChromaDB
- Install: `uv sync --extra team-memory`
- Build: `uv run python tools/rag_indexer.py` → writes `rag_index/` (5.3 MB, 186 chunks)
- Query: `uv run python tools/rag_query.py "how does JWS signing work" --top 3`
- GitHub Action: `.github/workflows/rag-index.yml` — nightly cron 01:00 UTC

**Unified query** (`tools/context_query.py`):

- Single entry point across all 3 layers
- Auto-extracts CamelCase and snake_case symbols from the prompt for graph layer
- Usage:

  ```bash
  uv run python tools/context_query.py "how does JWS signing work"
  uv run python tools/context_query.py "RenewalPlannerNode" --layers graph
  uv run python tools/context_query.py "atomic storage write" --layers memory rag
  uv run python tools/context_query.py "nonce signing" --inject   # injection-ready for Claude
  ```

**GitHub Actions:**

- `.github/workflows/code-graph.yml` — rebuilds `code_graph.sqlite` on every PR merge
- `.github/workflows/rag-index.yml` — rebuilds RAG index nightly at 01:00 UTC

**Pre-merge checklist (before merging to main):**

- Restore `rag_index/` exclusion in `.gitignore`
- Decide whether to commit `code_graph.sqlite` to main or keep on a separate branch
- Add `context_query.py` usage note to `CLAUDE.md`

**Note:** `rag_index/` is tracked on the POC branch only — restore `.gitignore` exclusion before merging to main.
