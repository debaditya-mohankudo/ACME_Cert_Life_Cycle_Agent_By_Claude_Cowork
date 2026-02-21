# Project Structure

```
acme-agent/
├── main.py                      # CLI entry point
├── config.py                    # Pydantic settings (all env vars)
├── requirements.txt
├── .env.example                 # Copy to .env and fill in credentials
├── CLAUDE.md                    # Development guide and conventions
│
├── llm/
│   ├── __init__.py
│   └── factory.py               # Provider-agnostic LLM factory (Anthropic, OpenAI, Ollama)
│
├── acme/
│   ├── client.py                # Stateless ACME RFC 8555 HTTP client
│   ├── crypto.py                # Domain key generation + CSR creation
│   ├── jws.py                   # JWK / JWS / EAB signing (josepy)
│   └── http_challenge.py        # Standalone HTTP-01 server + webroot writer
│
├── storage/
│   └── filesystem.py            # PEM read/write, expiry parsing, metadata
│
├── agent/
│   ├── state.py                 # AgentState, CertRecord, AcmeOrder TypedDicts
│   ├── graph.py                 # StateGraph builder + initial_state helper
│   ├── prompts.py               # LLM prompts for planner, error handler, reporter
│   └── nodes/
│       ├── scanner.py           # certificate_scanner
│       ├── planner.py           # renewal_planner (LLM)
│       ├── account.py           # acme_account_setup
│       ├── order.py             # order_initializer
│       ├── challenge.py         # challenge_setup + challenge_verifier
│       ├── csr.py               # csr_generator
│       ├── finalizer.py         # order_finalizer + cert_downloader
│       ├── storage.py           # storage_manager
│       ├── router.py            # routing functions for conditional edges
│       ├── error_handler.py     # error_handler (LLM)
│       ├── retry_scheduler.py   # retry_scheduler (applies backoff)
│       └── reporter.py          # summary_reporter (LLM)
│
├── doc/                         # Detailed documentation
│   ├── SECURITY.md              # 13-section security analysis (TLS, ACME, LLM validation, etc.)
│   └── DOCKER_TEST_FLOW.md      # End-to-end Pebble integration test flow in Docker
│
├── kb/                          # FAISS vector knowledge base (experimental)
│   ├── build_index.py           # Build semantic index from docs + code
│   ├── query.py                 # CLI for natural-language semantic search
│   ├── requirements.txt         # faiss-cpu, sentence-transformers
│   ├── index.faiss              # Pre-built FAISS vector index (177 chunks)
│   ├── chunks.json              # Chunk metadata and text
│   └── __init__.py
│
├── tests/
│   ├── conftest.py              # Pebble fixture, mock_llm_nodes fixture
│   ├── test_unit_acme.py        # Unit tests (ACME, crypto, state)
│   ├── test_integration_pebble.py
│   ├── test_lifecycle_pebble.py
│   └── test_kb.py               # KB chunking + FAISS search tests
│
├── certs/                       # Generated PEM files (gitignored)
    └── api.example.com/
        ├── cert.pem
        ├── chain.pem
        ├── fullchain.pem
        ├── privkey.pem          # chmod 600
        └── metadata.json
```
