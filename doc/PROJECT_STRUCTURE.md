# Project Structure

## When to use this page

- "Where is a particular module or feature located?"
- "What does this directory contain?"
- "How is the code organized?"
- "What file should I look at for X?"

## Canonicality

- **Canonical for**: Directory tree, file locations, module organization, high-level structure
- **Not canonical for**: Code implementation details (→ specific module files), architectural decisions (→ [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)), node architecture (→ [NODE_IMPLEMENTATION_ANALYSIS.md](NODE_IMPLEMENTATION_ANALYSIS.md))

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- System flow: [HOW_IT_WORKS.md](HOW_IT_WORKS.md)
- Architecture principles: [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md)

```
acme-agent/
├── main.py                      # CLI entry point
├── config.py                    # Pydantic settings (all env vars)
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
│   ├── http_challenge.py        # Standalone HTTP-01 server + webroot writer
│   ├── dns_challenge.py         # DNS-01 TXT value computation + provider adapters (Cloudflare, Route53, Google)
│   └── ca_detection.py          # X.509 issuer inspection → CA provider string; returns None if unrecognised
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
├── tests/
│   ├── conftest.py              # Pebble fixture, mock_llm_nodes fixture
│   ├── test_unit_acme.py        # Unit tests (ACME, crypto, state)
│   ├── test_integration_pebble.py
│   └── test_lifecycle_pebble.py
│
├── certs/                       # Generated PEM files (gitignored)
    └── api.example.com/
        ├── cert.pem
        ├── chain.pem
        ├── fullchain.pem
        ├── privkey.pem          # chmod 600
        └── metadata.json
```

---

## Metadata

- **Owner**: Architecture team
- **Status**: active (structural reference)
- **Last reviewed**: 2026-02-27
- **Next review due**: 2026-05-27 (quarterly, or on new modules)

