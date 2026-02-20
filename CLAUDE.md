# ACME Certificate Lifecycle Agent — Claude Code Guide

## Project overview
LangGraph StateGraph + Claude agent that automates TLS certificate renewal via the ACME RFC 8555 protocol. Supports DigiCert (EAB), Let's Encrypt, Let's Encrypt Staging, and custom CAs. Uses HTTP-01 challenge in standalone (port 80) or webroot mode.

## Commands

### Run the agent
```bash
python main.py --once                              # one renewal cycle
python main.py --schedule                          # daily schedule (default 06:00 UTC)
python main.py --once --domains api.example.com   # override managed domains
python main.py --once --checkpoint                 # with MemorySaver checkpointing
```

### Install dependencies
```bash
pip install -r requirements.txt
# or with uv:
uv sync
```

### Run tests
```bash
# Unit tests (no external services needed)
pytest tests/test_unit_acme.py -v

# Integration tests (require Pebble ACME server)
docker compose -f docker-compose.pebble.yml up -d
pytest tests/test_integration_pebble.py tests/test_lifecycle_pebble.py -v

# All tests
pytest -v
```

## Project structure
```
config.py                   # Pydantic Settings singleton (import `settings`)
main.py                     # CLI entry point
llm/
  __init__.py
  factory.py                # make_llm(model, max_tokens) — provider-agnostic factory
agent/
  state.py                  # AgentState TypedDict + AcmeOrder dataclass
  graph.py                  # build_graph() + initial_state() helpers
  prompts.py                # LLM prompt templates
  nodes/
    planner.py              # LLM: decides which domains need renewal
    scanner.py              # checks cert expiry on disk
    account.py              # ACME account registration
    order.py                # ACME order + authorization fetch
    challenge.py            # HTTP-01 challenge setup/teardown
    csr.py                  # CSR generation
    finalizer.py            # order finalization + cert download
    storage.py              # saves cert/key to CERT_STORE_PATH
    reporter.py             # LLM: generates human-readable summary
    error_handler.py        # LLM: handles errors, sets retry_delay
    router.py               # conditional edge logic
acme/
  client.py                 # AcmeClient base, DigiCertAcmeClient (EAB),
                            # LetsEncryptAcmeClient, make_client() factory
  jws.py                    # josepy JWK/JWS/EAB — account key operations
  crypto.py                 # domain key generation + CSR building
  http_challenge.py         # standalone HTTP server or webroot file writer
tests/
  conftest.py               # pebble_settings + mock_llm_nodes fixtures
  test_unit_acme.py         # unit tests (no network)
  test_integration_pebble.py
  test_lifecycle_pebble.py
```

## Key architecture decisions

### State & security
- **Account key never goes in AgentState** — would appear in LangSmith traces. It stays on disk at `ACCOUNT_KEY_PATH`.
- `AcmeOrder` uses `List[str]` for `auth_urls`, `challenge_urls`, `tokens`, `key_auths` to support multi-SAN certs.
- CSR is stored as a hex string in the order dict so it can travel through LangGraph state safely.
- `current_nonce` flows through state so every node picks up a fresh nonce.

### LLM provider and models
All nodes use a single `LLM_PROVIDER` (default `anthropic`). The factory lives in `llm/factory.py`
and is called as `make_llm(model, max_tokens)` — nodes never import a provider class directly.

| Node | Default model (Anthropic) | `max_tokens` |
|------|--------------------------|-------------|
| planner | `claude-haiku-4-5-20251001` | 512 |
| reporter | `claude-haiku-4-5-20251001` | 512 |
| error_handler | `claude-sonnet-4-6` | 256 |

Override via `.env`: `LLM_PROVIDER`, `LLM_MODEL_PLANNER`, `LLM_MODEL_REPORTER`, `LLM_MODEL_ERROR_HANDLER`.
When switching providers, set the corresponding model names (e.g. `LLM_MODEL_PLANNER=gpt-4o-mini` for OpenAI).

### Retry / resilience
- `retry_delay_seconds` doubles on each retry (exponential backoff via `error_handler` node).
- `MAX_RETRIES` (default 3) controls the retry ceiling.

### Planner output validation
- Planner output is validated to strip any domains not present in `managed_domains` (prevents LLM hallucination of out-of-scope domains).

## Configuration (`.env`)

```env
# CA selection
CA_PROVIDER=digicert          # digicert | letsencrypt | letsencrypt_staging | custom

# EAB credentials (DigiCert only)
ACME_EAB_KEY_ID=
ACME_EAB_HMAC_KEY=

# Custom CA (only when CA_PROVIDER=custom)
ACME_DIRECTORY_URL=

# Domains — comma-separated or JSON list
MANAGED_DOMAINS=api.example.com,shop.example.com

# Storage
CERT_STORE_PATH=./certs
ACCOUNT_KEY_PATH=./account.key

# HTTP-01 challenge
HTTP_CHALLENGE_MODE=standalone   # standalone | webroot
HTTP_CHALLENGE_PORT=80
WEBROOT_PATH=                    # required if HTTP_CHALLENGE_MODE=webroot

# LLM provider (anthropic | openai | ollama)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=               # required when LLM_PROVIDER=anthropic
OPENAI_API_KEY=                  # required when LLM_PROVIDER=openai
OLLAMA_BASE_URL=http://localhost:11434  # used when LLM_PROVIDER=ollama

# LLM models (set provider-appropriate model names when switching LLM_PROVIDER)
# LLM_MODEL_PLANNER=claude-haiku-4-5-20251001
# LLM_MODEL_REPORTER=claude-haiku-4-5-20251001
# LLM_MODEL_ERROR_HANDLER=claude-sonnet-4-6

# Scheduling
SCHEDULE_TIME=06:00              # HH:MM UTC

# Retry
MAX_RETRIES=3
RENEWAL_THRESHOLD_DAYS=30

# Testing only — never in production
ACME_INSECURE=false
ACME_CA_BUNDLE=

# LangSmith (optional)
LANGCHAIN_TRACING_V2=false
LANGCHAIN_API_KEY=
LANGCHAIN_PROJECT=acme-cert-agent
```

## Testing conventions
- Pebble integration tests are auto-skipped when Pebble isn't running (`requires_pebble` marker).
- Use `pebble_settings` fixture to mutate the `settings` singleton for a test; it restores originals via teardown.
- Use `mock_llm_nodes` fixture to patch `llm.factory.init_chat_model` — no API key needed for any provider.
- LLM mocks must return `AIMessage` objects (not plain `MagicMock`) so LangGraph's `add_messages` reducer accepts them.

## Documentation maintenance

### After code changes
When you modify the agent architecture, ACME protocol logic, or node behavior, update these files:
- **`ACME_Agent_Plan.md`** — if architecture, topology, or phase design changes
- **`README.md`** — if usage, configuration, or CLI changes
- **`CLAUDE.md`** — if project structure, commands, or key decisions change

### After running tests
Always update test documentation:
- **`TEST_RESULTS.md`** — run `pytest -v` and paste full output; update summary table
- **`TEST_SUMMARY.md`** — update test counts, duration, and prose descriptions of what each suite validates

Keep these synchronized so future sessions (yours or others') have accurate, current documentation.

## What NOT to do
- Do not put the account key or any private key material into `AgentState`.
- Do not set `ACME_INSECURE=true` in production.
- Do not add domains to the planner's output that aren't in `managed_domains`.
- Do not change `MANAGED_DOMAINS` parsing — the `_CommaFallbackMixin` in `config.py` handles pydantic-settings ≥2.7 quirks with comma-separated env vars.
