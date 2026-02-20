# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

Designed for the coming **47-day TLS mandate (2029)**, where automated renewal is not optional.

---

## How it works

The agent is a LangGraph `StateGraph` that walks through the ACME protocol step-by-step, with three LLM decision points:

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
  ├── failed ──► [error_handler] (LLM) ─── retry ──────────────────────────── ┤
  │                                    ├── skip  ─────────────────────────────►│
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

## Project structure

```
acme-agent/
├── main.py                      # CLI entry point
├── config.py                    # Pydantic settings (all env vars)
├── requirements.txt
├── .env.example                 # Copy to .env and fill in credentials
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
│       └── reporter.py          # summary_reporter (LLM)
│
└── certs/                       # Generated PEM files (gitignored)
    └── api.example.com/
        ├── cert.pem
        ├── chain.pem
        ├── fullchain.pem
        ├── privkey.pem          # chmod 600
        └── metadata.json
```

---

## Prerequisites

- **Python 3.11+**
- **Port 80 available** (for standalone HTTP-01 challenge mode). On Linux, use `authbind` or `sudo` to bind port 80 as a non-root user. See [Port 80 note](#port-80-note) below.
- **CA credentials** — for DigiCert: a DigiCert account with ACME enabled (Console → Automation → ACME), obtain your `ACME_EAB_KEY_ID` and `ACME_EAB_HMAC_KEY`. For Let's Encrypt: no credentials needed.
- An **LLM API key** — supports **Anthropic Claude** (default), **OpenAI**, or **Ollama** (local). See [LLM configuration](#llm-provider-configuration) below.

---

## Setup

### 1. Clone and install dependencies

```bash
git clone <repo-url>
cd acme-agent

# Using uv (recommended)
uv pip install -r requirements.txt

# Or with pip in a virtualenv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```dotenv
# CA provider (digicert | letsencrypt | letsencrypt_staging | custom)
CA_PROVIDER=digicert

# EAB credentials (required for DigiCert; leave empty for Let's Encrypt)
ACME_EAB_KEY_ID=your-eab-key-id
ACME_EAB_HMAC_KEY=your-base64url-hmac-key

# Domains to monitor (comma-separated)
MANAGED_DOMAINS=api.example.com,shop.example.com

# LLM provider (anthropic | openai | ollama)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...      # Required when LLM_PROVIDER=anthropic
# OPENAI_API_KEY=sk-...           # Uncomment for OpenAI
# OLLAMA_BASE_URL=http://localhost:11434  # Ollama local server
```

All available options are documented in [`.env.example`](.env.example).

---

## Usage

### Run one renewal cycle immediately

```bash
python main.py --once
```

### Run on a daily schedule

```bash
python main.py --schedule
```

Runs immediately on start, then repeats daily at `SCHEDULE_TIME` (default `06:00` UTC).

### Override domains for a single run

```bash
python main.py --once --domains api.example.com shop.example.com
```

### Enable checkpointing (resume interrupted runs)

```bash
python main.py --once --checkpoint
```

Uses LangGraph's `MemorySaver` to checkpoint state after each node. If a run is interrupted mid-flow (e.g., a network failure during finalization), the graph can resume from the last completed node.

---

## Configuration reference

All settings are read from environment variables or `.env`. Any variable can be overridden by setting it in the shell before running.

| Variable | Default | Description |
|---|---|---|
| `CA_PROVIDER` | `digicert` | CA to use: `digicert` · `letsencrypt` · `letsencrypt_staging` · `custom` |
| `ACME_EAB_KEY_ID` | — | EAB key identifier (DigiCert only) |
| `ACME_EAB_HMAC_KEY` | — | Base64url-encoded HMAC key (DigiCert only) |
| `ACME_DIRECTORY_URL` | *(auto-set)* | ACME directory URL — auto-populated from `CA_PROVIDER`; required only when `CA_PROVIDER=custom` |
| `MANAGED_DOMAINS` | *(required)* | Comma-separated list of domains to monitor |
| `RENEWAL_THRESHOLD_DAYS` | `30` | Renew when fewer than N days remain |
| `CERT_STORE_PATH` | `./certs` | Root directory for PEM files |
| `ACCOUNT_KEY_PATH` | `./account.key` | Path to persist the ACME account key |
| `HTTP_CHALLENGE_MODE` | `standalone` | `standalone` or `webroot` |
| `HTTP_CHALLENGE_PORT` | `80` | Port for the standalone HTTP-01 server |
| `WEBROOT_PATH` | — | Required when `HTTP_CHALLENGE_MODE=webroot` |
| `LLM_PROVIDER` | `anthropic` | LLM vendor: `anthropic` · `openai` · `ollama` |
| `ANTHROPIC_API_KEY` | — | Claude API key (required when `LLM_PROVIDER=anthropic`) |
| `OPENAI_API_KEY` | — | OpenAI API key (required when `LLM_PROVIDER=openai`) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama local server URL (used when `LLM_PROVIDER=ollama`) |
| `LLM_MODEL_PLANNER` | `claude-haiku-4-5-20251001` | Model for renewal planning (adjust based on `LLM_PROVIDER`) |
| `LLM_MODEL_ERROR_HANDLER` | `claude-sonnet-4-6` | Model for error analysis |
| `LLM_MODEL_REPORTER` | `claude-haiku-4-5-20251001` | Model for run summary |
| `SCHEDULE_TIME` | `06:00` | Daily run time (HH:MM, UTC) |
| `MAX_RETRIES` | `3` | Per-domain retry attempts before skipping |

---

## Certificate storage layout

Each renewed domain gets its own subdirectory:

```
./certs/api.example.com/
├── cert.pem        # Leaf certificate (end-entity only)
├── chain.pem       # Intermediate CA chain
├── fullchain.pem   # cert.pem + chain.pem — use this in nginx/apache
├── privkey.pem     # RSA-2048 private key (mode 0o600)
└── metadata.json   # {"issued_at", "expires_at", "acme_order_url", "renewed_by"}
```

Point your web server at `fullchain.pem` and `privkey.pem`:

```nginx
ssl_certificate     /path/to/certs/api.example.com/fullchain.pem;
ssl_certificate_key /path/to/certs/api.example.com/privkey.pem;
```

---

## HTTP-01 challenge modes

### Standalone (default)

The agent spins up a minimal HTTP server on port 80 for the duration of each challenge. No existing web server is required. Port 80 must not already be in use during the renewal window.

### Webroot

If nginx or Apache is already serving on port 80, set:

```dotenv
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

The agent writes the token file to `<WEBROOT_PATH>/.well-known/acme-challenge/<token>` and cleans it up after verification.

### Port 80 note

On Linux, non-root processes cannot bind port 80 by default. Options:

```bash
# Option 1: authbind
sudo apt install authbind
sudo touch /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80
sudo chown $(whoami) /etc/authbind/byport/80
authbind --deep python main.py --once

# Option 2: grant capability to the Python binary
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Option 3: non-privileged port + iptables redirect
HTTP_CHALLENGE_PORT=8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

---

## LLM nodes and provider support

All three LLM decision points use a **provider-agnostic factory** (`llm.factory.make_llm()`), allowing you to switch between vendors by changing a single config variable.

| Node | Default model | Responsibility |
|---|---|---|
| `renewal_planner` | Haiku | Classify domains as urgent / routine / skip; output is validated JSON |
| `error_handler` | Sonnet | Diagnose ACME failures; decide retry / skip / abort with exponential backoff |
| `summary_reporter` | Haiku | Generate a human-readable run summary for ops teams |

The planner validates its own output: any domain name the LLM returns that is not in `MANAGED_DOMAINS` is stripped before use, preventing hallucinated domains from triggering unintended renewals.

### LLM provider configuration

The agent supports **Anthropic Claude** (default), **OpenAI**, and **Ollama**. Switch providers by setting `LLM_PROVIDER` in `.env`:

#### Anthropic (default)
```dotenv
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL_PLANNER=claude-haiku-4-5-20251001
LLM_MODEL_REPORTER=claude-haiku-4-5-20251001
LLM_MODEL_ERROR_HANDLER=claude-sonnet-4-6
```

#### OpenAI
```dotenv
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
LLM_MODEL_PLANNER=gpt-4o-mini
LLM_MODEL_REPORTER=gpt-4o-mini
LLM_MODEL_ERROR_HANDLER=gpt-4o
```

#### Ollama (local)
```dotenv
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL_PLANNER=llama3.2
LLM_MODEL_REPORTER=llama3.2
LLM_MODEL_ERROR_HANDLER=llama3.2
```

---

## Let's Encrypt

Let's Encrypt is a free, globally trusted CA that requires no account registration fee and no EAB credentials. Set `CA_PROVIDER` and you are ready to go — the agent selects the correct directory URL and skips EAB automatically.

### Staging (recommended for testing)

Let's Encrypt staging issues certificates that are **not browser-trusted** but exercise the complete ACME flow identically to production. Use this first to validate your setup without consuming production rate-limit quota.

```dotenv
CA_PROVIDER=letsencrypt_staging
MANAGED_DOMAINS=api.example.com,shop.example.com
ANTHROPIC_API_KEY=sk-ant-...
```

```bash
python main.py --once
```

### Production

Once staging works end-to-end, switch to production with a single config change:

```dotenv
CA_PROVIDER=letsencrypt
MANAGED_DOMAINS=api.example.com,shop.example.com
ANTHROPIC_API_KEY=sk-ant-...
```

```bash
python main.py --once
```

Certificates issued in production are browser-trusted and valid for 90 days. With `RENEWAL_THRESHOLD_DAYS=30` (the default), the agent renews approximately 30 days before expiry — well inside Let's Encrypt's recommended renewal window.

### Rate limits

Let's Encrypt enforces rate limits on the production endpoint. The most relevant:

| Limit | Value |
|---|---|
| Certificates per registered domain per week | 50 |
| Duplicate certificates per week | 5 |
| Failed validations per account per domain per hour | 5 |
| New orders per account per 3 hours | 300 |

Staging has much higher (effectively unlimited) limits. Always test with `CA_PROVIDER=letsencrypt_staging` before running against production.

### Switching between staging and production

Both environments share the same account key file. However, staging accounts cannot be reused on production — delete `account.key` (or point `ACCOUNT_KEY_PATH` to a different file) when switching environments so the agent registers a fresh account.

```bash
# Switch from staging to production
rm ./account.key          # or set ACCOUNT_KEY_PATH=./account-prod.key
CA_PROVIDER=letsencrypt python main.py --once
```

### Directory URLs (set automatically)

| `CA_PROVIDER` | Directory URL |
|---|---|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` |
| `letsencrypt_staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` |

These are preset inside `LetsEncryptAcmeClient` — no manual URL configuration required.

---

## Observability

### Log output

All nodes emit structured log lines via Python's standard `logging`:

```
2026-02-19 06:00:01 INFO  agent.nodes.scanner   — api.example.com → expires 2026-02-24 (5 days) — URGENT
2026-02-19 06:00:03 INFO  agent.nodes.account   — Retrieved existing ACME account: https://acme.digicert.com/...
2026-02-19 06:00:07 INFO  agent.nodes.challenge — Authorization https://... is VALID
2026-02-19 06:00:12 INFO  agent.nodes.storage   — Stored PEM files for api.example.com (expires 2026-05-20)
```

### LangSmith tracing (optional)

Add to `.env` to trace every LLM call and node transition in the LangSmith UI:

```dotenv
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=ls__...
LANGCHAIN_PROJECT=acme-cert-agent
```

> **Security:** The ACME account private key is never stored in `AgentState` and will not appear in LangSmith traces. It is loaded from disk only within the node functions that need it.

---

## Security considerations

| Concern | Mitigation |
|---|---|
| Private key exposure | `privkey.pem` and `account.key` are written with `chmod 600` immediately after creation |
| EAB credential leakage | Stored in `.env` only — `.gitignore` excludes `.env` |
| LangSmith trace exposure | Account key is never placed in `AgentState` |
| Port 80 attack surface | Standalone server binds only during the challenge window, then shuts down |
| LLM hallucination | Planner output is validated against `MANAGED_DOMAINS` before any domain is acted upon |

---

## Dependencies

| Package | Purpose |
|---|---|
| `langgraph` | Stateful agent graph execution |
| `langchain` | LLM abstraction layer |
| `langchain-anthropic` | Claude LLM integration (default) |
| `langchain-openai` | OpenAI LLM integration |
| `langchain-ollama` | Ollama LLM integration (local models) |
| `josepy` | JWK / JWS signing (Certbot's battle-tested library) |
| `cryptography` | Key generation, CSR creation, certificate parsing |
| `requests` | ACME HTTP client |
| `pydantic-settings` | Environment-based configuration with validation |
| `schedule` | Lightweight daily scheduler |
| `structlog` | Structured logging |
| `pytest` + `responses` | Unit testing with mocked HTTP |
