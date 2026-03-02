# Setup

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Configuration reference: [CONFIGURATION.md](CONFIGURATION.md)
- Usage guide: [USAGE.md](USAGE.md)

---

## 0. Prerequisites

- **Python 3.11+**
- **Port 80 available** (for standalone HTTP-01 challenge mode). On Linux, use `authbind` or `sudo` to bind port 80 as a non-root user. See [HTTP challenge modes](HTTP_CHALLENGE_MODES.md) for options.
- **CA credentials** — for DigiCert: a DigiCert account with ACME enabled (Console → Automation → ACME), obtain your `ACME_EAB_KEY_ID` and `ACME_EAB_HMAC_KEY`. For Let's Encrypt: no credentials needed.
- An **LLM API key** — supports **Anthropic Claude** (default), **OpenAI**, or **Ollama** (local). See [LLM nodes and provider support](LLM_NODES.md).

## 1. Clone and install dependencies

```bash
git clone <repo-url>
cd acme-agent

uv sync
```

## 2. Configure environment

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

All available options are documented in [`.env.example`](../.env.example) and the [Configuration reference](./CONFIGURATION.md).
