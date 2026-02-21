# Setup

## 1. Clone and install dependencies

```bash
git clone <repo-url>
cd acme-agent

# Using uv (recommended)
uv sync

# Or with pip in a virtualenv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
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
