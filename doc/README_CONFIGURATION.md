# Configuration Reference

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
| `ACME_INSECURE` | `false` | Disable TLS verification — **testing only, never in production** |
| `ACME_CA_BUNDLE` | — | Path to custom CA certificate bundle for private ACME servers |
| `LANGCHAIN_TRACING_V2` | `false` | Enable LangSmith tracing |
| `LANGCHAIN_API_KEY` | — | LangSmith API key (required when tracing is enabled) |
| `LANGCHAIN_PROJECT` | `acme-cert-agent` | LangSmith project name |
