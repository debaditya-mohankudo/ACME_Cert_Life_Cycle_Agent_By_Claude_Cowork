# Feature Matrix — Availability & Status

Quick reference table of all supported features, test coverage, and configuration.

## Challenge Modes

| Feature | Status | Setup Doc | Config Env Var | Test Coverage | Notes |
|---------|--------|-----------|---|---|---|
| **HTTP-01 (Standalone)** | ✅ Production | [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md) | `HTTP_CHALLENGE_MODE=standalone` | ✅ Full | Built-in HTTP server on port 80 |
| **HTTP-01 (Webroot)** | ✅ Production | [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md) | `HTTP_CHALLENGE_MODE=webroot` + `WEBROOT_PATH` | ✅ Full | Requires existing web server |
| **DNS-01 (Cloudflare)** | ✅ Production | [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) | `HTTP_CHALLENGE_MODE=dns` + `DNS_PROVIDER=cloudflare` | ✅ Full | Via `dns-cloudflare` package |
| **DNS-01 (Route53)** | ✅ Production | [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) | `HTTP_CHALLENGE_MODE=dns` + `DNS_PROVIDER=route53` | ✅ Full | Requires AWS credentials |
| **DNS-01 (Google Cloud DNS)** | ✅ Production | [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) | `HTTP_CHALLENGE_MODE=dns` + `DNS_PROVIDER=google` | ✅ Full | Requires GCP service account |

## CA Providers

| CA | Status | EAB Required | Setup Doc | Config Env Var | Test Coverage | Notes |
|---|--------|---|---|---|---|---|
| **Let's Encrypt (Production)** | ✅ Production | No | [LETS_ENCRYPT.md](LETS_ENCRYPT.md) | `CA_PROVIDER=letsencrypt` | ✅ Full | Free, trusted, generous rate limits |
| **Let's Encrypt (Staging)** | ✅ Production | No | [LETS_ENCRYPT.md](LETS_ENCRYPT.md) | `CA_PROVIDER=letsencrypt_staging` | ✅ Full | For testing; certs not trusted |
| **DigiCert** | ✅ Production | Yes | [acme/client.py](../acme/client.py) | `CA_PROVIDER=digicert` + EAB vars | ✅ Full | Requires API credentials |
| **ZeroSSL** | ✅ Production | Yes | [acme/client.py](../acme/client.py) | `CA_PROVIDER=zerossl` + EAB vars | ✅ Full | Alternative EAB provider |
| **Sectigo** | ✅ Production | Yes | [acme/client.py](../acme/client.py) | `CA_PROVIDER=sectigo` + EAB vars | ✅ Full | Legacy/compatibility |
| **Custom ACME** | ✅ Production | Varies | [CONFIGURATION.md](CONFIGURATION.md) | `CA_PROVIDER=custom` + `ACME_DIRECTORY_URL` | ⚠️ Limited | For non-standard endpoints |

## Core Operations

| Feature | Status | Setup Doc | Config Env Var | Test Coverage | Notes |
|---------|--------|-----------|---|---|---|
| **Certificate Renewal** | ✅ Production | [USAGE.md](USAGE.md) | `python main.py --once` | ✅ Full | Renews all managed domains |
| **Scheduled Renewal** | ✅ Production | [USAGE.md](USAGE.md) | `python main.py --schedule` | ✅ Full | Daily loop, configurable interval |
| **Certificate Revocation** | ✅ Production | [REVOCATION_IMPLEMENTATION.md](REVOCATION_IMPLEMENTATION.md) | `python main.py --revoke-cert <domains> --reason <code>` | ✅ Full | On-demand via CLI |
| **Checkpoint/Resume** | ✅ Production | [CHECKPOINT_TESTS.md](CHECKPOINT_TESTS.md) | `python main.py --once --checkpoint` | ✅ Full | Via LangGraph MemorySaver |
| **Multi-Domain Support** | ✅ Production | [CONFIGURATION.md](CONFIGURATION.md) | `MANAGED_DOMAINS=a.com,b.com,c.com` | ✅ Full | Sequential processing (no parallelism) |

## Infrastructure & Tooling

| Feature | Status | Setup Doc | Config | Test Coverage | Notes |
|---------|--------|-----------|--------|---|---|
| **Docker Runtime** | ✅ Production | [DOCKER.md](DOCKER.md) | See docker-compose | ✅ Full | Standard + non-root variants |
| **Docker Non-Root** | ✅ Production | [DOCKER_NONROOT.md](DOCKER_NONROOT.md) | See dockerfile | ✅ Full | Hardened container image |
| **MCP Server Mode** | ✅ Production | [MCP_SERVER.md](MCP_SERVER.md) | See mcp config | ✅ Full | LLM-callable tools |
| **Pebble Integration** | ✅ Testing | [PEBBLE_TESTING_SERVER.md](PEBBLE_TESTING_SERVER.md) | Docker Compose | ✅ Full | Local ACME testing |

## LLM & Automation

| Feature | Status | Setup Doc | Config | Test Coverage | Notes |
|---------|--------|-----------|--------|---|---|
| **Renewal Planner (LLM)** | ✅ Production | [LLM_NODES.md](LLM_NODES.md) | `LLM_PROVIDER` + `LLM_MODEL_PLANNER` | ✅ Full | Classifies renewal priority |
| **Error Handler (LLM)** | ✅ Production | [LLM_NODES.md](LLM_NODES.md) | `LLM_PROVIDER` + `LLM_MODEL_ERROR_HANDLER` | ✅ Full | Decides retry/skip/abort |
| **Reporter (LLM)** | ✅ Production | [LLM_NODES.md](LLM_NODES.md) | `LLM_PROVIDER` + `LLM_MODEL_REPORTER` | ✅ Full | Generates summaries |
| **Anthropic API** | ✅ Production | [llm/factory.py](../llm/factory.py) | `LLM_PROVIDER=anthropic` + `ANTHROPIC_API_KEY` | ✅ Full | Default provider |
| **OpenAI API** | ✅ Production | [llm/factory.py](../llm/factory.py) | `LLM_PROVIDER=openai` + `OPENAI_API_KEY` | ✅ Full | Alternative provider |
| **Ollama (Local)** | ✅ Production | [llm/factory.py](../llm/factory.py) | `LLM_PROVIDER=ollama` + `OLLAMA_BASE_URL` | ✅ Full | No API key needed |
| **Planner Validation** | ✅ Production | [PLANNER_VALIDATION_TESTS.md](PLANNER_VALIDATION_TESTS.md) | Automatic | ✅ Full | Strips hallucinated domains |

---

## Legend

- **✅ Production** = Implemented, fully tested, documented, recommended for use
- **🔶 Proposed** = Designed but not yet implemented
- **⚠️ Limited** = Implemented but limited scope or testing
- **❌ Unsupported** = Not implemented; considered out-of-scope

---

## Test Statistics

As of 2026-02-27:

- **Unit tests**: 101 (ACME client, crypto, state, nodes)
- **Integration tests**: 45 (Pebble ACME server, lifecycle flows)
- **Total**: 146 passing tests
- **Coverage**: All production features have explicit test cases

See [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md) for detailed breakdown.

---

## See also

- Quick setup: [SETUP.md](SETUP.md)
- Full configuration reference: [CONFIGURATION.md](CONFIGURATION.md)
- Usage guide: [USAGE.md](USAGE.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Security & quality: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
- Test coverage details: [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md)
