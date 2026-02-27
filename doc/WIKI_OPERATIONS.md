# Wiki Hub: Operations

Use this hub for setup, runtime usage, environment configuration, and day-to-day operations.

---

## Agent Use Rules

- Start here for "how to run", "which command", and "which setting" questions.
- Answer CLI behavior from [USAGE.md](USAGE.md) and environment semantics from [CONFIGURATION.md](CONFIGURATION.md).
- For HTTP-01, use [HTTP_CHALLENGE_MODES.md](HTTP_CHALLENGE_MODES.md) as short orientation and [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md) as the detailed source.

---

## Setup and Bootstrapping

- Setup and prerequisites: [SETUP.md](SETUP.md)
- Dependency management: [DEPENDENCIES.md](DEPENDENCIES.md)

---

## Runtime Usage

- CLI usage and modes: [USAGE.md](USAGE.md)
- How it works (operator view): [HOW_IT_WORKS.md](HOW_IT_WORKS.md)
- Project structure map: [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
- Logging and observability: [LOGGER_IMPLEMENTATION_PLAN.md](LOGGER_IMPLEMENTATION_PLAN.md)

### Logging: Per-Run Unique ID (Production)

Every agent run generates a unique session ID (UUID) at startup and attaches it to every log record. This enables easy tracing and auditing of logs from a single execution.

**Status**: ✅ Production — Singleton logger active across all agent nodes

**Key features:**
- **Run ID injection**: Automatic UUID in every log message via `LoggerWithRunID` singleton
- **Traceability**: Follow all logs from a single run using the run ID
- **Audit trails**: Deterministic correlation of operations to specific executions
- **Output format**: `%(asctime)s [%(run_id)s] %(levelname)s %(name)s — %(message)s`

**Example output**:
```
2026-02-27 14:23:45 [a1b2c3d4-e5f6-7890-abcd-ef1234567890] INFO agent.nodes.planner — Classifying 3 domains
```

**Usage**: Import the singleton logger in any module:
```python
from logger import logger
logger.info("Processing domain: %s", domain)
```

**See also**: [LOGGER_IMPLEMENTATION_PLAN.md](LOGGER_IMPLEMENTATION_PLAN.md) for architecture, design rationale, and integration points.

---

## Configuration

- Complete configuration reference: [CONFIGURATION.md](CONFIGURATION.md)
- HTTP challenge modes: [HTTP_CHALLENGE_MODES.md](HTTP_CHALLENGE_MODES.md)
- HTTP challenge configuration details: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
- Let's Encrypt specifics: [LETS_ENCRYPT.md](LETS_ENCRYPT.md)

---

## Docker and Local Infra

- Docker runtime guide: [DOCKER.md](DOCKER.md)
- Non-root Docker hardening: [DOCKER_NONROOT.md](DOCKER_NONROOT.md)
- Docker test flow: [DOCKER_TEST_FLOW.md](DOCKER_TEST_FLOW.md)
- Pebble ACME test server: [PEBBLE_TESTING_SERVER.md](PEBBLE_TESTING_SERVER.md)

---

## Domain-Specific Features

### Challenge Modes

- **HTTP-01 (Standalone)** — Built-in HTTP server on port 80
  - Setup: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
  - Config: `HTTP_CHALLENGE_MODE=standalone`
  - Quick intro: [HTTP_CHALLENGE_MODES.md](HTTP_CHALLENGE_MODES.md)

- **HTTP-01 (Webroot)** — Serve tokens from existing web server
  - Setup: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
  - Config: `HTTP_CHALLENGE_MODE=webroot` + `WEBROOT_PATH=/path/to/webroot`
  - Internals: [HTTP_01_VALIDATION_EXPLAINED.md](HTTP_01_VALIDATION_EXPLAINED.md)

- **DNS-01 (DNS CNAME)** — Cloudflare, Route53, Google Cloud DNS
  - Setup: [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md)
  - Supported providers: Cloudflare, Route53, Google Cloud DNS
  - Config: `HTTP_CHALLENGE_MODE=dns` + provider-specific env vars

### Revocation

- **Certificate Revocation** — On-demand revocation via CLI
  - Implementation: [REVOCATION_IMPLEMENTATION.md](REVOCATION_IMPLEMENTATION.md)
  - Usage: `python main.py --revoke-cert domain1.com domain2.com --reason 4`
  - Reason codes: 0=unspecified, 1=keyCompromise, 4=superseded, 5=cessation

### CA Providers

- Let's Encrypt: [LETS_ENCRYPT.md](LETS_ENCRYPT.md)
- DigiCert, ZeroSSL, Sectigo: See [acme/client.py](../acme/client.py) class hierarchy
- Feature matrix: [FEATURE_MATRIX.md](FEATURE_MATRIX.md) (quick reference table)

---

## MCP Operations

- MCP server usage: [MCP_SERVER.md](MCP_SERVER.md)
- MCP implementation details: [MCP_IMPLEMENTATION_DETAILS.md](MCP_IMPLEMENTATION_DETAILS.md)
- MCP serialization/locking rationale: [MCP_TOOL_SERIALIZATION.md](MCP_TOOL_SERIALIZATION.md)

---

## See also

- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
- Docs home: [WIKI_HOME.md](WIKI_HOME.md)
