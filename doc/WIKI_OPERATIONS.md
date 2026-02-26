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
- Logger implementation plan: [LOGGER_IMPLEMENTATION_PLAN.md](LOGGER_IMPLEMENTATION_PLAN.md)
- Logging: Per-Run Unique ID Pattern

### Logging: Per-Run Unique ID Pattern

To improve traceability and auditability, every agent run generates a unique session ID (UUID) at startup. This ID is attached to every log record for the duration of the run.

**Pattern:**

1. Generate a unique run/session ID at process start (e.g., in main.py).
2. Initialize a singleton logger instance.
3. Inject the run ID into every log record using a logging.Filter or custom formatter.
4. All log statements automatically include the run ID.

**Benefits:**
- Enables easy tracing of logs from a single execution.
- Supports deterministic audit trails and debugging.
- Keeps logging configuration consistent across the codebase.

**Implementation Example:**
```python
import logging, uuid

RUN_ID = str(uuid.uuid4())

class RunIDFilter(logging.Filter):
    def filter(self, record):
        record.run_id = RUN_ID
        return True

logger = logging.getLogger("agent")
logger.addFilter(RunIDFilter())
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(run_id)s] %(levelname)s %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

logger.info("Agent started.")
```

Document this pattern in architecture and operations docs if extended or modified.

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

## MCP Operations

- MCP server usage: [MCP_SERVER.md](MCP_SERVER.md)
- MCP implementation details: [MCP_IMPLEMENTATION_DETAILS.md](MCP_IMPLEMENTATION_DETAILS.md)
- MCP serialization/locking rationale: [MCP_TOOL_SERIALIZATION.md](MCP_TOOL_SERIALIZATION.md)

---

## See also

- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
- Docs home: [WIKI_HOME.md](WIKI_HOME.md)
