# Logger Implementation: Per-Run Unique ID

**Status**: ✅ Production — Implemented and active across all agent nodes

## Overview

Every agent run generates a unique session ID (UUID) at startup. This ID is attached to every log record for the duration of the run, enabling easy tracing of logs from a single execution.

## Benefits

- **Traceability**: Follow all logs from a single run using the run ID
- **Audit trails**: Deterministic correlation of operations to specific executions
- **Debugging**: Match logs with checkpoints/traces without needing external correlation
- **Consistency**: Singleton pattern ensures one logger instance per process

## Implementation

### Architecture

The logging system uses `LoggerWithRunID` — a singleton class in `logger.py`:

```python
class LoggerWithRunID:
    """Singleton logger with per-run UUID injection."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, name="agent"):
        if not hasattr(self, "initialized"):
            self.run_id = str(uuid.uuid4())  # Generated once per process
            self.logger = logging.getLogger(name)
            self.logger.setLevel(logging.INFO)
            self._setup()
            self.initialized = True

    def _setup(self):
        """Configure handler with RunID filter."""
        class RunIDFilter(logging.Filter):
            def filter(inner_self, record):
                record.run_id = self.run_id
                return True

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(run_id)s] %(levelname)s %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addFilter(RunIDFilter())
        self.logger.addHandler(handler)
```

### Module-Level Singleton

At module load, a singleton instance is created:

```python
# logger.py
logger = LoggerWithRunID()  # Instantiated once; all imports get same instance
```

### Usage

Import and use throughout the codebase:

```python
# In any module (agent/nodes/*, main.py, etc.)
from logger import logger

logger.info("Processing domain: %s", domain)
logger.error("Failed to verify challenge", exc_info=True)
```

**Output example**:
```
2026-02-27 14:23:45 [a1b2c3d4-e5f6-7890-abcd-ef1234567890] INFO agent.nodes.planner — Classifying 3 domains for renewal
2026-02-27 14:23:46 [a1b2c3d4-e5f6-7890-abcd-ef1234567890] INFO agent.nodes.order — Creating ACME order for example.com
```

## Integration Points

**Files using logger** (actively in production):
- `main.py` — Entry point
- `mcp_server.py` — MCP integration
- `agent/nodes/*.py` — All 15+ agent nodes (planner, scanner, order, challenge, finalizer, etc.)

**Tests**:
- `tests/test_logger_singleton.py` — Validates singleton pattern and run ID injection

## Design Rationale

### Singleton Pattern

A singleton ensures:
1. **One logger per process** — prevents multiple StreamHandlers writing duplicate logs
2. **Lazy initialization** — logger is created on first import, not at module load time
3. **Thread-safe** — Python's `__new__` is atomic; no race conditions on instantiation

### Why Not Thread-Local?

Thread-local storage was considered but rejected because:
- Agent runs are sequential (one domain at a time per thread)
- Single run ID per process is sufficient (agents don't fork/spawn workers)
- Simpler code and easier to understand

### Filter vs. Formatter

Using a `logging.Filter` (not just Formatter) ensures the run ID is:
- Available to all handlers (even custom ones added later)
- Persistent across logger instances
- Testable independently

## Log Format

```
%(asctime)s [%(run_id)s] %(levelname)s %(name)s — %(message)s
```

| Component | Example | Purpose |
|-----------|---------|---------|
| `asctime` | `2026-02-27 14:23:45` | Timestamp (ISO 8601) |
| `run_id` | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` | Per-run UUID (bracketed for grep-ability) |
| `levelname` | `INFO`, `ERROR`, `WARNING` | Log severity |
| `name` | `agent.nodes.planner` | Module/logger name |
| `message` | `Classifying 3 domains...` | Actual log content |

## See also

- [OBSERVABILITY.md](OBSERVABILITY.md) — Full observability and logging strategy
- [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md) — Logging section in operations hub
- Source: [logger.py](../logger.py)
- Tests: [tests/test_logger_singleton.py](../tests/test_logger_singleton.py)
