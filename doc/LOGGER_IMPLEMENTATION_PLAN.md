# Logger Implementation Plan: Per-Run Unique ID

## Overview

To improve traceability and auditability, every agent run generates a unique session ID (UUID) at startup. This ID is attached to every log record for the duration of the run.

## Pattern

1. Generate a unique run/session ID at process start (e.g., in main.py).
2. Initialize a singleton logger instance.
3. Inject the run ID into every log record using a logging.Filter or custom formatter.
4. All log statements automatically include the run ID.

## Benefits
- Enables easy tracing of logs from a single execution.
- Supports deterministic audit trails and debugging.
- Keeps logging configuration consistent across the codebase.

## Implementation Example
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

## Documentation

Document this pattern in architecture and operations docs if extended or modified.
