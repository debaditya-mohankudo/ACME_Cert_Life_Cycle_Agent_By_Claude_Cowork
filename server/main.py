"""
ACME Certificate Lifecycle Agent — FastAPI REST server.

Design decisions (explicit, not accidental)
-------------------------------------------
1. SYNC ONLY. All endpoints are synchronous (def, not async def). This is a
   deliberate architectural decision consistent with the project's sequential,
   deterministic execution model (Design Principle 2 and 8). No async I/O,
   no background tasks, no concurrent ACME operations will be introduced here
   until the project decides to redesign from the ground up.

2. BLOCKING ENDPOINTS. POST /domains/{domain}/renew blocks until the full
   LangGraph run completes. The caller waits. This matches `python main.py
   --once` semantics exactly and preserves nonce sequencing guarantees.

3. DOMAIN AS CORRELATION KEY. Each ACME lifecycle is tied to exactly one
   domain. The domain is injected into the log ContextVar at the start of
   every state-mutating request so all log lines for that run are queryable
   by domain via GET /logs.

4. SINGLE WORKER. This server is intended to run as a single Uvicorn worker
   (no --workers flag). Running multiple workers would allow concurrent ACME
   operations, violating Hard Invariant 4.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make repo root importable when server/ is the working directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI

from server.routers import health, domains, certs, logs

app = FastAPI(
    title="ACME Certificate Lifecycle Agent",
    description=(
        "REST interface for the ACME certificate lifecycle agent. "
        "All state-mutating endpoints are synchronous and blocking — "
        "one domain at a time, by design."
    ),
    version="1.0.0",
)

app.include_router(health.router)
app.include_router(domains.router)
app.include_router(certs.router)
app.include_router(logs.router)
