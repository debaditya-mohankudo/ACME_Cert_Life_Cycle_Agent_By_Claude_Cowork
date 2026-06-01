"""
Central logger for the ACME Certificate Lifecycle Agent.

Domain-scoped logging
---------------------
Each operation is tied to exactly one domain (one ACME lifecycle = one domain).
We use a ContextVar so the domain flows automatically through the call stack
without threading every callsite.

Usage
-----
From any node or helper:

    from logger import logger
    logger.info("Creating order for %s", domain)   # domain stamp injected automatically

From the FastAPI layer (once per request):

    from logger import set_domain
    set_domain("api.example.com")

From the CLI / MCP layer the default sentinel "cli" is used — no setup needed.

Async / sync decision
---------------------
All log emission is synchronous. The SQLite handler opens a new connection per
record and closes it immediately. This is intentional: this project has decided
not to introduce async I/O until a ground-up redesign. The handler must never
block the ACME protocol flow for more than the cost of a local SQLite write,
which is acceptable.
"""
from __future__ import annotations

import logging
import sqlite3
import uuid
from contextvars import ContextVar
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Domain context — set once per request/run, read by the log filter
# ---------------------------------------------------------------------------

_context_domain: ContextVar[str] = ContextVar("acme_domain", default="cli")


def set_domain(domain: str) -> None:
    """Set the active domain for the current execution context."""
    _context_domain.set(domain)


def get_domain() -> str:
    return _context_domain.get()


# ---------------------------------------------------------------------------
# Log filter — stamps every record with the current domain
# ---------------------------------------------------------------------------

class _DomainFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.domain = _context_domain.get()
        return True


# ---------------------------------------------------------------------------
# SQLite handler — persists logs to logs.db, keyed by domain
# Sync-only by design: no async, no background thread, no queue.
# ---------------------------------------------------------------------------

_LOG_DB_PATH = Path(__file__).parent / "logs.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_logs (
    id      INTEGER PRIMARY KEY,
    domain  TEXT    NOT NULL,
    level   TEXT    NOT NULL,
    message TEXT    NOT NULL,
    ts      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_agent_logs_domain ON agent_logs (domain);
"""


class _SQLiteHandler(logging.Handler):
    """Writes log records to logs.db. Never raises — logging must not crash a flow."""

    def __init__(self, db_path: Path = _LOG_DB_PATH) -> None:
        super().__init__()
        self._db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.executescript(_SCHEMA)
        except Exception:
            pass

    def emit(self, record: logging.LogRecord) -> None:
        try:
            domain = getattr(record, "domain", _context_domain.get())
            msg = self.format(record)
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    "INSERT INTO agent_logs (domain, level, message) VALUES (?, ?, ?)",
                    (domain, record.levelname, msg),
                )
        except Exception:
            pass

    def handleError(self, record: logging.LogRecord) -> None:
        pass  # suppress — logging must never crash a protocol node


# ---------------------------------------------------------------------------
# Logger facade — thin wrapper, delegates to stdlib logger
# ---------------------------------------------------------------------------

class _Logger:
    """
    Singleton logger facade with domain-scoped context injection.

    Drop-in replacement for the previous LoggerWithRunID. All callsites
    (nodes, helpers, mcp_server) import `logger` and call .info/.error etc.
    The domain stamp is injected automatically via ContextVar — no callsite
    changes required.
    """

    _instance: "_Logger | None" = None

    def __new__(cls) -> "_Logger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self._logger = logging.getLogger("acme_agent")
        self._logger.setLevel(logging.INFO)
        self._logger.addFilter(_DomainFilter())

        # Stdout handler
        _stdout = logging.StreamHandler()
        _stdout.setFormatter(logging.Formatter(
            "%(asctime)s [%(domain)s] %(levelname)s %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self._logger.addHandler(_stdout)

        # SQLite handler (sync, local write only)
        self._logger.addHandler(_SQLiteHandler())

    # ── Logging methods ────────────────────────────────────────────────────

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.critical(msg, *args, **kwargs)

    # kept for backward-compat with any callsite that used get_run_id()
    def get_run_id(self) -> str:
        return _context_domain.get()


# Module-level singleton — import this everywhere
logger = _Logger()

__all__ = ["logger", "set_domain", "get_domain"]
