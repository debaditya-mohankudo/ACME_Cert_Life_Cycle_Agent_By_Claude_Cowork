"""GET /logs — query persisted agent logs by domain."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Literal, Optional, TypedDict

from fastapi import APIRouter, Query

router = APIRouter(prefix="/logs", tags=["logs"])

_LOG_DB = Path(__file__).parent.parent.parent / "logs.db"

LogLevel = Literal["INFO", "WARNING", "ERROR", "DEBUG", "CRITICAL"]


class LogEntry(TypedDict):
    ts: str
    level: str
    message: str


class LogsResponse(TypedDict):
    domain: str
    logs: list[LogEntry]
    count: int


@router.get("")
def get_logs(
    domain: str = Query(..., description="Domain to fetch logs for"),
    limit: int = Query(default=200, ge=1, le=1000),
    level: Optional[LogLevel] = Query(default=None, description="Filter by log level"),
) -> LogsResponse:
    """
    Return persisted log lines for a domain.

    All log lines emitted during a renew or revoke run are stored in logs.db
    tagged with the domain name. Use this endpoint to inspect what happened
    during a specific run without tailing stdout.
    """
    if not _LOG_DB.exists():
        return {"domain": domain, "logs": [], "count": 0}

    query = "SELECT ts, level, message FROM agent_logs WHERE domain = ?"
    params: list[Any] = [domain]

    if level:
        query += " AND level = ?"
        params.append(level)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    try:
        with sqlite3.connect(_LOG_DB) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
        entries = [{"ts": r["ts"], "level": r["level"], "message": r["message"]} for r in rows]
        return {"domain": domain, "logs": entries, "count": len(entries)}
    except Exception as exc:
        return {"domain": domain, "logs": [], "count": 0, "error": str(exc)}
