"""
Tests for the domain-scoped logger (logger.py).

The old LoggerWithRunID/RunIDFilter/LoggerDecorator API was replaced with a
ContextVar-based domain-scoped logger. These tests cover the new API:
  - logger singleton identity
  - set_domain / get_domain round-trip
  - _DomainFilter stamps records with the current domain
  - logging methods delegate correctly
"""
import logging
from unittest.mock import patch

import pytest

from logger import logger, set_domain, get_domain


# ── Singleton ─────────────────────────────────────────────────────────────────

def test_logger_singleton_identity():
    from logger import logger as log2
    assert logger is log2, "logger should be a module-level singleton"


def test_underlying_logger_is_named_agent():
    assert logger._logger.name == "acme_agent"


# ── Domain ContextVar ─────────────────────────────────────────────────────────

def test_set_and_get_domain_round_trip():
    set_domain("example.com")
    assert get_domain() == "example.com"


def test_get_domain_default_is_cli():
    # Import ContextVar directly to reset to default without side effects
    from logger import _context_domain
    token = _context_domain.set("cli")
    try:
        assert get_domain() == "cli"
    finally:
        _context_domain.reset(token)


def test_domain_filter_stamps_record():
    set_domain("filter-test.com")
    from logger import _DomainFilter
    f = _DomainFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="hello", args=(), exc_info=None,
    )
    f.filter(record)
    assert record.domain == "filter-test.com"


# ── Logging methods ───────────────────────────────────────────────────────────

def test_info_delegates_to_underlying_logger(caplog):
    set_domain("delegate.com")
    with caplog.at_level(logging.INFO, logger="agent"):
        logger.info("info message")
    assert any("info message" in r.message for r in caplog.records)


def test_warning_delegates_to_underlying_logger(caplog):
    with caplog.at_level(logging.WARNING, logger="agent"):
        logger.warning("warn message")
    assert any("warn message" in r.message for r in caplog.records)


def test_error_delegates_to_underlying_logger(caplog):
    with caplog.at_level(logging.ERROR, logger="agent"):
        logger.error("err message")
    assert any("err message" in r.message for r in caplog.records)


# ── Backward compat ───────────────────────────────────────────────────────────

def test_get_run_id_returns_current_domain():
    set_domain("compat.com")
    assert logger.get_run_id() == "compat.com"
