import pytest
from logger import LoggerWithRunID

def test_logger_singleton_identity():
    log1 = LoggerWithRunID()
    log2 = LoggerWithRunID()
    # Both should be the same object (singleton)
    assert log1 is log2, "LoggerWithRunID should be a singleton"
    # Their .logger attribute should reference the same underlying logger
    assert log1.logger is log2.logger, "Underlying logger should be singleton"
    # Both instances should be the same due to singleton pattern
    assert log1 is log2, "LoggerWithRunID should be a singleton"

def test_logger_singleton_global():
    log1 = LoggerWithRunID()
    log2 = LoggerWithRunID()
    import logging
    # The logger named 'agent' should be the same object
    assert logging.getLogger("agent") is log1.logger
    assert logging.getLogger("agent") is log2.logger
