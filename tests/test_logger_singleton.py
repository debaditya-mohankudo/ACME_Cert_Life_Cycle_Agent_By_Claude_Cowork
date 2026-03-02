import pytest
import logging
from logger import LoggerWithRunID, LoggerDecorator, RunIDFilter


# === Singleton Tests ===

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
    # The logger named 'agent' should be the same object
    assert logging.getLogger("agent") is log1.logger
    assert logging.getLogger("agent") is log2.logger


# === RunIDFilter Tests ===

def test_run_id_filter_adds_run_id():
    """RunIDFilter should add run_id to log records."""
    run_id = "test-123"
    filter_obj = RunIDFilter(run_id)
    
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="test message", args=(), exc_info=None
    )
    
    result = filter_obj.filter(record)
    assert result is True
    assert hasattr(record, "run_id")
    assert record.run_id == run_id


# === LoggerDecorator Tests ===

def test_logger_decorator_wraps_logger():
    """LoggerDecorator should wrap a standard logger."""
    base_logger = logging.getLogger("test_decorator")
    run_id = "decorator-456"
    
    decorator = LoggerDecorator(base_logger, run_id)
    
    assert decorator.run_id == run_id
    assert decorator._logger is base_logger


def test_logger_decorator_get_run_id():
    """LoggerDecorator.get_run_id() should return the run_id."""
    base_logger = logging.getLogger("test_get_run_id")
    run_id = "run-789"
    
    decorator = LoggerDecorator(base_logger, run_id)
    
    assert decorator.get_run_id() == run_id


def test_logger_decorator_logging_methods(caplog):
    """LoggerDecorator should delegate all logging methods."""
    base_logger = logging.getLogger("test_methods")
    decorator = LoggerDecorator(base_logger, "method-test")
    
    with caplog.at_level(logging.INFO):
        decorator.info("info message")
        decorator.warning("warning message")
        decorator.error("error message")
        decorator.critical("critical message")
    
    # Check that messages were logged (logger is INFO level by default)
    assert "info message" in caplog.text
    assert "warning message" in caplog.text
    assert "error message" in caplog.text
    assert "critical message" in caplog.text


# === Integration Tests ===

def test_logger_with_run_id_delegates_to_decorator():
    """LoggerWithRunID should delegate to LoggerDecorator."""
    logger = LoggerWithRunID()
    
    assert hasattr(logger, "_decorator")
    assert isinstance(logger._decorator, LoggerDecorator)
    assert logger.get_run_id() == logger._decorator.get_run_id()


def test_run_id_in_log_output(caplog):
    """Run ID should appear in actual log output."""
    logger = LoggerWithRunID()
    run_id = logger.get_run_id()
    
    with caplog.at_level(logging.INFO):
        logger.info("test message with run_id")
    
    # The run_id should be in the log record
    assert len(caplog.records) > 0
    assert hasattr(caplog.records[0], "run_id")
    assert caplog.records[0].run_id == run_id
