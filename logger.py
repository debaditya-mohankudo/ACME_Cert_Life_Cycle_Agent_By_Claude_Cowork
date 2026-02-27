import logging
import uuid

class LoggerWithRunID:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, name="agent"):
        if not hasattr(self, "initialized"):
            self.run_id = str(uuid.uuid4())
            self.logger = logging.getLogger(name)
            self.logger.setLevel(logging.INFO)
            self._setup()
            self.initialized = True

    def _setup(self):
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

    def info(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.logger.exception(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def get_run_id(self):
        return self.run_id

__all__ = ["LoggerWithRunID", "logger"]

# Module-level singleton instance to avoid callers instantiating during import,
# which can cause race conditions when many modules create their own instances.
logger = LoggerWithRunID()
