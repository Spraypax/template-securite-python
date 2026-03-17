import logging
import pytest


def test_logger_exists():
    from tp1.utils.config import logger
    assert logger is not None

def test_logger_name():
    from tp1.utils.config import logger
    assert logger.name == "TP1"

def test_logger_is_logging_instance():
    from tp1.utils.config import logger
    assert isinstance(logger, logging.Logger)

def test_logger_file_handler_exists():
    root_logger = logging.getLogger()
    handler_types = [type(h) for h in root_logger.handlers]
    assert any(issubclass(t, logging.FileHandler) for t in handler_types)

def test_logger_stream_handler_exists():
    root_logger = logging.getLogger()
    handler_types = [type(h) for h in root_logger.handlers]
    assert any(issubclass(t, logging.StreamHandler) for t in handler_types)
