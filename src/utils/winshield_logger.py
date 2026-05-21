"""
WinShield+ logging utilities.

Creates timestamped file logs for runtime operations while keeping terminal
output controlled by the banner and print helper utilities.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from utils.winshield_paths import ensure_directory, get_logs_dir


# ------------------------------------------------------------
# LOG PATHS
# ------------------------------------------------------------

def get_log_path(prefix: str = "winshield") -> Path:
    """Return a timestamped log file path."""

    logs_dir = get_logs_dir()
    ensure_directory(logs_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return logs_dir / f"{prefix}_{timestamp}.log"


# ------------------------------------------------------------
# LOGGER HANDLERS
# ------------------------------------------------------------

def close_logger_handlers(logger: logging.Logger) -> None:
    """Flush, close, and remove all handlers from a logger."""

    for handler in logger.handlers[:]:
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


def build_file_handler(log_path: Path) -> logging.FileHandler:
    """Build a configured file handler for WinShield+ logs."""

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)

    return file_handler


# ------------------------------------------------------------
# LOGGER SETUP
# ------------------------------------------------------------

def setup_logger(
    name: str = "winshield",
    prefix: str = "winshield",
) -> logging.Logger:
    """
    Create and return a configured file logger.

    Existing handlers are closed before a new handler is attached. This avoids
    duplicate log entries and releases old log files before artefact cleanup.
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    close_logger_handlers(logger)

    log_path = get_log_path(prefix)
    file_handler = build_file_handler(log_path)

    logger.addHandler(file_handler)

    logger.info("WinShield+ logger started")
    logger.info("Log file: %s", log_path)

    return logger