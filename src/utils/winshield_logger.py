"""
WinShield+ logging utilities.

Creates simple timestamped log files for runtime operations while keeping
terminal output separate from file logging.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from winshield_paths import get_logs_dir, ensure_directory


# ------------------------------------------------------------
# LOGGER CONFIGURATION
# ------------------------------------------------------------

def get_log_path(prefix: str = "winshield") -> Path:
    """Return a timestamped log file path."""

    logs_dir = get_logs_dir()
    ensure_directory(logs_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return logs_dir / f"{prefix}_{timestamp}.log"


def setup_logger(name: str = "winshield", prefix: str = "winshield") -> logging.Logger:
    """
    Create and return a configured file logger.

    Existing handlers are cleared so repeated setup calls do not duplicate log
    entries in the same process.
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    log_path = get_log_path(prefix)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info("WinShield+ logger started")
    logger.info("Log file: %s", log_path)

    return logger