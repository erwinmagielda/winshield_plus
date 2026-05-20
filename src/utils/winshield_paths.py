"""
WinShield+ path utilities.

Centralises project paths so core, training, and utility modules can resolve
files consistently from anywhere inside the repository.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# PROJECT ROOT
# ------------------------------------------------------------

def get_project_root() -> Path:
    """
    Return the WinShield+ project root directory.

    Expected layout:

        winshield_plus/
        ├── config/
        ├── data/
        ├── models/
        ├── results/
        ├── src/
        └── training/
    """

    return Path(__file__).resolve().parents[2]


# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------

def get_config_path() -> Path:
    """Return the WinShield+ JSON configuration path."""

    return get_project_root() / "config" / "winshield_config.json"


def load_config() -> dict[str, Any]:
    """
    Load WinShield+ configuration.

    Returns an empty dictionary if the config file is missing or invalid.
    This keeps older modules safe during the refactor.
    """

    config_path = get_config_path()

    if not config_path.exists():
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            return json.load(config_file)
    except json.JSONDecodeError:
        return {}


# ------------------------------------------------------------
# PATH RESOLUTION
# ------------------------------------------------------------

def resolve_project_path(relative_path: str) -> Path:
    """Resolve a repository-relative path from the project root."""

    return get_project_root() / relative_path


def get_path_from_config(path_key: str, fallback: str) -> Path:
    """
    Return a configured project path.

    If the key is missing from config, the fallback path is used.
    """

    config = load_config()
    configured_paths = config.get("paths", {})

    relative_path = configured_paths.get(path_key, fallback)

    return resolve_project_path(relative_path)


# ------------------------------------------------------------
# COMMON DIRECTORIES
# ------------------------------------------------------------

def get_scan_source_dir() -> Path:
    """Return the preserved source scan directory."""

    return get_path_from_config("scan_source_dir", "data/scans")


def get_dataset_dir() -> Path:
    """Return the generated dataset directory."""

    return get_path_from_config("dataset_dir", "data/dataset")


def get_runtime_dir() -> Path:
    """Return the generated runtime directory."""

    return get_path_from_config("runtime_dir", "data/runtime")


def get_logs_dir() -> Path:
    """Return the runtime logs directory."""

    return get_path_from_config("logs_dir", "data/logs")


def get_models_dir() -> Path:
    """Return the generated model artefacts directory."""

    return get_path_from_config("models_dir", "models")


def get_results_dir() -> Path:
    """Return the generated results directory."""

    return get_path_from_config("results_dir", "results")


def get_downloads_dir() -> Path:
    """Return the downloaded update package directory."""

    return get_path_from_config("downloads_dir", "downloads")


def get_powershell_dir() -> Path:
    """Return the PowerShell script directory."""

    return resolve_project_path("src/powershell")


# ------------------------------------------------------------
# DIRECTORY PREPARATION
# ------------------------------------------------------------

def ensure_directory(path: Path) -> None:
    """Create a directory if it does not already exist."""

    path.mkdir(parents=True, exist_ok=True)


def prepare_runtime_directories() -> None:
    """
    Ensure generated runtime directories exist.

    This does not delete existing files. Cleanup is handled separately.
    """

    for directory in [
        get_dataset_dir(),
        get_runtime_dir(),
        get_logs_dir(),
        get_models_dir(),
        get_results_dir(),
        get_downloads_dir(),
    ]:
        ensure_directory(directory)