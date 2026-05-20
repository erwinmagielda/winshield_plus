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

def get_src_dir() -> Path:
    """Return the source directory."""

    return resolve_project_path("src")


def get_core_dir() -> Path:
    """Return the core Python module directory."""

    return get_src_dir() / "core"


def get_training_dir() -> Path:
    """Return the training pipeline directory."""

    return resolve_project_path("training")


def get_powershell_dir() -> Path:
    """Return the PowerShell script directory."""

    return get_src_dir() / "powershell"


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


# ------------------------------------------------------------
# CORE SCRIPT PATHS
# ------------------------------------------------------------

def get_main_script() -> Path:
    """Return the main WinShield+ runner path."""

    return get_src_dir() / "winshield_main.py"


def get_scanner_script() -> Path:
    """Return the scanner script path."""

    return get_core_dir() / "winshield_scanner.py"


def get_prioritiser_script() -> Path:
    """Return the prioritiser script path."""

    return get_core_dir() / "winshield_prioritiser.py"


def get_downloader_script() -> Path:
    """Return the downloader script path."""

    return get_core_dir() / "winshield_downloader.py"


def get_installer_script() -> Path:
    """Return the installer script path."""

    return get_core_dir() / "winshield_installer.py"


# ------------------------------------------------------------
# TRAINING SCRIPT PATHS
# ------------------------------------------------------------

def get_clear_artefacts_script() -> Path:
    """Return the artefact cleanup script path."""

    return get_training_dir() / "clear_artefacts.py"


def get_data_pipeline_script() -> Path:
    """Return the data pipeline script path."""

    return get_training_dir() / "data_pipeline.py"


def get_model_pipeline_script() -> Path:
    """Return the model pipeline script path."""

    return get_training_dir() / "model_pipeline.py"


def get_regression_training_script() -> Path:
    """Return the regression training script path."""

    return get_training_dir() / "train_regression.py"


def get_classification_training_script() -> Path:
    """Return the classification training script path."""

    return get_training_dir() / "train_classification.py"


def get_clustering_training_script() -> Path:
    """Return the clustering training script path."""

    return get_training_dir() / "train_clustering.py"


# ------------------------------------------------------------
# OUTPUT FILE PATHS
# ------------------------------------------------------------

def get_model_setup_summary_path() -> Path:
    """Return the model setup summary output path."""

    return get_results_dir() / "model_setup_run.json"


def get_model_pipeline_summary_path() -> Path:
    """Return the model pipeline summary output path."""

    return get_results_dir() / "model_pipeline_summary.json"


def get_ranking_results_path() -> Path:
    """Return the ranking results output path."""

    return get_results_dir() / "ranking_results.json"


def get_validated_dataset_path() -> Path:
    """Return the validated training dataset path."""

    return get_dataset_dir() / "validated_dataset.csv"


def get_validated_runtime_path() -> Path:
    """Return the validated runtime dataset path."""

    return get_runtime_dir() / "validated_runtime.csv"


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