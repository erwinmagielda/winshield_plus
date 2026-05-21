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
# CONFIGURATION
# ------------------------------------------------------------

def get_config_path() -> Path:
    """Return the WinShield+ JSON configuration path."""

    return get_project_root() / "config" / "winshield_config.json"


def load_config() -> dict[str, Any]:
    """
    Load WinShield+ configuration.

    Returns an empty dictionary if the configuration file is missing or invalid.
    This keeps modules safe during local setup and refactoring.
    """

    config_path = get_config_path()

    if not config_path.is_file():
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            config = json.load(config_file)

    except json.JSONDecodeError:
        return {}

    if not isinstance(config, dict):
        return {}

    return config


# ------------------------------------------------------------
# PATH RESOLUTION
# ------------------------------------------------------------

def resolve_project_path(relative_path: str) -> Path:
    """Resolve a repository-relative path from the project root."""

    return get_project_root() / relative_path


def get_path_from_config(path_key: str, fallback: str) -> Path:
    """
    Return a configured project path.

    If the key is missing from the configuration file, the fallback path is used.
    """

    config = load_config()
    configured_paths = config.get("paths", {})

    if not isinstance(configured_paths, dict):
        configured_paths = {}

    relative_path = configured_paths.get(path_key, fallback)

    return resolve_project_path(str(relative_path))


# ------------------------------------------------------------
# SOURCE DIRECTORIES
# ------------------------------------------------------------

def get_src_dir() -> Path:
    """Return the source directory."""

    return resolve_project_path("src")


def get_core_dir() -> Path:
    """Return the core Python module directory."""

    return get_src_dir() / "core"


def get_utils_dir() -> Path:
    """Return the utility module directory."""

    return get_src_dir() / "utils"


def get_training_dir() -> Path:
    """Return the training pipeline directory."""

    return resolve_project_path("training")


def get_powershell_dir() -> Path:
    """Return the PowerShell script directory."""

    return get_src_dir() / "powershell"


# ------------------------------------------------------------
# GENERATED DIRECTORIES
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


def get_reports_dir() -> Path:
    """Return the generated report directory."""

    return get_results_dir() / "reports"


def get_rankings_dir() -> Path:
    """Return the generated ranking output directory."""

    return get_results_dir() / "rankings"


def get_summaries_dir() -> Path:
    """Return the generated pipeline summary directory."""

    return get_results_dir() / "summaries"


def get_charts_dir() -> Path:
    """Return the generated chart directory."""

    return get_results_dir() / "charts"


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


def get_reporter_script() -> Path:
    """Return the reporter script path."""

    return get_core_dir() / "winshield_reporter.py"


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
# DATASET OUTPUT PATHS
# ------------------------------------------------------------

def get_validated_dataset_path() -> Path:
    """Return the validated training dataset path."""

    return get_dataset_dir() / "validated_dataset.csv"


def get_validated_runtime_path() -> Path:
    """Return the validated runtime dataset path."""

    return get_runtime_dir() / "validated_runtime.csv"


# ------------------------------------------------------------
# RESULTS OUTPUT PATHS
# ------------------------------------------------------------

def get_runtime_report_path() -> Path:
    """Return the runtime Markdown report output path."""

    return get_reports_dir() / "winshield_report.md"


def get_ranking_results_path() -> Path:
    """Return the ranking results output path."""

    return get_rankings_dir() / "ranking_results.json"


def get_model_setup_summary_path() -> Path:
    """Return the model setup summary output path."""

    return get_summaries_dir() / "model_setup_run.json"


def get_model_pipeline_summary_path() -> Path:
    """Return the model pipeline summary output path."""

    return get_summaries_dir() / "model_pipeline_summary.json"


def get_training_pipeline_summary_path() -> Path:
    """Return the training data pipeline summary output path."""

    return get_summaries_dir() / "training_pipeline_summary.json"


def get_runtime_pipeline_summary_path() -> Path:
    """Return the runtime data pipeline summary output path."""

    return get_summaries_dir() / "runtime_pipeline_summary.json"


def get_clustering_elbow_chart_path() -> Path:
    """Return the clustering elbow chart output path."""

    return get_charts_dir() / "clustering_elbow_curve.png"


def get_clustering_scatter_chart_path() -> Path:
    """Return the clustering scatter chart output path."""

    return get_charts_dir() / "clustering_scatter.png"


# ------------------------------------------------------------
# DIRECTORY PREPARATION
# ------------------------------------------------------------

def ensure_directory(path: Path) -> None:
    """Create a directory if it does not already exist."""

    path.mkdir(parents=True, exist_ok=True)


def prepare_runtime_directories() -> None:
    """
    Ensure generated runtime directories exist.

    This does not delete existing files. Cleanup is handled separately by the
    artefact cleanup workflow.
    """

    directories = [
        get_dataset_dir(),
        get_runtime_dir(),
        get_logs_dir(),
        get_models_dir(),
        get_results_dir(),
        get_reports_dir(),
        get_rankings_dir(),
        get_summaries_dir(),
        get_charts_dir(),
        get_downloads_dir(),
    ]

    for directory in directories:
        ensure_directory(directory)