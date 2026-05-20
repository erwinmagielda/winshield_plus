"""
WinShield+ main runner.

Provides the operator menu for scanning, risk ranking, update handling,
artefact cleanup, and model setup.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from utils.winshield_banner import (
    print_error,
    print_info,
    print_menu_header,
    print_step,
    print_success,
    print_warning,
    print_workflow_header,
)
from utils.winshield_logger import setup_logger
from utils.winshield_paths import (
    get_models_dir,
    get_project_root,
    get_results_dir,
    get_runtime_dir,
    prepare_runtime_directories,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

ROOT_DIR = get_project_root()
SRC_DIR = ROOT_DIR / "src"
CORE_DIR = SRC_DIR / "core"
TRAINING_DIR = ROOT_DIR / "training"

DATA_PIPELINE_SCRIPT = TRAINING_DIR / "data_pipeline.py"
MODEL_PIPELINE_SCRIPT = TRAINING_DIR / "model_pipeline.py"
CLEAR_ARTEFACTS_SCRIPT = TRAINING_DIR / "clear_artefacts.py"

SCANNER_SCRIPT = CORE_DIR / "winshield_scanner.py"
PRIORITISER_SCRIPT = CORE_DIR / "winshield_prioritiser.py"
DOWNLOADER_SCRIPT = CORE_DIR / "winshield_downloader.py"
INSTALLER_SCRIPT = CORE_DIR / "winshield_installer.py"

RUNTIME_DIR = get_runtime_dir()
MODELS_DIR = get_models_dir()
RESULTS_DIR = get_results_dir()

MODEL_SETUP_RUN_PATH = RESULTS_DIR / "model_setup_run.json"

PYTHON_EXE = sys.executable


# ------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------

LOGGER = setup_logger(name="winshield", prefix="winshield")


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean console output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def prepare_environment() -> bool:
    """Prepare runtime directories before the menu starts."""

    try:
        prepare_runtime_directories()
        return True

    except Exception as exc:
        print_error(f"Failed to prepare runtime directories: {exc}")
        return False


# ------------------------------------------------------------
# STAGES
# ------------------------------------------------------------

STAGES: dict[str, tuple[str, Path]] = {
    "1": ("Scan System", SCANNER_SCRIPT),
    "3": ("Download Update", DOWNLOADER_SCRIPT),
    "4": ("Install Update", INSTALLER_SCRIPT),
    "5": ("Clear Artefacts", CLEAR_ARTEFACTS_SCRIPT),
}


# ------------------------------------------------------------
# VALIDATION HELPERS
# ------------------------------------------------------------

def models_are_present() -> bool:
    """Return True if the required trained model artefacts are present."""

    required_artefacts = [
        MODELS_DIR / "regression_model.joblib",
        MODELS_DIR / "regression_preprocessor.joblib",
        MODELS_DIR / "classification_model.joblib",
        MODELS_DIR / "classification_preprocessor.joblib",
        MODELS_DIR / "clustering_model.joblib",
        MODELS_DIR / "clustering_preprocessor.joblib",
        MODELS_DIR / "clustering_features.joblib",
    ]

    missing_artefacts = [
        artefact for artefact in required_artefacts
        if not artefact.is_file()
    ]

    if missing_artefacts:
        print_error("Required model artefacts missing")
        for artefact in missing_artefacts:
            print(f"    - {relative_path(artefact)}")

        return False

    return True


def runtime_scan_is_present() -> bool:
    """Return True if a runtime system scan is available."""

    return RUNTIME_DIR.is_dir() and any(RUNTIME_DIR.glob("scan_*.json"))


# ------------------------------------------------------------
# STAGE EXECUTION
# ------------------------------------------------------------

def run_stage(label: str, script_path: Path) -> int:
    """Run a single workflow stage and return its exit code."""

    print_workflow_header(label)

    if not script_path.is_file():
        print_error(f"Stage script missing: {relative_path(script_path)}")
        LOGGER.error("Stage script missing: %s", relative_path(script_path))
        return 1

    print_step(f"Running {relative_path(script_path)}")
    LOGGER.info("Running stage: %s (%s)", label, relative_path(script_path))

    try:
        completed = subprocess.run(
            [PYTHON_EXE, str(script_path)],
            cwd=ROOT_DIR,
            check=False,
        )

    except KeyboardInterrupt:
        print()
        print_warning(f"{label} cancelled")
        LOGGER.warning("%s cancelled", label)
        return 130

    except Exception as exc:
        print_error(f"{label} failed to launch: {exc}")
        LOGGER.exception("%s failed to launch", label)
        return 1

    return_code = int(completed.returncode or 0)

    if return_code != 0:
        print()
        print_error(f"{label} failed: exit code {return_code}")
        LOGGER.error("%s failed with exit code %s", label, return_code)
    else:
        LOGGER.info("%s completed successfully", label)

    return return_code


# ------------------------------------------------------------
# MODEL SETUP PIPELINE
# ------------------------------------------------------------

def run_model_setup() -> int:
    """Run training data preparation followed by model training."""

    print_workflow_header("Model Setup")
    LOGGER.info("Model Setup started")

    pipeline = [
        ("Data Pipeline", DATA_PIPELINE_SCRIPT, ["--mode", "training"]),
        ("Model Pipeline", MODEL_PIPELINE_SCRIPT, []),
    ]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "pipeline": "model_setup",
        "started_at_utc": utc_timestamp(),
        "finished_at_utc": None,
        "status": "running",
        "stages": [],
    }

    print_info(f"Setup details: {relative_path(MODEL_SETUP_RUN_PATH)}")
    print()

    for label, script_path, args in pipeline:

        stage_summary: dict[str, Any] = {
            "label": label,
            "script": relative_path(script_path),
            "args": args,
            "started_at_utc": utc_timestamp(),
            "finished_at_utc": None,
            "exit_code": None,
            "status": "running",
            "stdout": "",
            "stderr": "",
        }

        if not script_path.is_file():
            print_error(f"Stage script missing: {relative_path(script_path)}")
            LOGGER.error("Model Setup stage script missing: %s", relative_path(script_path))

            stage_summary["finished_at_utc"] = utc_timestamp()
            stage_summary["exit_code"] = 1
            stage_summary["status"] = "missing_script"

            summary["stages"].append(stage_summary)
            summary["finished_at_utc"] = utc_timestamp()
            summary["status"] = "failed"

            save_model_setup_summary(summary)
            return 1

        print_step(f"Running {label}")
        LOGGER.info("Model Setup running stage: %s", label)

        try:
            result = subprocess.run(
                [PYTHON_EXE, str(script_path), *args],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

        except KeyboardInterrupt:
            print()
            print_warning("Model Setup cancelled")
            LOGGER.warning("Model Setup cancelled")

            stage_summary["finished_at_utc"] = utc_timestamp()
            stage_summary["exit_code"] = 130
            stage_summary["status"] = "cancelled"

            summary["stages"].append(stage_summary)
            summary["finished_at_utc"] = utc_timestamp()
            summary["status"] = "cancelled"

            save_model_setup_summary(summary)
            return 130

        except Exception as exc:
            print_error(f"{label} failed to launch: {exc}")
            LOGGER.exception("Model Setup stage failed to launch: %s", label)

            stage_summary["finished_at_utc"] = utc_timestamp()
            stage_summary["exit_code"] = 1
            stage_summary["status"] = "failed_to_launch"
            stage_summary["stderr"] = str(exc)

            summary["stages"].append(stage_summary)
            summary["finished_at_utc"] = utc_timestamp()
            summary["status"] = "failed"

            save_model_setup_summary(summary)
            return 1

        stage_summary["finished_at_utc"] = utc_timestamp()
        stage_summary["exit_code"] = int(result.returncode or 0)
        stage_summary["stdout"] = result.stdout
        stage_summary["stderr"] = result.stderr

        if result.returncode == 0:
            stage_summary["status"] = "completed"
            print_success(f"{label} completed")
            LOGGER.info("Model Setup stage completed: %s", label)
        else:
            stage_summary["status"] = "failed"
            print_error(f"{label} failed: exit code {result.returncode}")
            LOGGER.error("Model Setup stage failed: %s | code %s", label, result.returncode)

            summary["stages"].append(stage_summary)
            summary["finished_at_utc"] = utc_timestamp()
            summary["status"] = "failed"

            save_model_setup_summary(summary)
            return int(result.returncode)

        summary["stages"].append(stage_summary)

    summary["finished_at_utc"] = utc_timestamp()
    summary["status"] = "completed"

    save_model_setup_summary(summary)

    print()
    print_success("Model Setup completed")
    LOGGER.info("Model Setup completed")

    return 0


def save_model_setup_summary(summary: dict[str, Any]) -> None:
    """Save model setup execution details as structured JSON."""

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    with MODEL_SETUP_RUN_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print_success(f"Summary saved: {relative_path(MODEL_SETUP_RUN_PATH)}")
    LOGGER.info("Model Setup summary saved: %s", relative_path(MODEL_SETUP_RUN_PATH))


# ------------------------------------------------------------
# RUNTIME PIPELINE
# ------------------------------------------------------------

def run_runtime_pipeline() -> int:
    """Run runtime data preparation followed by KB prioritisation."""

    print_workflow_header("Rank Risk")
    LOGGER.info("Rank Risk started")

    if not models_are_present():
        print_info("Run Model Setup before ranking risk")
        LOGGER.warning("Rank Risk stopped because model artefacts are missing")
        return 1

    if not runtime_scan_is_present():
        print_error("Runtime scan missing")
        print_info("Run Scan System before ranking risk")
        LOGGER.warning("Rank Risk stopped because runtime scan is missing")
        return 1

    pipeline = [
        ("Runtime Data Pipeline", DATA_PIPELINE_SCRIPT, ["--mode", "runtime"]),
        ("Risk Prioritiser", PRIORITISER_SCRIPT, []),
    ]

    for label, script_path, args in pipeline:

        if not script_path.is_file():
            print_error(f"Stage script missing: {relative_path(script_path)}")
            LOGGER.error("Rank Risk stage script missing: %s", relative_path(script_path))
            return 1

        print_step(f"Running {label}")
        LOGGER.info("Rank Risk running stage: %s", label)

        try:
            result = subprocess.run(
                [PYTHON_EXE, str(script_path), *args],
                cwd=ROOT_DIR,
                check=False,
            )

        except KeyboardInterrupt:
            print()
            print_warning("Rank Risk cancelled")
            LOGGER.warning("Rank Risk cancelled")
            return 130

        except Exception as exc:
            print_error(f"{label} failed to launch: {exc}")
            LOGGER.exception("Rank Risk stage failed to launch: %s", label)
            return 1

        if result.returncode != 0:
            print_error(f"{label} failed: exit code {result.returncode}")
            LOGGER.error("Rank Risk stage failed: %s | code %s", label, result.returncode)
            return int(result.returncode)

        LOGGER.info("Rank Risk stage completed: %s", label)

    print()
    print_success("Rank Risk completed")
    LOGGER.info("Rank Risk completed")

    return 0


# ------------------------------------------------------------
# MENU
# ------------------------------------------------------------

def print_menu() -> None:
    """Print the interactive operator menu."""

    print_menu_header()
    print("1) Scan System")
    print("2) Rank Risk")
    print("3) Download Update")
    print("4) Install Update")
    print("5) Clear Artefacts")
    print("6) Model Setup")
    print("7) Exit")
    print()
    print("=" * 60)
    print()


def read_choice() -> str:
    """Read a non-empty menu choice from stdin."""

    while True:
        try:
            choice = input("Select an option: ").strip()

        except (KeyboardInterrupt, EOFError):
            print()
            print_warning("WinShield+ cancelled")
            LOGGER.warning("WinShield+ cancelled at menu prompt")
            return "7"

        if choice:
            return choice


# ------------------------------------------------------------
# MAIN LOOP
# ------------------------------------------------------------

def main() -> int:
    """Run the interactive WinShield+ menu."""

    LOGGER.info("WinShield+ started")

    if not prepare_environment():
        LOGGER.error("Runtime environment preparation failed")
        return 1

    while True:

        print_menu()
        choice = read_choice()
        LOGGER.info("Menu option selected: %s", choice)

        if choice == "7":
            print()
            print_success("Exiting WinShield+")
            LOGGER.info("WinShield+ exited")
            return 0

        if choice == "2":
            return_code = run_runtime_pipeline()
            LOGGER.info("Rank Risk exited with code %s", return_code)

            if return_code != 0:
                print_warning(f"Rank Risk exited: code {return_code}")
            continue

        if choice == "6":
            return_code = run_model_setup()
            LOGGER.info("Model Setup exited with code %s", return_code)

            if return_code != 0:
                print_warning(f"Model Setup exited: code {return_code}")
            continue

        if choice in STAGES:
            label, script_path = STAGES[choice]
            return_code = run_stage(label, script_path)
            LOGGER.info("%s exited with code %s", label, return_code)

            if return_code != 0:
                print_warning(f"{label} exited: code {return_code}")
            continue

        print()
        print_warning("Invalid selection")
        LOGGER.warning("Invalid menu selection: %s", choice)
        print()


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())