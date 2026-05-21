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
    print_menu_title,
    print_step,
    print_success,
    print_warning,
    print_workflow_header,
)
from utils.winshield_logger import setup_logger
from utils.winshield_paths import (
    get_clear_artefacts_script,
    get_data_pipeline_script,
    get_downloader_script,
    get_installer_script,
    get_model_pipeline_script,
    get_model_setup_summary_path,
    get_models_dir,
    get_prioritiser_script,
    get_project_root,
    get_runtime_dir,
    get_scanner_script,
    prepare_runtime_directories,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

ROOT_DIR = get_project_root()

DATA_PIPELINE_SCRIPT = get_data_pipeline_script()
MODEL_PIPELINE_SCRIPT = get_model_pipeline_script()
CLEAR_ARTEFACTS_SCRIPT = get_clear_artefacts_script()

SCANNER_SCRIPT = get_scanner_script()
PRIORITISER_SCRIPT = get_prioritiser_script()
DOWNLOADER_SCRIPT = get_downloader_script()
INSTALLER_SCRIPT = get_installer_script()

RUNTIME_DIR = get_runtime_dir()
MODELS_DIR = get_models_dir()

MODEL_SETUP_SUMMARY_PATH = get_model_setup_summary_path()

PYTHON_EXE = sys.executable


# ------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------

LOGGER = setup_logger(name="winshield", prefix="winshield")


def close_logger() -> None:
    """Close active logger handlers so generated logs can be cleaned."""

    for handler in LOGGER.handlers[:]:
        handler.flush()
        handler.close()
        LOGGER.removeHandler(handler)


def restart_logger() -> None:
    """Restart file logging after artefact cleanup."""

    global LOGGER

    close_logger()
    LOGGER = setup_logger(name="winshield", prefix="winshield")
    LOGGER.info("WinShield+ logger restarted")


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
    """Prepare required runtime directories before the menu starts."""

    try:
        prepare_runtime_directories()
        return True

    except Exception as exc:
        print_error(f"Failed to prepare runtime directories: {exc}")
        LOGGER.exception("Runtime directory preparation failed")
        return False


# ------------------------------------------------------------
# MENU STAGES
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
    """Return True if all required trained model artefacts are present."""

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

    if not missing_artefacts:
        return True

    print_error("Required model artefacts missing")
    LOGGER.warning("Required model artefacts missing")

    for artefact in missing_artefacts:
        print(f"    - {relative_path(artefact)}")
        LOGGER.warning("Missing model artefact: %s", relative_path(artefact))

    return False


def runtime_scan_is_present() -> bool:
    """Return True if a runtime system scan is available."""

    return RUNTIME_DIR.is_dir() and any(RUNTIME_DIR.glob("scan_*.json"))


# ------------------------------------------------------------
# SCRIPT EXECUTION
# ------------------------------------------------------------

def run_python_script_live(
    label: str,
    script_path: Path,
    args: list[str] | None = None,
) -> tuple[int, str]:
    """
    Run a Python script and stream its output live to the console.

    Child modules own their operational printing. The main runner launches each
    stage, records status, and leaves detailed output to the child workflow.
    """

    if args is None:
        args = []

    output_lines: list[str] = []

    if not script_path.is_file():
        print_error(f"Stage script missing: {relative_path(script_path)}")
        LOGGER.error("Stage script missing: %s", relative_path(script_path))
        return 1, ""

    LOGGER.info(
        "Running stage: %s (%s)",
        label,
        relative_path(script_path),
    )

    try:
        process = subprocess.Popen(
            [PYTHON_EXE, "-u", str(script_path), *args],
            cwd=ROOT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if process.stdout:
            for line in process.stdout:
                print(line, end="")
                output_lines.append(line)

        return_code = process.wait()

        return int(return_code or 0), "".join(output_lines)

    except KeyboardInterrupt:
        print()
        print_warning(f"{label} cancelled")
        LOGGER.warning("%s cancelled", label)

        return 130, "".join(output_lines)

    except Exception as exc:
        print_error(f"{label} failed to launch: {exc}")
        LOGGER.exception("%s failed to launch", label)

        return 1, "".join(output_lines)


def run_single_stage(label: str, script_path: Path) -> int:
    """Run a single menu stage and return its exit code."""

    print_workflow_header(label)
    print_step(f"Starting {label}")

    return_code, _ = run_python_script_live(
        label=label,
        script_path=script_path,
    )

    if return_code == 0:
        LOGGER.info("%s completed successfully", label)
    else:
        print()
        print_error(f"{label} failed: exit code {return_code}")
        LOGGER.error("%s failed with exit code %s", label, return_code)

    return return_code


# ------------------------------------------------------------
# SUMMARY EXPORT
# ------------------------------------------------------------

def save_model_setup_summary(summary: dict[str, Any]) -> None:
    """Save model setup execution details as structured JSON."""

    MODEL_SETUP_SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)

    with MODEL_SETUP_SUMMARY_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print_success(f"Summary saved: {relative_path(MODEL_SETUP_SUMMARY_PATH)}")
    LOGGER.info(
        "Model Setup summary saved: %s",
        relative_path(MODEL_SETUP_SUMMARY_PATH),
    )


def build_stage_summary(
    label: str,
    script_path: Path,
    args: list[str],
) -> dict[str, Any]:
    """Build the initial summary object for a workflow stage."""

    return {
        "label": label,
        "script": relative_path(script_path),
        "args": args,
        "started_at_utc": utc_timestamp(),
        "finished_at_utc": None,
        "exit_code": None,
        "status": "running",
    }


# ------------------------------------------------------------
# MODEL SETUP PIPELINE
# ------------------------------------------------------------

def run_model_setup() -> int:
    """Run training data preparation followed by model training."""

    print_workflow_header("Model Setup")
    LOGGER.info("Model Setup started")

    pipeline = [
        ("Data pipeline", DATA_PIPELINE_SCRIPT, ["--mode", "training"]),
        ("Model pipeline", MODEL_PIPELINE_SCRIPT, []),
    ]

    summary: dict[str, Any] = {
        "pipeline": "model_setup",
        "started_at_utc": utc_timestamp(),
        "finished_at_utc": None,
        "status": "running",
        "stages": [],
    }

    print_info(f"Setup summary: {relative_path(MODEL_SETUP_SUMMARY_PATH)}")
    print()

    for label, script_path, args in pipeline:
        stage_summary = build_stage_summary(label, script_path, args)

        print_step(f"Running {label}")

        return_code, _ = run_python_script_live(
            label=label,
            script_path=script_path,
            args=args,
        )

        stage_summary["finished_at_utc"] = utc_timestamp()
        stage_summary["exit_code"] = return_code

        if return_code == 0:
            stage_summary["status"] = "completed"
            LOGGER.info("Model Setup stage completed: %s", label)
            summary["stages"].append(stage_summary)
            continue

        if return_code == 130:
            stage_summary["status"] = "cancelled"
            summary["status"] = "cancelled"
        else:
            stage_summary["status"] = "failed"
            summary["status"] = "failed"
            print_error(f"{label} failed: exit code {return_code}")
            LOGGER.error("Model Setup stage failed: %s | code %s", label, return_code)

        summary["stages"].append(stage_summary)
        summary["finished_at_utc"] = utc_timestamp()

        save_model_setup_summary(summary)

        return return_code

    summary["finished_at_utc"] = utc_timestamp()
    summary["status"] = "completed"

    save_model_setup_summary(summary)

    print()
    print_success("Model Setup completed")
    LOGGER.info("Model Setup completed")

    return 0


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
        ("Runtime data pipeline", DATA_PIPELINE_SCRIPT, ["--mode", "runtime"]),
        ("Risk prioritiser", PRIORITISER_SCRIPT, []),
    ]

    for label, script_path, args in pipeline:
        print_step(f"Running {label}")

        return_code, _ = run_python_script_live(
            label=label,
            script_path=script_path,
            args=args,
        )

        if return_code == 0:
            LOGGER.info("Rank Risk stage completed: %s", label)
            continue

        print_error(f"{label} failed: exit code {return_code}")
        LOGGER.error("Rank Risk stage failed: %s | code %s", label, return_code)

        return return_code

    print()
    print_success("Rank Risk completed")
    LOGGER.info("Rank Risk completed")

    return 0


# ------------------------------------------------------------
# MENU
# ------------------------------------------------------------

def print_menu() -> None:
    """Print the compact interactive operator menu."""

    print_menu_title()
    print("1) Scan System")
    print("2) Rank Risk")
    print("3) Download Update")
    print("4) Install Update")
    print("5) Clear Artefacts")
    print("6) Model Setup")
    print("7) Exit")
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
# MENU HANDLERS
# ------------------------------------------------------------

def handle_clear_artefacts(label: str, script_path: Path) -> int:
    """Run artefact cleanup while safely restarting file logging afterwards."""

    close_logger()

    return_code = run_single_stage(label, script_path)

    restart_logger()
    LOGGER.info("Clear Artefacts exited with code %s", return_code)

    return return_code


def handle_single_stage(label: str, script_path: Path) -> int:
    """Run a standard single-script menu stage."""

    return_code = run_single_stage(label, script_path)
    LOGGER.info("%s exited with code %s", label, return_code)

    return return_code


def handle_menu_choice(choice: str) -> int | None:
    """Handle one menu choice and return an exit code when exiting."""

    LOGGER.info("Menu option selected: %s", choice)

    if choice == "7":
        print()
        print_success("Exiting WinShield+")
        LOGGER.info("WinShield+ exited")
        close_logger()
        return 0

    if choice == "2":
        return_code = run_runtime_pipeline()
        LOGGER.info("Rank Risk exited with code %s", return_code)
        return None

    if choice == "6":
        return_code = run_model_setup()
        LOGGER.info("Model Setup exited with code %s", return_code)
        return None

    if choice in STAGES:
        label, script_path = STAGES[choice]

        if label == "Clear Artefacts":
            return_code = handle_clear_artefacts(label, script_path)
        else:
            return_code = handle_single_stage(label, script_path)

        LOGGER.info("%s exited with code %s", label, return_code)
        return None

    print()
    print_warning("Invalid selection")
    LOGGER.warning("Invalid menu selection: %s", choice)
    print()

    return None


# ------------------------------------------------------------
# MAIN LOOP
# ------------------------------------------------------------

def main() -> int:
    """Run the interactive WinShield+ menu."""

    LOGGER.info("WinShield+ started")

    if not prepare_environment():
        LOGGER.error("Runtime environment preparation failed")
        return 1

    print_menu_header()

    while True:
        print_menu()

        choice = read_choice()
        exit_code = handle_menu_choice(choice)

        if exit_code is not None:
            return exit_code


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())