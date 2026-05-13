"""
WinShield+ master runner.

Provides an operator menu for running scanner, prioritisation,
download, install, artefact cleanup, and model setup stages from
a single entry point.
"""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parents[1]
TRAINING_DIR = ROOT_DIR / "training"

DATA_PIPELINE_SCRIPT = TRAINING_DIR / "data_pipeline.py"
MODEL_PIPELINE_SCRIPT = TRAINING_DIR / "model_pipeline.py"
CLEAR_RUN_SCRIPT = TRAINING_DIR / "clear_run.py"

SCANNER_SCRIPT = SCRIPT_DIR / "winshield_scanner.py"
PRIORITISER_SCRIPT = SCRIPT_DIR / "winshield_prioritiser.py"
DOWNLOADER_SCRIPT = SCRIPT_DIR / "winshield_downloader.py"
INSTALLER_SCRIPT = SCRIPT_DIR / "winshield_installer.py"

RUNTIME_DIR = ROOT_DIR / "data" / "runtime"
MODELS_DIR = ROOT_DIR / "models"
RESULTS_DIR = ROOT_DIR / "results"

MODEL_SETUP_RUN_PATH = RESULTS_DIR / "model_setup_run.json"

PYTHON_EXE = sys.executable


# ------------------------------------------------------------
# DISPLAY
# ------------------------------------------------------------

BANNER = r"""
 __        ___       ____  _     _      _     _
 \ \      / (_)_ __ / ___|| |__ (_) ___| | __| |
  \ \ /\ / /| | '_ \\___ \| '_ \| |/ _ \ |/ _` |
   \ V  V / | | | | |___) | | | | |  __/ | (_| |
    \_/\_/  |_|_| |_|____/|_| |_|_|\___|_|\__,_|

        Windows Patch Risk Prioritisation
"""


def print_header(title: str) -> None:
    """Print a standard WinShield+ stage header."""

    print()
    print("=" * 60)
    print(f"WinShield+ - {title}")
    print("=" * 60)
    print()


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean console output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------
# STAGES
# ------------------------------------------------------------

STAGES: dict[str, tuple[str, Path]] = {
    "1": ("Scan System", SCANNER_SCRIPT),
    "3": ("Download Update", DOWNLOADER_SCRIPT),
    "4": ("Install Update", INSTALLER_SCRIPT),
    "5": ("Clear Artefacts", CLEAR_RUN_SCRIPT),
}


# ------------------------------------------------------------
# VALIDATION HELPERS
# ------------------------------------------------------------

def models_are_present() -> bool:
    """Return True if the required trained model artefacts are present."""

    required_artifacts = [
        MODELS_DIR / "regression_model.joblib",
        MODELS_DIR / "regression_preprocessor.joblib",
        MODELS_DIR / "classification_model.joblib",
        MODELS_DIR / "classification_preprocessor.joblib",
        MODELS_DIR / "clustering_model.joblib",
        MODELS_DIR / "clustering_preprocessor.joblib",
        MODELS_DIR / "clustering_features.joblib",
    ]

    missing_artifacts = [
        artifact for artifact in required_artifacts
        if not artifact.is_file()
    ]

    if missing_artifacts:
        print("[X] Required model artefacts missing")
        for artifact in missing_artifacts:
            print(f"    - {relative_path(artifact)}")

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

    print_header(label)

    if not script_path.is_file():
        print(f"[X] Stage script missing: {relative_path(script_path)}")
        return 1

    print(f"[*] Running {relative_path(script_path)}")

    try:
        completed = subprocess.run(
            [PYTHON_EXE, str(script_path)],
            cwd=ROOT_DIR,
            check=False,
        )

        return_code = int(completed.returncode or 0)

    except KeyboardInterrupt:
        print()
        print(f"[!] {label} cancelled")
        return 130

    except Exception as exc:
        print(f"[X] {label} failed to launch: {exc}")
        return 1

    print()

    if return_code == 0:
        print(f"[+] {label} completed")
    else:
        print(f"[X] {label} failed: exit code {return_code}")

    return return_code


# ------------------------------------------------------------
# MODEL SETUP PIPELINE
# ------------------------------------------------------------

def run_model_setup() -> int:
    """Run training data preparation followed by model training quietly."""

    print_header("Model Setup")

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

    print(f"[i] Setup details: {relative_path(MODEL_SETUP_RUN_PATH)}")
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
            print(f"[X] Stage script missing: {relative_path(script_path)}")

            stage_summary["finished_at_utc"] = utc_timestamp()
            stage_summary["exit_code"] = 1
            stage_summary["status"] = "missing_script"

            summary["stages"].append(stage_summary)
            summary["finished_at_utc"] = utc_timestamp()
            summary["status"] = "failed"

            save_model_setup_summary(summary)
            return 1

        print(f"[*] Running {label}")

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
            print("[!] Model Setup cancelled")

            stage_summary["finished_at_utc"] = utc_timestamp()
            stage_summary["exit_code"] = 130
            stage_summary["status"] = "cancelled"

            summary["stages"].append(stage_summary)
            summary["finished_at_utc"] = utc_timestamp()
            summary["status"] = "cancelled"

            save_model_setup_summary(summary)
            return 130

        except Exception as exc:
            print(f"[X] {label} failed to launch: {exc}")

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
            print(f"[+] {label} completed")
        else:
            stage_summary["status"] = "failed"
            print(f"[X] {label} failed: exit code {result.returncode}")

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
    print("[+] Model Setup completed")

    return 0


def save_model_setup_summary(summary: dict[str, Any]) -> None:
    """Save Model Setup execution details as structured JSON."""

    with MODEL_SETUP_RUN_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print(f"[+] Summary saved: {relative_path(MODEL_SETUP_RUN_PATH)}")


# ------------------------------------------------------------
# RUNTIME PIPELINE
# ------------------------------------------------------------

def run_runtime_pipeline() -> int:
    """Run runtime data preparation followed by KB prioritisation."""

    print_header("Rank Risk")

    if not models_are_present():
        print("[i] Run Model Setup before ranking risk")
        return 1

    if not runtime_scan_is_present():
        print("[X] Runtime scan missing")
        print("[i] Run Scan System before ranking risk")
        return 1

    pipeline = [
        ("Runtime Data Pipeline", DATA_PIPELINE_SCRIPT, ["--mode", "runtime"]),
        ("Risk Prioritiser", PRIORITISER_SCRIPT, []),
    ]

    for label, script_path, args in pipeline:

        if not script_path.is_file():
            print(f"[X] Stage script missing: {relative_path(script_path)}")
            return 1

        print(f"[*] Running {label}")

        try:
            result = subprocess.run(
                [PYTHON_EXE, str(script_path), *args],
                cwd=ROOT_DIR,
                check=False,
            )

        except KeyboardInterrupt:
            print()
            print("[!] Rank Risk cancelled")
            return 130

        except Exception as exc:
            print(f"[X] {label} failed to launch: {exc}")
            return 1

        if result.returncode != 0:
            print(f"[X] {label} failed: exit code {result.returncode}")
            return int(result.returncode)

        print(f"[+] {label} completed")

    print()
    print("[+] Rank Risk completed")

    return 0


# ------------------------------------------------------------
# MENU
# ------------------------------------------------------------

def print_menu() -> None:
    """Print the interactive operator menu."""

    print(BANNER)
    print("=" * 60)
    print("1) Scan System")
    print("2) Rank Risk")
    print("3) Download Update")
    print("4) Install Update")
    print("5) Clear Artefacts")
    print("6) Model Setup")
    print("7) Exit")
    print("=" * 60)
    print()


def read_choice() -> str:
    """Read a non-empty menu choice from stdin."""

    while True:
        try:
            choice = input("Select an option: ").strip()

        except (KeyboardInterrupt, EOFError):
            print()
            print("[!] WinShield+ cancelled")
            return "7"

        if choice:
            return choice


# ------------------------------------------------------------
# MAIN LOOP
# ------------------------------------------------------------

def main() -> int:
    """Run the interactive WinShield+ menu."""

    while True:

        print_menu()
        choice = read_choice()

        if choice == "7":
            print()
            print("[+] Exiting WinShield+")
            return 0

        if choice == "2":
            return_code = run_runtime_pipeline()
            if return_code != 0:
                print(f"[!] Rank Risk exited: code {return_code}")
            continue

        if choice == "6":
            return_code = run_model_setup()
            if return_code != 0:
                print(f"[!] Model Setup exited: code {return_code}")
            continue

        if choice in STAGES:
            label, script_path = STAGES[choice]
            return_code = run_stage(label, script_path)
            if return_code != 0:
                print(f"[!] {label} exited: code {return_code}")
            continue

        print()
        print("[!] Invalid selection")
        print()


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())