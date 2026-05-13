"""
WinShield+ master runner.

Provides an operator menu for running scanner, prioritisation,
download, install, artefact cleanup, and model setup stages from
a single entry point.
"""

import subprocess
import sys
from pathlib import Path


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

MODEL_SETUP_LOG = RESULTS_DIR / "model_setup_output.log"

PYTHON_EXE = sys.executable


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
        print("[X] Required model artefacts were not found:")
        for artifact in missing_artifacts:
            print(f"  - {artifact}")

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

    if not script_path.is_file():
        print(f"[X] Stage script not found: {script_path}")
        return 1

    print()
    print(f"[*] {label}")
    print("=" * 60)

    try:
        completed = subprocess.run(
            [PYTHON_EXE, str(script_path)],
            cwd=ROOT_DIR,
            check=False,
        )

        return_code = int(completed.returncode or 0)

    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        return 130

    except Exception as exc:
        print(f"[X] Failed to launch stage: {exc}")
        return 1

    print("=" * 60)

    if return_code == 0:
        print("[+] Finished successfully\n")
    else:
        print(f"[!] Finished with exit code {return_code}\n")

    return return_code


# ------------------------------------------------------------
# MODEL SETUP PIPELINE
# ------------------------------------------------------------

def run_model_setup() -> int:
    """Run training data preparation followed by model training quietly."""

    pipeline = [
        (DATA_PIPELINE_SCRIPT, ["--mode", "training"]),
        (MODEL_PIPELINE_SCRIPT, []),
    ]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print()
    print("[*] Starting model setup pipeline")
    print("[i] Detailed output is being written to results/model_setup_output.log")
    print()

    with MODEL_SETUP_LOG.open("w", encoding="utf-8") as log_file:

        for script_path, args in pipeline:

            if not script_path.is_file():
                print(f"[X] Missing model setup script: {script_path}")
                return 1

            print(f"[*] Running {script_path.name}...")

            log_file.write(f"\n=== Running {script_path.name} ===\n")
            log_file.flush()

            try:
                result = subprocess.run(
                    [PYTHON_EXE, str(script_path), *args],
                    cwd=ROOT_DIR,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    check=False,
                )

            except KeyboardInterrupt:
                print("\n[!] Model setup cancelled by user.\n")
                return 130

            except Exception as exc:
                print(f"[X] Failed to execute model setup stage: {exc}\n")
                return 1

            if result.returncode != 0:
                print(f"[X] {script_path.name} failed.")
                print("[i] Check results/model_setup_output.log for details.\n")
                return int(result.returncode)

    print("[+] Model setup completed successfully.\n")
    return 0


# ------------------------------------------------------------
# RUNTIME PIPELINE
# ------------------------------------------------------------

def run_runtime_pipeline() -> int:
    """Run runtime data preparation followed by KB prioritisation."""

    if not models_are_present():
        print("[i] Run option 6, Model Setup, before ranking risk.\n")
        return 1

    if not runtime_scan_is_present():
        print("[X] No runtime system scan was found.")
        print("[i] Run option 1, Scan System, before ranking risk.\n")
        return 1

    pipeline = [
        (DATA_PIPELINE_SCRIPT, ["--mode", "runtime"]),
        (PRIORITISER_SCRIPT, []),
    ]

    print()
    print("[*] Starting vulnerability prioritisation pipeline")
    print(f"[*] Root directory: {ROOT_DIR}")
    print()

    for script_path, args in pipeline:

        if not script_path.is_file():
            print(f"[X] Missing pipeline script: {script_path}")
            return 1

        print(f"[*] Running {script_path.name}")

        try:
            result = subprocess.run(
                [PYTHON_EXE, str(script_path), *args],
                cwd=ROOT_DIR,
                check=False,
            )

        except KeyboardInterrupt:
            print("\n[!] Pipeline cancelled by user.\n")
            return 130

        except Exception as exc:
            print(f"[X] Failed to execute stage: {exc}\n")
            return 1

        if result.returncode != 0:
            print("[X] Pipeline stage failed.\n")
            return int(result.returncode)

    print("[+] Pipeline completed successfully.\n")
    return 0


# ------------------------------------------------------------
# MENU
# ------------------------------------------------------------

def print_menu() -> None:
    """Print the interactive operator menu."""

    print("=" * 43)
    print("                WinShield+")
    print("=" * 43)
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
            print("\n[!] Cancelled by user.")
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
            print("Exiting WinShield+.")
            return 0

        if choice == "2":
            return_code = run_runtime_pipeline()
            if return_code != 0:
                print(f"[!] Pipeline exited with code {return_code}\n")
            continue

        if choice == "6":
            return_code = run_model_setup()
            if return_code != 0:
                print(f"[!] Model setup exited with code {return_code}\n")
            continue

        if choice in STAGES:
            label, script_path = STAGES[choice]
            return_code = run_stage(label, script_path)
            if return_code != 0:
                print(f"[!] Stage exited with code {return_code}\n")
            continue

        print("[!] Invalid selection.\n")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())