"""
WinShield+ master runner.

Provides an operator menu for running scanner, prioritisation,
download, install, and cleanup stages from a single entry point.
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
PRIORITISER_SCRIPT = SCRIPT_DIR / "winshield_prioritiser.py"
REMOVE_RUN_SCRIPT = ROOT_DIR / "remove_run.py"

PYTHON_EXE = sys.executable


# ------------------------------------------------------------
# STAGES
# ------------------------------------------------------------

STAGES: dict[str, tuple[str, Path]] = {
    "1": ("Scan System", SCRIPT_DIR / "winshield_scanner.py"),
    "3": ("Download Update", SCRIPT_DIR / "winshield_downloader.py"),
    "4": ("Install Update", SCRIPT_DIR / "winshield_installer.py"),
    "5": ("Clean Artefacts", REMOVE_RUN_SCRIPT),
}


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
# RUNTIME PIPELINE
# ------------------------------------------------------------

def run_runtime_pipeline() -> int:
    """Run runtime data preparation followed by KB prioritisation."""

    pipeline = [
        (DATA_PIPELINE_SCRIPT, ["--mode", "runtime"]),
        (PRIORITISER_SCRIPT, []),
    ]

    print("[*] Starting vulnerability prioritisation pipeline\n")
    print(f"[*] Root directory: {ROOT_DIR}\n")

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
    print("5) Clean Artefacts")
    print("6) Exit")
    print()


def read_choice() -> str:
    """Read a non-empty menu choice from stdin."""

    while True:
        try:
            choice = input("Select an option: ").strip()

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Cancelled by user.")
            return "6"

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

        if choice == "6":
            print("Exiting WinShield+.")
            return 0

        if choice == "2":
            return_code = run_runtime_pipeline()
            if return_code != 0:
                print(f"[!] Pipeline exited with code {return_code}\n")
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