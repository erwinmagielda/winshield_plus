"""
WinShield Master

Operator entry point for the WinShield workflow.
"""

import os
import subprocess
import sys
from typing import Dict, Tuple


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.dirname(SCRIPT_DIR)
ROOT_DIR = os.path.dirname(SRC_DIR)

TRAINING_DIR = os.path.join(ROOT_DIR, "training")

FLATTEN_SCRIPT = os.path.join(TRAINING_DIR, "flatten.py")
ENRICH_SCRIPT = os.path.join(TRAINING_DIR, "enrich.py")
VALIDATE_SCRIPT = os.path.join(TRAINING_DIR, "validate.py")
PREPROCESS_SCRIPT = os.path.join(TRAINING_DIR, "preprocess.py")

PRIORITISER_SCRIPT = os.path.join(SCRIPT_DIR, "winshield_prioritiser.py")

PYTHON_EXE = sys.executable


STAGES: Dict[str, Tuple[str, str]] = {
    "1": ("Scan System", os.path.join(SCRIPT_DIR, "winshield_scanner.py")),
    "3": ("Download KB", os.path.join(SCRIPT_DIR, "winshield_downloader.py")),
    "4": ("Install KB", os.path.join(SCRIPT_DIR, "winshield_installer.py")),
}


def run_stage(label: str, path: str) -> int:

    if not os.path.isfile(path):
        print(f"[X] Stage script not found: {path}")
        return 1

    print()
    print(f"[*] {label}")
    print("=" * 60)

    try:
        completed = subprocess.run(
            [PYTHON_EXE, path],
            cwd=ROOT_DIR,
            check=False,
        )

        rc = int(completed.returncode or 0)

    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        return 130

    except Exception as exc:
        print(f"[X] Failed to launch stage: {exc}")
        return 1

    print("=" * 60)

    if rc == 0:
        print("[+] Finished successfully\n")
    else:
        print(f"[!] Finished with exit code {rc}\n")

    return rc


def run_runtime_pipeline() -> int:

    pipeline = [
        (FLATTEN_SCRIPT, ["--mode", "runtime"]),
        (ENRICH_SCRIPT, ["--mode", "runtime"]),
        (VALIDATE_SCRIPT, ["--mode", "runtime"]),
        (PREPROCESS_SCRIPT, ["--mode", "runtime"]),
        (PRIORITISER_SCRIPT, []),
    ]

    print("[*] Starting vulnerability prioritisation pipeline\n")

    for script, args in pipeline:

        if not os.path.isfile(script):
            print(f"[X] Missing pipeline script: {script}")
            return

        print(f"[*] Running {os.path.basename(script)}")

        result = subprocess.run(
            [PYTHON_EXE, script, *args],
            cwd=ROOT_DIR
        )

        if result.returncode != 0:
            print("[X] Pipeline stage failed.\n")
            return


def print_menu() -> None:

    print("=" * 43)
    print("                 WinShield")
    print("=" * 43)
    print("1) Scan System")
    print("2) Rank Risk")
    print("3) Download Update")
    print("4) Install Update")
    print("5) Exit")
    print()


def read_choice() -> str:

    while True:

        try:
            choice = input("Select an option: ").strip()

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Cancelled by user.")
            return "5"

        if choice:
            return choice


def main() -> int:

    while True:

        print_menu()

        choice = read_choice()

        if choice == "5":
            print("Exiting WinShield.")
            return 0

        if choice == "2":
            run_runtime_pipeline()
            continue

        if choice in STAGES:
            label, path = STAGES[choice]
            run_stage(label, path)
            continue

        print("[!] Invalid selection.\n")


if __name__ == "__main__":
    raise SystemExit(main())