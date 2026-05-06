"""
WinShield+ model pipeline.

Runs the full training workflow:
1. Build and validate the training dataset.
2. Train the regression model.
3. Train the classification model.
4. Train the clustering model.

This script is the main one-command entry point for rebuilding all model
artifacts used by runtime prioritisation.
"""

import subprocess
import sys
from pathlib import Path


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parents[0]

DATA_PIPELINE_SCRIPT = SCRIPT_DIR / "data_pipeline.py"
REGRESSION_SCRIPT = SCRIPT_DIR / "train_regression.py"
CLASSIFICATION_SCRIPT = SCRIPT_DIR / "train_classification.py"
CLUSTERING_SCRIPT = SCRIPT_DIR / "train_clustering.py"

PYTHON_EXE = sys.executable


# ------------------------------------------------------------
# PIPELINE STAGES
# ------------------------------------------------------------

STAGES: list[tuple[str, Path, list[str]]] = [
    (
        "Build Training Dataset",
        DATA_PIPELINE_SCRIPT,
        ["--mode", "training"],
    ),
    (
        "Train Regression Model",
        REGRESSION_SCRIPT,
        [],
    ),
    (
        "Train Classification Model",
        CLASSIFICATION_SCRIPT,
        [],
    ),
    (
        "Train Clustering Model",
        CLUSTERING_SCRIPT,
        [],
    ),
]


# ------------------------------------------------------------
# STAGE EXECUTION
# ------------------------------------------------------------

def run_stage(label: str, script_path: Path, args: list[str]) -> int:
    """Run a pipeline stage and return its exit code."""

    if not script_path.is_file():
        print(f"[X] Stage script not found: {script_path}")
        return 1

    print()
    print("=" * 70)
    print(f"[*] {label}")
    print("=" * 70)

    try:
        result = subprocess.run(
            [PYTHON_EXE, str(script_path), *args],
            cwd=ROOT_DIR,
            check=False,
        )

    except KeyboardInterrupt:
        print("\n[!] Pipeline cancelled by user.")
        return 130

    except Exception as exc:
        print(f"[X] Failed to run stage: {exc}")
        return 1

    if result.returncode != 0:
        print(f"[X] Stage failed with exit code {result.returncode}")
        return int(result.returncode)

    print(f"[+] {label} completed successfully")

    return 0


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the full WinShield+ model training pipeline."""

    print("\n=== WinShield+ Model Pipeline ===")

    for label, script_path, args in STAGES:
        return_code = run_stage(
            label=label,
            script_path=script_path,
            args=args,
        )

        if return_code != 0:
            print("\n[X] Model pipeline stopped.")
            return return_code

    print()
    print("=== Model Pipeline Complete ===")
    print("[+] Training dataset rebuilt")
    print("[+] Regression model trained")
    print("[+] Classification model trained")
    print("[+] Clustering model trained")
    print()

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())