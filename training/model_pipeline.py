"""
WinShield+ model pipeline.

Runs the full training workflow:
1. Build and validate the training dataset.
2. Train the regression model.
3. Train the classification model.
4. Train the clustering model.

Exports a model pipeline summary to results/model_pipeline_summary.json.
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
ROOT_DIR = SCRIPT_DIR.parents[0]
RESULTS_DIR = ROOT_DIR / "results"
MODELS_DIR = ROOT_DIR / "models"

DATA_PIPELINE_SCRIPT = SCRIPT_DIR / "data_pipeline.py"
REGRESSION_SCRIPT = SCRIPT_DIR / "train_regression.py"
CLASSIFICATION_SCRIPT = SCRIPT_DIR / "train_classification.py"
CLUSTERING_SCRIPT = SCRIPT_DIR / "train_clustering.py"

SUMMARY_PATH = RESULTS_DIR / "model_pipeline_summary.json"

PYTHON_EXE = sys.executable

RESULTS_DIR.mkdir(parents=True, exist_ok=True)


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

EXPECTED_ARTIFACTS: dict[str, list[Path]] = {
    "regression": [
        MODELS_DIR / "regression_model.joblib",
        MODELS_DIR / "regression_preprocessor.joblib",
    ],
    "classification": [
        MODELS_DIR / "classification_model.joblib",
        MODELS_DIR / "classification_preprocessor.joblib",
    ],
    "clustering": [
        MODELS_DIR / "clustering_model.joblib",
        MODELS_DIR / "clustering_preprocessor.joblib",
        MODELS_DIR / "clustering_features.joblib",
    ],
}


# ------------------------------------------------------------
# SUMMARY HELPERS
# ------------------------------------------------------------

def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def relative_path(path: Path) -> str:
    """Return a project-relative path for summary output."""

    return str(path.relative_to(ROOT_DIR))


def build_artifact_summary() -> dict[str, Any]:
    """Summarise expected model artifacts after training."""

    artifact_summary: dict[str, Any] = {}

    for group, paths in EXPECTED_ARTIFACTS.items():
        artifact_summary[group] = []

        for path in paths:
            artifact_summary[group].append(
                {
                    "path": relative_path(path),
                    "exists": path.is_file(),
                    "size_bytes": path.stat().st_size if path.is_file() else None,
                }
            )

    return artifact_summary


def save_model_pipeline_summary(summary: dict[str, Any]) -> None:
    """Save model pipeline summary JSON."""

    with SUMMARY_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print(f"[+] Model pipeline summary saved to {SUMMARY_PATH}")


# ------------------------------------------------------------
# STAGE EXECUTION
# ------------------------------------------------------------

def run_stage(label: str, script_path: Path, args: list[str]) -> dict[str, Any]:
    """Run a pipeline stage and return a stage summary."""

    stage_summary: dict[str, Any] = {
        "label": label,
        "script": relative_path(script_path),
        "args": args,
        "started_at_utc": utc_timestamp(),
        "finished_at_utc": None,
        "exit_code": None,
        "status": "running",
    }

    if not script_path.is_file():
        print(f"[X] Stage script not found: {script_path}")

        stage_summary["finished_at_utc"] = utc_timestamp()
        stage_summary["exit_code"] = 1
        stage_summary["status"] = "missing_script"

        return stage_summary

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

        stage_summary["exit_code"] = int(result.returncode or 0)

    except KeyboardInterrupt:
        print("\n[!] Pipeline cancelled by user.")

        stage_summary["exit_code"] = 130
        stage_summary["status"] = "cancelled"
        stage_summary["finished_at_utc"] = utc_timestamp()

        return stage_summary

    except Exception as exc:
        print(f"[X] Failed to run stage: {exc}")

        stage_summary["exit_code"] = 1
        stage_summary["status"] = "failed_to_launch"
        stage_summary["error"] = str(exc)
        stage_summary["finished_at_utc"] = utc_timestamp()

        return stage_summary

    stage_summary["finished_at_utc"] = utc_timestamp()

    if stage_summary["exit_code"] == 0:
        stage_summary["status"] = "completed"
        print(f"[+] {label} completed successfully")
    else:
        stage_summary["status"] = "failed"
        print(f"[X] Stage failed with exit code {stage_summary['exit_code']}")

    return stage_summary


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the full WinShield+ model training pipeline."""

    print("\n=== WinShield+ Model Pipeline ===")

    summary: dict[str, Any] = {
        "pipeline": "model_pipeline",
        "timestamp_utc": utc_timestamp(),
        "status": "running",
        "stages": [],
        "artifacts": {},
    }

    final_exit_code = 0

    for label, script_path, args in STAGES:
        stage_summary = run_stage(
            label=label,
            script_path=script_path,
            args=args,
        )

        summary["stages"].append(stage_summary)

        if stage_summary["exit_code"] != 0:
            final_exit_code = int(stage_summary["exit_code"])
            summary["status"] = "failed"
            summary["artifacts"] = build_artifact_summary()
            save_model_pipeline_summary(summary)

            print("\n[X] Model pipeline stopped.")
            return final_exit_code

    summary["status"] = "completed"
    summary["artifacts"] = build_artifact_summary()
    save_model_pipeline_summary(summary)

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