"""
WinShield+ model pipeline.

Runs the model training workflow:
1. Train the regression model.
2. Train the classification model.
3. Train the clustering model.

Requires data/dataset/validated_dataset.csv to already exist.
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
ROOT_DIR = SCRIPT_DIR.parent

RESULTS_DIR = ROOT_DIR / "results"
MODELS_DIR = ROOT_DIR / "models"

VALIDATED_DATASET_PATH = ROOT_DIR / "data" / "dataset" / "validated_dataset.csv"

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
    ("Regression Training", REGRESSION_SCRIPT, []),
    ("Classification Training", CLASSIFICATION_SCRIPT, []),
    ("Clustering Training", CLUSTERING_SCRIPT, []),
]

EXPECTED_ARTEFACTS: dict[str, list[Path]] = {
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
# DISPLAY AND SUMMARY HELPERS
# ------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a standard model pipeline section heading."""

    print()
    print(f"--- {title} ---")


def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def build_artefact_summary() -> dict[str, Any]:
    """Summarise expected model artefacts after training."""

    artefact_summary: dict[str, Any] = {}

    for group, paths in EXPECTED_ARTEFACTS.items():
        artefact_summary[group] = []

        for path in paths:
            artefact_summary[group].append(
                {
                    "path": relative_path(path),
                    "exists": path.is_file(),
                    "size_bytes": path.stat().st_size if path.is_file() else None,
                }
            )

    return artefact_summary


def save_model_pipeline_summary(summary: dict[str, Any]) -> None:
    """Save model pipeline summary JSON."""

    with SUMMARY_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print(f"[+] Summary saved: {relative_path(SUMMARY_PATH)}")


# ------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ------------------------------------------------------------

def validate_required_inputs() -> tuple[bool, str | None]:
    """Check that the validated training dataset exists before model training."""

    if not VALIDATED_DATASET_PATH.is_file():
        return (
            False,
            "Validated dataset missing. Run Data Pipeline in training mode first.",
        )

    return True, None


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
        print(f"[X] Stage script missing: {relative_path(script_path)}")

        stage_summary["finished_at_utc"] = utc_timestamp()
        stage_summary["exit_code"] = 1
        stage_summary["status"] = "missing_script"

        return stage_summary

    print(f"[*] Running {label}")

    try:
        result = subprocess.run(
            [PYTHON_EXE, str(script_path), *args],
            cwd=ROOT_DIR,
            check=False,
        )

        stage_summary["exit_code"] = int(result.returncode or 0)

    except KeyboardInterrupt:
        print()
        print("[!] Model Pipeline cancelled")

        stage_summary["exit_code"] = 130
        stage_summary["status"] = "cancelled"
        stage_summary["finished_at_utc"] = utc_timestamp()

        return stage_summary

    except Exception as exc:
        print(f"[X] {label} failed to launch: {exc}")

        stage_summary["exit_code"] = 1
        stage_summary["status"] = "failed_to_launch"
        stage_summary["error"] = str(exc)
        stage_summary["finished_at_utc"] = utc_timestamp()

        return stage_summary

    stage_summary["finished_at_utc"] = utc_timestamp()

    if stage_summary["exit_code"] == 0:
        stage_summary["status"] = "completed"
        print(f"[+] {label} completed")
    else:
        stage_summary["status"] = "failed"
        print(f"[X] {label} failed: exit code {stage_summary['exit_code']}")

    return stage_summary


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ model training pipeline."""

    print()
    print("=" * 60)
    print("WinShield+ - Model Pipeline")
    print("=" * 60)

    summary: dict[str, Any] = {
        "pipeline": "model_pipeline",
        "timestamp_utc": utc_timestamp(),
        "status": "running",
        "input": {
            "validated_dataset": {
                "path": relative_path(VALIDATED_DATASET_PATH),
                "exists": VALIDATED_DATASET_PATH.is_file(),
                "size_bytes": (
                    VALIDATED_DATASET_PATH.stat().st_size
                    if VALIDATED_DATASET_PATH.is_file()
                    else None
                ),
            }
        },
        "stages": [],
        "artefacts": {},
    }

    print_section("Pre-flight")
    print(f"[*] Checking input: {relative_path(VALIDATED_DATASET_PATH)}")

    inputs_valid, error_message = validate_required_inputs()

    if not inputs_valid:
        print(f"[X] {error_message}")

        summary["status"] = "failed"
        summary["error"] = error_message
        summary["artefacts"] = build_artefact_summary()
        save_model_pipeline_summary(summary)

        return 1

    print("[+] Input dataset ready")

    print_section("Training")

    for label, script_path, args in STAGES:
        stage_summary = run_stage(
            label=label,
            script_path=script_path,
            args=args,
        )

        summary["stages"].append(stage_summary)

        if stage_summary["exit_code"] != 0:
            summary["status"] = "failed"
            summary["artefacts"] = build_artefact_summary()
            save_model_pipeline_summary(summary)

            print()
            print("[X] Model Pipeline stopped")
            return int(stage_summary["exit_code"])

    summary["status"] = "completed"
    summary["artefacts"] = build_artefact_summary()

    print_section("Artefacts")

    for group, artefacts in summary["artefacts"].items():
        existing_count = sum(1 for artefact in artefacts if artefact["exists"])
        print(f"[+] {group.title()}: {existing_count}/{len(artefacts)} ready")

        for artefact in artefacts:
            status = "ready" if artefact["exists"] else "missing"
            print(f"    - {artefact['path']} [{status}]")

    print_section("Summary")
    save_model_pipeline_summary(summary)

    print()
    print("[+] Model Pipeline completed")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())