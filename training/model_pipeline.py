"""
WinShield+ model pipeline.

Runs the model training workflow:
1. Train the regression model.
2. Train the classification model.
3. Train the clustering model.

Requires data/dataset/validated_dataset.csv to already exist.
Exports a model pipeline summary to results/summaries/.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import (  # noqa: E402
    print_error,
    print_info,
    print_section,
    print_step,
    print_success,
    print_warning,
)
from utils.winshield_paths import (  # noqa: E402
    ensure_directory,
    get_charts_dir,
    get_model_pipeline_summary_path,
    get_models_dir,
    get_summaries_dir,
    get_validated_dataset_path,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent

VALIDATED_DATASET_PATH = get_validated_dataset_path()
MODELS_DIR = get_models_dir()
SUMMARIES_DIR = get_summaries_dir()
CHARTS_DIR = get_charts_dir()

REGRESSION_SCRIPT = SCRIPT_DIR / "train_regression.py"
CLASSIFICATION_SCRIPT = SCRIPT_DIR / "train_classification.py"
CLUSTERING_SCRIPT = SCRIPT_DIR / "train_clustering.py"

SUMMARY_PATH = get_model_pipeline_summary_path()

PYTHON_EXE = sys.executable


# ------------------------------------------------------------
# PIPELINE STAGES
# ------------------------------------------------------------

STAGES: list[tuple[str, str, Path, list[str]]] = [
    ("regression", "Regression", REGRESSION_SCRIPT, []),
    ("classification", "Classification", CLASSIFICATION_SCRIPT, []),
    ("clustering", "Clustering", CLUSTERING_SCRIPT, []),
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
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def utc_timestamp() -> str:
    """Return UTC timestamp for summary metadata."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def print_pipeline_header() -> None:
    """Print the model pipeline header."""

    print()
    print("Model pipeline")
    print("=" * 60)


def prepare_pipeline_directories() -> None:
    """Ensure model pipeline output directories exist."""

    for directory in [MODELS_DIR, SUMMARIES_DIR, CHARTS_DIR]:
        ensure_directory(directory)


def validate_required_inputs() -> tuple[bool, str | None]:
    """Check that the validated training dataset exists before model training."""

    if not VALIDATED_DATASET_PATH.is_file():
        return (
            False,
            "Validated dataset missing. Run Data pipeline in training mode first.",
        )

    return True, None


# ------------------------------------------------------------
# OUTPUT PARSING
# ------------------------------------------------------------

def extract_float(output: str, labels: list[str]) -> float | None:
    """Extract a float metric from training output."""

    for label in labels:
        pattern = rf"{re.escape(label)}\s*:\s*([-+]?\d+(?:\.\d+)?)"
        match = re.search(pattern, output, flags=re.IGNORECASE)

        if match:
            return float(match.group(1))

    return None


def extract_int(output: str, labels: list[str]) -> int | None:
    """Extract an integer metric from training output."""

    for label in labels:
        pattern = rf"{re.escape(label)}\s*:\s*(\d+)"
        match = re.search(pattern, output, flags=re.IGNORECASE)

        if match:
            return int(match.group(1))

    return None


def extract_first_path(output: str, terms: list[str]) -> str | None:
    """Extract the first saved path matching any term."""

    for line in output.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()

        if "saved:" not in lowered:
            continue

        if not any(term.lower() in lowered for term in terms):
            continue

        _, _, path = stripped.partition(":")
        path = path.strip()

        if path:
            return path

    return None


def build_evaluation_summary(stage_key: str, output: str) -> dict[str, Any]:
    """Build structured evaluation values from training output."""

    if stage_key == "regression":
        return {
            "metrics": {
                "mae": extract_float(output, ["MAE", "Mean absolute error"]),
                "rmse": extract_float(output, ["RMSE", "Root mean squared error"]),
                "r2": extract_float(output, ["R2", "R2 score", "R-squared"]),
            },
            "model_path": extract_first_path(output, ["model saved", "regression_model"]),
        }

    if stage_key == "classification":
        return {
            "metrics": {
                "accuracy": extract_float(output, ["Accuracy"]),
                "weighted_f1": extract_float(output, ["Weighted F1", "F1 weighted"]),
            },
            "model_path": extract_first_path(output, ["model saved", "classification_model"]),
        }

    if stage_key == "clustering":
        return {
            "metrics": {
                "clusters_created": extract_int(
                    output,
                    ["Clusters created", "Clusters", "Selected clusters"],
                ),
            },
            "elbow_chart_path": extract_first_path(output, ["elbow chart", "elbow"]),
            "scatter_chart_path": extract_first_path(output, ["scatter chart", "scatter"]),
            "model_path": extract_first_path(output, ["model saved", "clustering_model"]),
        }

    return {
        "metrics": {},
        "model_path": None,
    }


# ------------------------------------------------------------
# METRIC PRINTING
# ------------------------------------------------------------

def print_metric(label: str, value: Any, decimals: int = 4) -> None:
    """Print one metric line."""

    if value is None:
        print_warning(f"{label}: not available")
        return

    if isinstance(value, int):
        print_success(f"{label}: {value}")
        return

    print_success(f"{label}: {float(value):.{decimals}f}")


def print_stage_evaluation(stage_key: str, evaluation: dict[str, Any]) -> None:
    """Print clean model evaluation details."""

    metrics = evaluation.get("metrics", {})

    if stage_key == "regression":
        print_metric("MAE", metrics.get("mae"))
        print_metric("RMSE", metrics.get("rmse"))
        print_metric("R2", metrics.get("r2"))

    elif stage_key == "classification":
        print_metric("Accuracy", metrics.get("accuracy"))
        print_metric("Weighted F1", metrics.get("weighted_f1"))

    elif stage_key == "clustering":
        print_metric("Clusters created", metrics.get("clusters_created"), decimals=0)

        elbow_chart_path = evaluation.get("elbow_chart_path")
        scatter_chart_path = evaluation.get("scatter_chart_path")

        if elbow_chart_path:
            print_success(f"Elbow chart saved: {elbow_chart_path}")

        if scatter_chart_path:
            print_success(f"Scatter chart saved: {scatter_chart_path}")

    model_path = evaluation.get("model_path")

    if model_path:
        print_success(f"Model saved: {model_path}")
    else:
        print_warning("Model path not reported by training script")


# ------------------------------------------------------------
# ARTEFACT SUMMARY
# ------------------------------------------------------------

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


def save_model_pipeline_summary(summary: dict[str, Any]) -> Path:
    """Save model pipeline summary JSON."""

    ensure_directory(SUMMARY_PATH.parent)

    with SUMMARY_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print_success(f"Summary saved: {relative_path(SUMMARY_PATH)}")

    return SUMMARY_PATH


# ------------------------------------------------------------
# STAGE EXECUTION
# ------------------------------------------------------------

def run_stage(
    stage_key: str,
    label: str,
    script_path: Path,
    args: list[str],
) -> dict[str, Any]:
    """Run a model training stage."""

    stage_summary: dict[str, Any] = {
        "key": stage_key,
        "label": label,
        "script": relative_path(script_path),
        "args": args,
        "started_at_utc": utc_timestamp(),
        "finished_at_utc": None,
        "exit_code": None,
        "status": "running",
        "evaluation": {},
        "stdout": "",
        "stderr": "",
    }

    print_section(label)

    if not script_path.is_file():
        print_error(f"Stage script missing: {relative_path(script_path)}")

        stage_summary["finished_at_utc"] = utc_timestamp()
        stage_summary["exit_code"] = 1
        stage_summary["status"] = "missing_script"

        return stage_summary

    print_step(f"Training {label.lower()} model")

    try:
        result = subprocess.run(
            [PYTHON_EXE, "-u", str(script_path), *args],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=False,
        )

        stage_summary["exit_code"] = int(result.returncode or 0)
        stage_summary["stdout"] = result.stdout
        stage_summary["stderr"] = result.stderr

    except KeyboardInterrupt:
        print()
        print_warning("Model pipeline cancelled")

        stage_summary["exit_code"] = 130
        stage_summary["status"] = "cancelled"
        stage_summary["finished_at_utc"] = utc_timestamp()

        return stage_summary

    except Exception as exc:
        print_error(f"{label} failed to launch: {exc}")

        stage_summary["exit_code"] = 1
        stage_summary["status"] = "failed_to_launch"
        stage_summary["error"] = str(exc)
        stage_summary["finished_at_utc"] = utc_timestamp()

        return stage_summary

    stage_summary["finished_at_utc"] = utc_timestamp()

    stage_summary["evaluation"] = build_evaluation_summary(
        stage_key=stage_key,
        output=stage_summary["stdout"],
    )

    if stage_summary["exit_code"] == 0:
        stage_summary["status"] = "completed"
        print_stage_evaluation(stage_key, stage_summary["evaluation"])

        if stage_summary["stderr"]:
            print_warning("Warnings captured in model pipeline summary")

    else:
        stage_summary["status"] = "failed"
        print_error(f"{label} failed: exit code {stage_summary['exit_code']}")

        if stage_summary["stderr"]:
            print_warning("Last stderr lines:")
            for line in stage_summary["stderr"].splitlines()[-5:]:
                print(f"    {line}")

        if stage_summary["stdout"]:
            print_info("Last stdout lines:")
            for line in stage_summary["stdout"].splitlines()[-5:]:
                print(f"    {line}")

    return stage_summary


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ model training pipeline."""

    prepare_pipeline_directories()
    print_pipeline_header()

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
    print_success(f"Training dataset: {relative_path(VALIDATED_DATASET_PATH)}")
    print_success(f"Models directory: {relative_path(MODELS_DIR)}")
    print_success(f"Charts directory: {relative_path(CHARTS_DIR)}")

    inputs_valid, error_message = validate_required_inputs()

    if not inputs_valid:
        print_error(str(error_message))

        summary["status"] = "failed"
        summary["error"] = error_message
        summary["artefacts"] = build_artefact_summary()

        print_section("Summary")
        save_model_pipeline_summary(summary)

        return 1

    print_success("Required inputs ready")

    for stage_key, label, script_path, args in STAGES:
        stage_summary = run_stage(
            stage_key=stage_key,
            label=label,
            script_path=script_path,
            args=args,
        )

        summary["stages"].append(stage_summary)

        if stage_summary["exit_code"] != 0:
            summary["status"] = "failed"
            summary["artefacts"] = build_artefact_summary()

            print_section("Summary")
            save_model_pipeline_summary(summary)

            print()
            print_error("Model pipeline stopped")

            return int(stage_summary["exit_code"])

    summary["status"] = "completed"
    summary["artefacts"] = build_artefact_summary()

    print_section("Summary")
    save_model_pipeline_summary(summary)

    print()
    print_success("Model pipeline completed")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())