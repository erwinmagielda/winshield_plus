"""
WinShield+ model pipeline.

Runs the model training workflow:
1. Train the regression model.
2. Train the classification model.
3. Train the clustering model.

Requires data/dataset/validated_dataset.csv to already exist.
Exports a model pipeline summary to results/model_pipeline_summary.json.
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


from utils.winshield_banner import (
    print_error,
    print_info,
    print_section,
    print_step,
    print_success,
    print_warning,
)
from utils.winshield_paths import (
    ensure_directory,
    get_dataset_dir,
    get_model_pipeline_summary_path,
    get_models_dir,
    get_results_dir,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent

DATASET_DIR = get_dataset_dir()
RESULTS_DIR = get_results_dir()
MODELS_DIR = get_models_dir()

VALIDATED_DATASET_PATH = DATASET_DIR / "validated_dataset.csv"

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
# DISPLAY AND SUMMARY HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def print_pipeline_header() -> None:
    """Print the model pipeline header without extra trailing spacing."""

    print()
    print("Model Pipeline")
    print("=" * 60)


def prepare_pipeline_directories() -> None:
    """Ensure model pipeline output directories exist."""

    ensure_directory(RESULTS_DIR)
    ensure_directory(MODELS_DIR)


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

    ensure_directory(RESULTS_DIR)

    with SUMMARY_PATH.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print_success(f"Summary saved: {relative_path(SUMMARY_PATH)}")


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
# OUTPUT PARSING
# ------------------------------------------------------------

def extract_metric(output: str, label: str) -> float | None:
    """Extract a numeric metric from training script output."""

    pattern = rf"\[\+\]\s+{re.escape(label)}:\s+([-+]?\d+(?:\.\d+)?)"
    match = re.search(pattern, output)

    if not match:
        return None

    return float(match.group(1))


def extract_int_metric(output: str, label: str) -> int | None:
    """Extract an integer metric from training script output."""

    pattern = rf"\[\+\]\s+{re.escape(label)}:\s+(\d+)"
    match = re.search(pattern, output)

    if not match:
        return None

    return int(match.group(1))


def extract_saved_paths(output: str) -> list[str]:
    """Extract saved artefact paths from training script output."""

    paths: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped.startswith("[+]"):
            continue

        if "saved:" not in stripped.lower():
            continue

        _, _, path = stripped.partition(":")
        path = path.strip()

        if path:
            paths.append(path)

    return paths


def extract_key_lines(output: str) -> list[str]:
    """Extract useful success and info lines from training output."""

    useful_prefixes = ("[+]", "[i]")
    useful_terms = (
        "MAE:",
        "RMSE:",
        "R2:",
        "Accuracy:",
        "Weighted F1:",
        "Clusters created:",
        "Elbow chart saved:",
        "Cluster chart saved:",
        "Model saved:",
        "Preprocessor saved:",
        "Feature list saved:",
    )

    key_lines: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped.startswith(useful_prefixes):
            continue

        if any(term in stripped for term in useful_terms):
            key_lines.append(stripped)

    return key_lines


def build_evaluation_summary(stage_key: str, output: str) -> dict[str, Any]:
    """Build structured evaluation values from a training script output."""

    if stage_key == "regression":
        return {
            "metrics": {
                "mae": extract_metric(output, "MAE"),
                "rmse": extract_metric(output, "RMSE"),
                "r2": extract_metric(output, "R2"),
            },
            "saved_paths": extract_saved_paths(output),
        }

    if stage_key == "classification":
        return {
            "metrics": {
                "accuracy": extract_metric(output, "Accuracy"),
                "weighted_f1": extract_metric(output, "Weighted F1"),
            },
            "saved_paths": extract_saved_paths(output),
        }

    if stage_key == "clustering":
        return {
            "metrics": {
                "clusters_created": extract_int_metric(output, "Clusters created"),
            },
            "saved_paths": extract_saved_paths(output),
        }

    return {
        "metrics": {},
        "saved_paths": extract_saved_paths(output),
    }


def print_stage_evaluation(stage_key: str, evaluation: dict[str, Any]) -> None:
    """Print concise model evaluation details for one stage."""

    metrics = evaluation.get("metrics", {})
    saved_paths = evaluation.get("saved_paths", [])

    if stage_key == "regression":
        if metrics.get("mae") is not None:
            print_success(f"MAE: {metrics['mae']:.4f}")
        if metrics.get("rmse") is not None:
            print_success(f"RMSE: {metrics['rmse']:.4f}")
        if metrics.get("r2") is not None:
            print_success(f"R2: {metrics['r2']:.4f}")

    elif stage_key == "classification":
        if metrics.get("accuracy") is not None:
            print_success(f"Accuracy: {metrics['accuracy']:.4f}")
        if metrics.get("weighted_f1") is not None:
            print_success(f"Weighted F1: {metrics['weighted_f1']:.4f}")

    elif stage_key == "clustering":
        if metrics.get("clusters_created") is not None:
            print_success(f"Clusters created: {metrics['clusters_created']}")

    for path in saved_paths:
        print_success(f"Saved: {path}")


# ------------------------------------------------------------
# STAGE EXECUTION
# ------------------------------------------------------------

def run_stage(
    stage_key: str,
    label: str,
    script_path: Path,
    args: list[str],
) -> dict[str, Any]:
    """Run a pipeline stage and return a stage summary."""

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
        "key_output_lines": [],
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

    print_step(f"Running {script_path.name}")

    try:
        result = subprocess.run(
            [PYTHON_EXE, str(script_path), *args],
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
        print_warning("Model Pipeline cancelled")

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

    if stage_summary["stderr"]:
        print_warning(f"{label} produced stderr output")
        for line in stage_summary["stderr"].splitlines()[:8]:
            print(f"    {line}")

    stage_summary["evaluation"] = build_evaluation_summary(
        stage_key=stage_key,
        output=stage_summary["stdout"],
    )

    stage_summary["key_output_lines"] = extract_key_lines(stage_summary["stdout"])

    if stage_summary["exit_code"] == 0:
        stage_summary["status"] = "completed"
        print_stage_evaluation(stage_key, stage_summary["evaluation"])
        print_success(f"{label} completed")
    else:
        stage_summary["status"] = "failed"
        print_error(f"{label} failed: exit code {stage_summary['exit_code']}")

        if stage_summary["stdout"]:
            print_info("Last stdout lines:")
            for line in stage_summary["stdout"].splitlines()[-8:]:
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
    print_step(f"Checking input: {relative_path(VALIDATED_DATASET_PATH)}")

    inputs_valid, error_message = validate_required_inputs()

    if not inputs_valid:
        print_error(str(error_message))

        summary["status"] = "failed"
        summary["error"] = error_message
        summary["artefacts"] = build_artefact_summary()
        save_model_pipeline_summary(summary)

        return 1

    print_success("Input dataset ready")

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
            save_model_pipeline_summary(summary)

            print()
            print_error("Model Pipeline stopped")
            return int(stage_summary["exit_code"])

    summary["status"] = "completed"
    summary["artefacts"] = build_artefact_summary()

    print_section("Artefacts")

    for group, artefacts in summary["artefacts"].items():
        existing_count = sum(1 for artefact in artefacts if artefact["exists"])
        print_success(f"{group.title()}: {existing_count}/{len(artefacts)} ready")

        for artefact in artefacts:
            status = "ready" if artefact["exists"] else "missing"
            print(f"    - {artefact['path']} [{status}]")

    print_section("Summary")
    save_model_pipeline_summary(summary)

    print()
    print_success("Model Pipeline completed")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())