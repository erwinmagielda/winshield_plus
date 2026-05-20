"""
WinShield+ prioritiser.

Loads validated runtime vulnerability data, applies transparent policy scoring,
then applies trained regression, classification, and clustering models as
supporting signals.

Exports ranked KB prioritisation results for review or downstream automation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import joblib
import pandas as pd


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from core.winshield_reporter import generate_report
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
    get_models_dir,
    get_results_dir,
    get_runtime_dir,
)
from utils.winshield_risk import apply_risk_policy


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

RUNTIME_DIR = get_runtime_dir()
MODELS_DIR = get_models_dir()
RESULTS_DIR = get_results_dir()

RUNTIME_DATA_PATH = RUNTIME_DIR / "validated_runtime.csv"

REGRESSION_MODEL_PATH = MODELS_DIR / "regression_model.joblib"
REGRESSION_PREPROCESSOR_PATH = MODELS_DIR / "regression_preprocessor.joblib"

CLASSIFICATION_MODEL_PATH = MODELS_DIR / "classification_model.joblib"
CLASSIFICATION_PREPROCESSOR_PATH = MODELS_DIR / "classification_preprocessor.joblib"

CLUSTERING_MODEL_PATH = MODELS_DIR / "clustering_model.joblib"
CLUSTERING_PREPROCESSOR_PATH = MODELS_DIR / "clustering_preprocessor.joblib"

RESULTS_PATH = RESULTS_DIR / "ranking_results.json"


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def safe_mode(series: pd.Series, fallback: Any = "Unknown") -> Any:
    """Return the first mode value from a series, or fallback if unavailable."""

    mode_values = series.dropna().mode()

    if mode_values.empty:
        return fallback

    return mode_values.iloc[0]


def highest_priority(series: pd.Series) -> str:
    """Return the highest priority label present in a series."""

    priorities = set(series.dropna().astype(str))

    if "High" in priorities:
        return "High"

    if "Medium" in priorities:
        return "Medium"

    if "Low" in priorities:
        return "Low"

    return "Unknown"


def format_drivers(drivers: Any) -> str:
    """Return risk drivers as a readable string."""

    if isinstance(drivers, list):
        return ", ".join(str(driver) for driver in drivers)

    return str(drivers)


# ------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------

def load_runtime_data() -> pd.DataFrame:
    """Load validated runtime data produced by the runtime pipeline."""

    if not RUNTIME_DATA_PATH.is_file():
        raise RuntimeError("Validated runtime data missing. Run Rank Risk after Scan System.")

    return pd.read_csv(RUNTIME_DATA_PATH)


# ------------------------------------------------------------
# MODEL LOADING
# ------------------------------------------------------------

def validate_model_artefacts() -> None:
    """Check that all required trained model artefacts exist."""

    required_artefacts = [
        REGRESSION_MODEL_PATH,
        REGRESSION_PREPROCESSOR_PATH,
        CLASSIFICATION_MODEL_PATH,
        CLASSIFICATION_PREPROCESSOR_PATH,
        CLUSTERING_MODEL_PATH,
        CLUSTERING_PREPROCESSOR_PATH,
    ]

    missing_artefacts = [
        artefact for artefact in required_artefacts
        if not artefact.is_file()
    ]

    if missing_artefacts:
        missing = ", ".join(relative_path(path) for path in missing_artefacts)
        raise RuntimeError(f"Model artefacts missing: {missing}")


# ------------------------------------------------------------
# FEATURE PREPARATION
# ------------------------------------------------------------

def prepare_features(runtime_data: pd.DataFrame) -> pd.DataFrame:
    """Prepare model input features from validated runtime data."""

    features = runtime_data.copy()

    features["exploited_flag"] = features["exploitation"].apply(
        lambda value: 1 if "Exploited:Yes" in str(value) else 0
    )

    drop_columns = [
        "kb_id",
        "cve_id",
        "month",
        "published_date",
        "exploitation",
        "policy_risk",
        "policy_priority",
        "policy_drivers",
        "top_driver",
    ]

    return features.drop(columns=drop_columns, errors="ignore")


# ------------------------------------------------------------
# MODEL INFERENCE
# ------------------------------------------------------------

def predict_priorities(runtime_data: pd.DataFrame) -> pd.DataFrame:
    """Apply risk policy and trained models to runtime data."""

    predictions = apply_risk_policy(runtime_data)
    features = prepare_features(predictions)

    regression_model = joblib.load(REGRESSION_MODEL_PATH)
    regression_preprocessor = joblib.load(REGRESSION_PREPROCESSOR_PATH)

    classification_model = joblib.load(CLASSIFICATION_MODEL_PATH)
    classification_preprocessor = joblib.load(CLASSIFICATION_PREPROCESSOR_PATH)

    clustering_model = joblib.load(CLUSTERING_MODEL_PATH)
    clustering_preprocessor = joblib.load(CLUSTERING_PREPROCESSOR_PATH)

    regression_features = regression_preprocessor.transform(features)
    classification_features = classification_preprocessor.transform(features)
    clustering_features = clustering_preprocessor.transform(features)

    predictions["ml_risk"] = regression_model.predict(regression_features)
    predictions["ml_priority"] = classification_model.predict(classification_features)
    predictions["cluster"] = clustering_model.predict(clustering_features)

    return predictions


# ------------------------------------------------------------
# KB RANKING
# ------------------------------------------------------------

def get_kb_order(predictions: pd.DataFrame) -> pd.Index:
    """Return KB IDs ordered by highest policy risk."""

    return (
        predictions.groupby("kb_id")["policy_risk"]
        .max()
        .sort_values(ascending=False)
        .index
    )


def build_results(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    """Build JSON-serialisable KB ranking results."""

    output: list[dict[str, Any]] = []

    for kb_id, kb_rows in predictions.groupby("kb_id"):
        cve_rows = kb_rows.sort_values("policy_risk", ascending=False)

        top_row = cve_rows.iloc[0]

        entry = {
            "kb_id": kb_id,
            "policy_risk": float(cve_rows["policy_risk"].max()),
            "ml_risk": float(cve_rows["ml_risk"].max()),
            "policy_priority": highest_priority(cve_rows["policy_priority"]),
            "ml_priority": highest_priority(cve_rows["ml_priority"]),
            "cluster": int(safe_mode(cve_rows["cluster"], fallback=0)),
            "cve_count": int(len(cve_rows)),
            "top_driver": str(top_row.get("top_driver", "baseline CVSS exposure")),
            "review_reason": format_drivers(top_row.get("policy_drivers", [])),
            "cves": [],
        }

        for _, row in cve_rows.iterrows():
            entry["cves"].append(
                {
                    "cve_id": row["cve_id"],
                    "policy_risk": float(row["policy_risk"]),
                    "ml_risk": float(row["ml_risk"]),
                    "policy_priority": row["policy_priority"],
                    "ml_priority": row["ml_priority"],
                    "cluster": int(row["cluster"]),
                    "top_driver": row["top_driver"],
                    "drivers": format_drivers(row["policy_drivers"]),
                }
            )

        output.append(entry)

    return sorted(output, key=lambda item: item["policy_risk"], reverse=True)


# ------------------------------------------------------------
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_runtime_summary(runtime_data: pd.DataFrame) -> None:
    """Print concise runtime dataset summary."""

    print_section("Runtime Data")
    print_success(f"Input: {relative_path(RUNTIME_DATA_PATH)}")
    print_success(f"Runtime rows: {len(runtime_data)}")
    print_success(f"Unique KBs: {runtime_data['kb_id'].nunique()}")
    print_success(f"Unique CVEs: {runtime_data['cve_id'].nunique()}")


def print_policy_summary(predictions: pd.DataFrame) -> None:
    """Print concise risk policy summary."""

    print_section("Risk Policy")
    print_info("Primary ranking: policy risk")
    print_info("Supporting signals: ML risk, ML priority, cluster")
    print_success(f"Policy risk min: {predictions['policy_risk'].min():.2f}")
    print_success(f"Policy risk max: {predictions['policy_risk'].max():.2f}")
    print_success(f"Policy risk mean: {predictions['policy_risk'].mean():.2f}")


def print_patch_recommendation(predictions: pd.DataFrame) -> None:
    """Print aligned KB-level remediation order based on policy risk."""

    print_section("Ranked Remediation")

    results = build_results(predictions)

    if not results:
        print_warning("No ranking results produced")
        return

    header = (
        f"{'Rank':<6} | "
        f"{'KB':<12} | "
        f"{'Policy':>7} | "
        f"{'ML Risk':>7} | "
        f"{'Priority':<10} | "
        f"{'Cluster':>7} | "
        f"{'CVEs':>5} | "
        f"{'Top Driver':<24}"
    )

    print(header)
    print("-" * len(header))

    for index, entry in enumerate(results, start=1):
        print(
            f"{index:<6} | "
            f"{entry['kb_id']:<12} | "
            f"{entry['policy_risk']:>7.2f} | "
            f"{entry['ml_risk']:>7.2f} | "
            f"{entry['policy_priority']:<10} | "
            f"{entry['cluster']:>7} | "
            f"{entry['cve_count']:>5} | "
            f"{entry['top_driver']:<24}"
        )


def print_kb_breakdown(predictions: pd.DataFrame) -> None:
    """Print aligned CVE-level details grouped by ranked KB."""

    print_section("CVE Breakdown")

    sorted_predictions = predictions.sort_values("policy_risk", ascending=False)
    kb_order = get_kb_order(sorted_predictions)

    cve_width = 18
    policy_width = 7
    ml_width = 7
    priority_width = 10
    cluster_width = 7
    driver_width = 24

    separator = "-" * 80

    for index, kb_id in enumerate(kb_order, start=1):
        kb_rows = sorted_predictions[sorted_predictions["kb_id"] == kb_id]

        policy_risk = kb_rows["policy_risk"].max()
        ml_risk = kb_rows["ml_risk"].max()
        policy_priority = highest_priority(kb_rows["policy_priority"])
        ml_priority = highest_priority(kb_rows["ml_priority"])
        cluster = safe_mode(kb_rows["cluster"], fallback=0)
        cve_count = len(kb_rows)

        top_row = kb_rows.iloc[0]
        review_reason = format_drivers(top_row.get("policy_drivers", []))

        if index > 1:
            print()
            print(separator)
            print()

        print_success(kb_id)
        print(
            f"    KB risk: {policy_risk:.2f} | "
            f"ML risk: {ml_risk:.2f} | "
            f"Priority: {policy_priority} | "
            f"ML priority: {ml_priority} | "
            f"Cluster: {cluster} | "
            f"CVEs: {cve_count}"
        )
        print(f"    Reason: {review_reason}")
        print()

        header = (
            f"    {'CVE':<{cve_width}} | "
            f"{'Policy':>{policy_width}} | "
            f"{'ML Risk':>{ml_width}} | "
            f"{'Priority':<{priority_width}} | "
            f"{'Cluster':>{cluster_width}} | "
            f"{'Driver':<{driver_width}}"
        )

        print(header)
        print("    " + "-" * (len(header) - 4))

        for _, row in kb_rows.iterrows():
            print(
                f"    {row['cve_id']:<{cve_width}} | "
                f"{row['policy_risk']:>{policy_width}.2f} | "
                f"{row['ml_risk']:>{ml_width}.2f} | "
                f"{row['policy_priority']:<{priority_width}} | "
                f"{row['cluster']:>{cluster_width}} | "
                f"{row['top_driver']:<{driver_width}}"
            )


# ------------------------------------------------------------
# RESULT EXPORT
# ------------------------------------------------------------

def save_results(predictions: pd.DataFrame) -> None:
    """Save KB ranking results to the results directory."""

    ensure_directory(RESULTS_DIR)

    output = build_results(predictions)

    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print_success(f"Results saved: {relative_path(RESULTS_PATH)}")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ risk prioritisation workflow."""

    try:
        print_section("Pre-flight")
        print_step("Checking model artefacts")
        validate_model_artefacts()
        print_success("Model artefacts ready")

        runtime_data = load_runtime_data()
        print_runtime_summary(runtime_data)

        print_section("Inference")
        print_step("Applying risk policy and trained models")
        predictions = predict_priorities(runtime_data)
        print_success("Policy scores and predictions generated")

        print_policy_summary(predictions)
        print_patch_recommendation(predictions)
        print_kb_breakdown(predictions)

        print_section("Export")
        save_results(predictions)

        report_path = generate_report()
        print_success(f"Report saved: {relative_path(report_path)}")

        print()
        print_success("Risk Prioritisation completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Risk Prioritisation cancelled")
        return 130

    except Exception as exc:
        print_error(f"Risk Prioritisation failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())