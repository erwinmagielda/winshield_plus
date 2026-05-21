"""
WinShield+ prioritiser.

Loads validated runtime vulnerability data, applies transparent policy scoring,
then applies trained regression, classification, and clustering models as
supporting signals.

Exports ranked KB prioritisation results and generates a Markdown report.
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


from core.winshield_reporter import generate_report  # noqa: E402
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
    get_models_dir,
    get_ranking_results_path,
    get_validated_runtime_path,
)
from utils.winshield_risk import apply_risk_policy  # noqa: E402


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

RUNTIME_DATA_PATH = get_validated_runtime_path()
RESULTS_PATH = get_ranking_results_path()

MODELS_DIR = get_models_dir()

REGRESSION_MODEL_PATH = MODELS_DIR / "regression_model.joblib"
REGRESSION_PREPROCESSOR_PATH = MODELS_DIR / "regression_preprocessor.joblib"

CLASSIFICATION_MODEL_PATH = MODELS_DIR / "classification_model.joblib"
CLASSIFICATION_PREPROCESSOR_PATH = MODELS_DIR / "classification_preprocessor.joblib"

CLUSTERING_MODEL_PATH = MODELS_DIR / "clustering_model.joblib"
CLUSTERING_PREPROCESSOR_PATH = MODELS_DIR / "clustering_preprocessor.joblib"


# ------------------------------------------------------------
# CONSOLE LIMITS
# ------------------------------------------------------------

TOP_CVE_PREVIEW_LIMIT = 10


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

def get_required_model_artefacts() -> list[Path]:
    """Return required model artefact paths."""

    return [
        REGRESSION_MODEL_PATH,
        REGRESSION_PREPROCESSOR_PATH,
        CLASSIFICATION_MODEL_PATH,
        CLASSIFICATION_PREPROCESSOR_PATH,
        CLUSTERING_MODEL_PATH,
        CLUSTERING_PREPROCESSOR_PATH,
    ]


def validate_model_artefacts() -> None:
    """Check that all required trained model artefacts exist."""

    missing_artefacts = [
        artefact for artefact in get_required_model_artefacts()
        if not artefact.is_file()
    ]

    if missing_artefacts:
        missing = ", ".join(relative_path(path) for path in missing_artefacts)
        raise RuntimeError(f"Model artefacts missing: {missing}")


def load_models() -> dict[str, Any]:
    """Load trained models and preprocessors."""

    return {
        "regression_model": joblib.load(REGRESSION_MODEL_PATH),
        "regression_preprocessor": joblib.load(REGRESSION_PREPROCESSOR_PATH),
        "classification_model": joblib.load(CLASSIFICATION_MODEL_PATH),
        "classification_preprocessor": joblib.load(CLASSIFICATION_PREPROCESSOR_PATH),
        "clustering_model": joblib.load(CLUSTERING_MODEL_PATH),
        "clustering_preprocessor": joblib.load(CLUSTERING_PREPROCESSOR_PATH),
    }


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
    models = load_models()

    regression_features = models["regression_preprocessor"].transform(features)
    classification_features = models["classification_preprocessor"].transform(features)
    clustering_features = models["clustering_preprocessor"].transform(features)

    predictions["ml_risk"] = models["regression_model"].predict(regression_features)
    predictions["ml_priority"] = models["classification_model"].predict(classification_features)
    predictions["cluster"] = models["clustering_model"].predict(clustering_features)

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
    """Print runtime dataset summary."""

    print_section("Runtime data")
    print_success(f"Input: {relative_path(RUNTIME_DATA_PATH)}")
    print_success(f"Runtime rows: {len(runtime_data)}")
    print_success(f"Unique KBs: {runtime_data['kb_id'].nunique()}")
    print_success(f"Unique CVEs: {runtime_data['cve_id'].nunique()}")


def print_feature_summary(features: pd.DataFrame) -> None:
    """Print compact model feature preparation summary."""

    print_section("Feature preparation")
    print_success(f"Model feature rows: {len(features)}")
    print_success(f"Model feature columns: {len(features.columns)}")
    print_info("Policy output columns excluded from model features")


def print_policy_summary(predictions: pd.DataFrame) -> None:
    """Print risk policy summary."""

    print_section("Risk policy")
    print_info("Primary ranking: policy risk")
    print_info("Supporting signals: ML risk, ML priority, cluster")
    print_success(f"Policy risk min: {predictions['policy_risk'].min():.2f}")
    print_success(f"Policy risk max: {predictions['policy_risk'].max():.2f}")
    print_success(f"Policy risk mean: {predictions['policy_risk'].mean():.2f}")


def print_ml_summary(predictions: pd.DataFrame) -> None:
    """Print supporting ML signal summary."""

    print_section("ML signals")
    print_success(f"ML risk min: {predictions['ml_risk'].min():.2f}")
    print_success(f"ML risk max: {predictions['ml_risk'].max():.2f}")
    print_success(f"ML risk mean: {predictions['ml_risk'].mean():.2f}")

    print_info("ML priority distribution:")
    for label, count in predictions["ml_priority"].value_counts().items():
        print(f"    - {label}: {count}")

    print_info("Cluster distribution:")
    for cluster_id, count in predictions["cluster"].value_counts().sort_index().items():
        print(f"    - Cluster {cluster_id}: {count}")


def print_ranked_remediation(results: list[dict[str, Any]]) -> None:
    """Print aligned KB-level remediation order based on policy risk."""

    print_section("Ranked remediation")

    if not results:
        print_warning("No ranking results produced")
        return

    header = (
        f"{'Rank':<6} | "
        f"{'KB':<12} | "
        f"{'Policy':>7} | "
        f"{'ML risk':>7} | "
        f"{'Priority':<10} | "
        f"{'Cluster':>7} | "
        f"{'CVEs':>5} | "
        f"{'Top driver':<24}"
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


def print_top_cve_preview(results: list[dict[str, Any]]) -> None:
    """Print a compact top-CVE preview for each ranked KB."""

    print_section("CVE preview")

    if not results:
        print_warning("No CVE preview available")
        return

    for entry in results:
        cves = entry.get("cves", [])
        preview_cves = cves[:TOP_CVE_PREVIEW_LIMIT]
        hidden_count = len(cves) - len(preview_cves)

        print_success(entry["kb_id"])
        print_info(
            f"Showing top {len(preview_cves)} of {len(cves)} CVEs by policy risk"
        )

        header = (
            f"    {'CVE':<18} | "
            f"{'Policy':>7} | "
            f"{'ML risk':>7} | "
            f"{'Priority':<10} | "
            f"{'Driver':<24}"
        )

        print(header)
        print("    " + "-" * (len(header) - 4))

        for cve in preview_cves:
            print(
                f"    {cve['cve_id']:<18} | "
                f"{cve['policy_risk']:>7.2f} | "
                f"{cve['ml_risk']:>7.2f} | "
                f"{cve['policy_priority']:<10} | "
                f"{cve['top_driver']:<24}"
            )

        if hidden_count > 0:
            print_info(f"Additional CVEs hidden from terminal: {hidden_count}")
            print_info("Full CVE breakdown saved to ranking JSON and Markdown report")


# ------------------------------------------------------------
# RESULT EXPORT
# ------------------------------------------------------------

def save_results(results: list[dict[str, Any]]) -> Path:
    """Save KB ranking results to the ranking results path."""

    ensure_directory(RESULTS_PATH.parent)

    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    return RESULTS_PATH


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
        print_step("Applying policy risk logic")
        policy_data = apply_risk_policy(runtime_data)
        print_success("Policy scores generated")

        features = prepare_features(policy_data)
        print_feature_summary(features)

        print_step("Loading trained models")
        validate_model_artefacts()
        print_success("Trained models ready")

        print_step("Applying regression, classification, and clustering models")
        predictions = predict_priorities(runtime_data)
        print_success("ML supporting signals generated")

        results = build_results(predictions)

        print_policy_summary(predictions)
        print_ml_summary(predictions)
        print_ranked_remediation(results)
        print_top_cve_preview(results)

        print_section("Export")
        results_path = save_results(results)
        print_success(f"Results saved: {relative_path(results_path)}")

        report_path = generate_report()
        print_success(f"Report saved: {relative_path(report_path)}")

        print()
        print_success("Risk prioritisation completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Risk prioritisation cancelled")
        return 130

    except Exception as exc:
        print_error(f"Risk prioritisation failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())