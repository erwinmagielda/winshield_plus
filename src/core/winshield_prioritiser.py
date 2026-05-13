"""
WinShield+ prioritiser.

Loads validated runtime vulnerability data, applies trained regression,
classification, and clustering models, then ranks missing KBs by predicted risk.
Exports ranked prioritisation results for review or downstream automation.
"""

import json
from pathlib import Path
from typing import Any

import joblib
import pandas as pd


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parents[1]

RUNTIME_DIR = ROOT_DIR / "data" / "runtime"
MODELS_DIR = ROOT_DIR / "models"
RESULTS_DIR = ROOT_DIR / "results"

RUNTIME_DATA_PATH = RUNTIME_DIR / "validated_runtime.csv"

REGRESSION_MODEL_PATH = MODELS_DIR / "regression_model.joblib"
REGRESSION_PREPROCESSOR_PATH = MODELS_DIR / "regression_preprocessor.joblib"

CLASSIFICATION_MODEL_PATH = MODELS_DIR / "classification_model.joblib"
CLASSIFICATION_PREPROCESSOR_PATH = MODELS_DIR / "classification_preprocessor.joblib"

CLUSTERING_MODEL_PATH = MODELS_DIR / "clustering_model.joblib"
CLUSTERING_PREPROCESSOR_PATH = MODELS_DIR / "clustering_preprocessor.joblib"

RESULTS_PATH = RESULTS_DIR / "ranking_results.json"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a standard prioritiser section heading."""

    print()
    print(f"--- {title} ---")


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


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
    ]

    return features.drop(columns=drop_columns)


# ------------------------------------------------------------
# MODEL INFERENCE
# ------------------------------------------------------------

def predict_priorities(runtime_data: pd.DataFrame) -> pd.DataFrame:
    """Apply trained models and attach predictions to runtime data."""

    predictions = runtime_data.copy()
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

    predictions["regression"] = regression_model.predict(regression_features)
    predictions["classification"] = classification_model.predict(classification_features)
    predictions["cluster"] = clustering_model.predict(clustering_features)

    return predictions


# ------------------------------------------------------------
# KB RANKING
# ------------------------------------------------------------

def get_kb_order(predictions: pd.DataFrame) -> pd.Index:
    """Return KB IDs ordered by highest predicted risk."""

    return (
        predictions.groupby("kb_id")["regression"]
        .max()
        .sort_values(ascending=False)
        .index
    )


def build_results(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    """Build JSON-serialisable KB ranking results."""

    output: list[dict[str, Any]] = []

    for kb_id, kb_rows in predictions.groupby("kb_id"):
        cve_rows = kb_rows.sort_values("regression", ascending=False)

        entry = {
            "kb_id": kb_id,
            "max_risk": float(cve_rows["regression"].max()),
            "classification": cve_rows["classification"].mode()[0],
            "cluster": int(cve_rows["cluster"].mode()[0]),
            "cve_count": int(len(cve_rows)),
            "cves": [],
        }

        for _, row in cve_rows.iterrows():
            entry["cves"].append(
                {
                    "cve_id": row["cve_id"],
                    "risk": float(row["regression"]),
                    "classification": row["classification"],
                    "cluster": int(row["cluster"]),
                }
            )

        output.append(entry)

    return sorted(output, key=lambda item: item["max_risk"], reverse=True)


# ------------------------------------------------------------
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_runtime_summary(runtime_data: pd.DataFrame) -> None:
    """Print concise runtime dataset summary."""

    print_section("Runtime Data")
    print(f"[+] Input: {relative_path(RUNTIME_DATA_PATH)}")
    print(f"[+] Runtime rows: {len(runtime_data)}")
    print(f"[+] Unique KBs: {runtime_data['kb_id'].nunique()}")
    print(f"[+] Unique CVEs: {runtime_data['cve_id'].nunique()}")


def print_patch_recommendation(predictions: pd.DataFrame) -> None:
    """Print aligned KB-level remediation order based on predicted risk."""

    print_section("Ranked Remediation")

    results = build_results(predictions)

    if not results:
        print("[!] No ranking results produced")
        return

    header = (
        f"{'Rank':<6} | "
        f"{'KB':<12} | "
        f"{'Risk':>7} | "
        f"{'Priority':<10} | "
        f"{'Cluster':>7} | "
        f"{'CVEs':>5}"
    )

    print(header)
    print("-" * len(header))

    for index, entry in enumerate(results, start=1):
        print(
            f"{index:<6} | "
            f"{entry['kb_id']:<12} | "
            f"{entry['max_risk']:>7.2f} | "
            f"{entry['classification']:<10} | "
            f"{entry['cluster']:>7} | "
            f"{entry['cve_count']:>5}"
        )


def print_kb_breakdown(predictions: pd.DataFrame) -> None:
    """Print aligned CVE-level prediction details grouped by ranked KB."""

    print_section("CVE Breakdown")

    sorted_predictions = predictions.sort_values("regression", ascending=False)
    kb_order = get_kb_order(sorted_predictions)

    cve_width = 18
    risk_width = 7
    priority_width = 10
    cluster_width = 7

    separator = "-" * 60

    for index, kb_id in enumerate(kb_order, start=1):
        kb_rows = sorted_predictions[sorted_predictions["kb_id"] == kb_id]

        max_risk = kb_rows["regression"].max()
        classification = kb_rows["classification"].mode()[0]
        cluster = kb_rows["cluster"].mode()[0]
        cve_count = len(kb_rows)

        if index > 1:
            print()
            print(separator)
            print()

        print(f"[+] {kb_id}")
        print(
            f"    KB risk: {max_risk:.2f} | "
            f"Priority: {classification} | "
            f"Cluster: {cluster} | "
            f"CVEs: {cve_count}"
        )
        print()

        header = (
            f"    {'CVE':<{cve_width}} | "
            f"{'Risk':>{risk_width}} | "
            f"{'Priority':<{priority_width}} | "
            f"{'Cluster':>{cluster_width}}"
        )

        print(header)
        print("    " + "-" * (len(header) - 4))

        for _, row in kb_rows.iterrows():
            print(
                f"    {row['cve_id']:<{cve_width}} | "
                f"{row['regression']:>{risk_width}.2f} | "
                f"{row['classification']:<{priority_width}} | "
                f"{row['cluster']:>{cluster_width}}"
            )


# ------------------------------------------------------------
# RESULT EXPORT
# ------------------------------------------------------------

def save_results(predictions: pd.DataFrame) -> None:
    """Save KB ranking results to the results directory."""

    output = build_results(predictions)

    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print(f"[+] Results saved: {relative_path(RESULTS_PATH)}")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> None:
    """Run the WinShield+ risk prioritisation workflow."""

    print()
    print("=" * 60)
    print("WinShield+ - Risk Prioritisation")
    print("=" * 60)

    print_section("Pre-flight")
    print("[*] Checking model artefacts")
    validate_model_artefacts()
    print("[+] Model artefacts ready")

    runtime_data = load_runtime_data()
    print_runtime_summary(runtime_data)

    print_section("Inference")
    print("[*] Applying trained models")
    predictions = predict_priorities(runtime_data)
    print("[+] Predictions generated")

    print_patch_recommendation(predictions)
    print_kb_breakdown(predictions)

    print_section("Export")
    save_results(predictions)

    print()
    print("[+] Risk Prioritisation completed")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()