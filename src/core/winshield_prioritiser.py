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
# DATA LOADING
# ------------------------------------------------------------

def load_runtime_data() -> pd.DataFrame:
    """Load validated runtime data produced by the runtime pipeline."""

    if not RUNTIME_DATA_PATH.exists():
        raise RuntimeError("Run the runtime pipeline first.")

    return pd.read_csv(RUNTIME_DATA_PATH)


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


# ------------------------------------------------------------
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_kb_breakdown(predictions: pd.DataFrame) -> None:
    """Print CVE-level prediction details grouped by KB."""

    sorted_predictions = predictions.sort_values("regression", ascending=False)
    kb_order = get_kb_order(sorted_predictions)

    for kb_id in kb_order:
        kb_rows = sorted_predictions[sorted_predictions["kb_id"] == kb_id]

        max_risk = kb_rows["regression"].max()
        cluster = kb_rows["cluster"].mode()[0]
        classification = kb_rows["classification"].mode()[0]

        print(
            f"{kb_id} | Cluster: {cluster} | "
            f"Classification: {classification} | "
            f"Max Risk: {max_risk:.2f} | "
            f"CVEs: {len(kb_rows)}"
        )

        for _, row in kb_rows.iterrows():
            print(
                f"   ├ {row['cve_id']} | "
                f"Cluster: {row['cluster']} | "
                f"Classification: {row['classification']} | "
                f"Risk: {row['regression']:.2f}"
            )

        print()


def print_patch_recommendation(predictions: pd.DataFrame) -> None:
    """Print KB-level remediation order based on maximum predicted risk."""

    print("\n=== Patch Remediation Recommendation ===\n")

    kb_scores = (
        predictions.groupby("kb_id")["regression"]
        .max()
        .sort_values(ascending=False)
    )

    for index, (kb_id, score) in enumerate(kb_scores.items(), start=1):
        kb_rows = predictions[predictions["kb_id"] == kb_id]

        cluster = kb_rows["cluster"].mode()[0]
        classification = kb_rows["classification"].mode()[0]

        print(
            f"{index}. {kb_id} | Cluster: {cluster} | "
            f"Classification: {classification} | "
            f"Risk: {score:.2f} | "
            f"CVEs: {len(kb_rows)}"
        )

    print()


# ------------------------------------------------------------
# RESULT EXPORT
# ------------------------------------------------------------

def build_results(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    """Build JSON-serialisable KB ranking results."""

    output: list[dict[str, Any]] = []

    for kb_id, kb_rows in predictions.groupby("kb_id"):
        entry = {
            "kb_id": kb_id,
            "max_risk": float(kb_rows["regression"].max()),
            "classification": kb_rows["classification"].mode()[0],
            "cluster": int(kb_rows["cluster"].mode()[0]),
            "cves": [],
        }

        for _, row in kb_rows.iterrows():
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


def save_results(predictions: pd.DataFrame) -> None:
    """Save KB ranking results to the results directory."""

    output = build_results(predictions)

    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    print(f"[+] Results saved to {RESULTS_PATH}")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> None:
    print("\n=== WinShield+ Prioritisation ===")

    runtime_data = load_runtime_data()
    predictions = predict_priorities(runtime_data)

    print_kb_breakdown(predictions)
    print_patch_recommendation(predictions)
    save_results(predictions)

    print("[+] Done.\n")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()