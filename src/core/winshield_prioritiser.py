"""
WinShield Prioritiser

Uses the already preprocessed runtime dataset to predict
patch risk using BOTH:
- Regression model → numeric risk score
- Classification model → priority label

Displays both outputs clearly.
"""

import os
import json
import pandas as pd
import joblib


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

RUNTIME_DIR = os.path.join(ROOT_DIR, "data", "runtime")
MODELS_DIR = os.path.join(ROOT_DIR, "models")
RESULTS_DIR = os.path.join(ROOT_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

RUNTIME_FEATURES = os.path.join(RUNTIME_DIR, "preprocessed_runtime.csv")
RUNTIME_VALIDATED = os.path.join(RUNTIME_DIR, "validated_runtime.csv")

REGRESSOR_PATH = os.path.join(MODELS_DIR, "regressor.joblib")
CLASSIFIER_PATH = os.path.join(MODELS_DIR, "classifier.joblib")

RESULTS_PATH = os.path.join(RESULTS_DIR, "ranking_results.json")


# ------------------------------------------------------------
# LOAD RUNTIME DATA
# ------------------------------------------------------------

def load_runtime_data():

    if not os.path.exists(RUNTIME_FEATURES):
        raise RuntimeError("Run runtime preprocessing first.")

    features = pd.read_csv(RUNTIME_FEATURES)
    metadata = pd.read_csv(RUNTIME_VALIDATED)

    if len(features) != len(metadata):
        raise RuntimeError("Feature and metadata rows do not match.")

    return features, metadata


# ------------------------------------------------------------
# PREDICT (REGRESSION + CLASSIFICATION)
# ------------------------------------------------------------

def predict_risk(features, metadata):

    regressor = joblib.load(REGRESSOR_PATH)
    classifier = joblib.load(CLASSIFIER_PATH)

    expected = regressor.n_features_in_
    features = features.iloc[:, :expected]

    # --- regression ---
    reg_preds = regressor.predict(features)

    # --- classification ---
    clf_preds = classifier.predict(features)

    metadata["regression_score"] = reg_preds
    metadata["classification_label"] = clf_preds

    return metadata


# ------------------------------------------------------------
# KB ORDER (BASED ON REGRESSION)
# ------------------------------------------------------------

def get_kb_order(df):

    kb_scores = (
        df.groupby("kb_id")["regression_score"]
        .max()
        .sort_values(ascending=False)
    )

    return kb_scores.index


# ------------------------------------------------------------
# PATCH RECOMMENDATION
# ------------------------------------------------------------

def print_patch_recommendation(df):

    print("\n=== Patch Remediation Recommendation ===\n")

    kb_scores = (
        df.groupby("kb_id")["regression_score"]
        .max()
        .sort_values(ascending=False)
    )

    rank = 1

    for kb, score in kb_scores.items():

        rows = df[df["kb_id"] == kb]

        level = rows["classification_label"].mode()[0]
        cve_count = len(rows)

        print(
            f"{rank}. {kb} | "
            f"Classification: {level} | "
            f"Regression: {score:.2f} | "
            f"CVEs: {cve_count}"
        )

        rank += 1

    print("\n")


# ------------------------------------------------------------
# PRINT PRIORITISATION
# ------------------------------------------------------------

def print_kb_breakdown(df):

    print("\n=== Patch Priority ===\n")

    df_sorted = df.sort_values("regression_score", ascending=False)

    kb_order = get_kb_order(df_sorted)

    for kb in kb_order:

        kb_rows = df_sorted[df_sorted["kb_id"] == kb]

        max_risk = kb_rows["regression_score"].max()
        cve_count = len(kb_rows)

        kb_level = kb_rows["classification_label"].mode()[0]

        print(
            f"{kb} | "
            f"Classification: {kb_level} | "
            f"Max Regression: {max_risk:.2f} | "
            f"CVEs: {cve_count}"
        )

        for _, row in kb_rows.iterrows():

            print(
                f"   ├ {row['cve_id']} | "
                f"Classification: {row['classification_label']} | "
                f"Regression: {row['regression_score']:.2f}"
            )

        print()


# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

def save_results(df):

    output = []

    for kb, rows in df.groupby("kb_id"):

        max_risk = rows["regression_score"].max()

        entry = {
            "kb_id": kb,
            "max_regression": float(max_risk),
            "classification": rows["classification_label"].mode()[0],
            "cves": []
        }

        for _, r in rows.iterrows():

            entry["cves"].append({
                "cve_id": r["cve_id"],
                "regression_score": float(r["regression_score"]),
                "classification": r["classification_label"]
            })

        output.append(entry)

    output = sorted(output, key=lambda x: x["max_regression"], reverse=True)

    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Ranking results saved to: {RESULTS_PATH}")


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main():

    print("\n=== WinShield AI Prioritisation ===")

    features, metadata = load_runtime_data()

    df = predict_risk(features, metadata)

    print_kb_breakdown(df)

    print_patch_recommendation(df)

    save_results(df)

    print("[+] Vulnerability prioritisation complete.\n")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()