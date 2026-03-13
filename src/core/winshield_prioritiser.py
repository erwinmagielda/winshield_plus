"""
WinShield Prioritiser

Uses the already preprocessed runtime dataset to predict
patch risk using the trained regression model.
Displays both continuous ML risk score and priority tier.
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

MODEL_PATH = os.path.join(MODELS_DIR, "regressor.joblib")
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
# RISK CLASSIFICATION
# ------------------------------------------------------------

def classify_risk(score):

    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"


# ------------------------------------------------------------
# PREDICT RISK
# ------------------------------------------------------------

def predict_risk(features, metadata):

    model = joblib.load(MODEL_PATH)

    expected = model.n_features_in_
    features = features.iloc[:, :expected]

    predictions = model.predict(features)

    metadata["predicted_risk"] = predictions
    metadata["risk_level"] = metadata["predicted_risk"].apply(classify_risk)

    return metadata


# ------------------------------------------------------------
# KB ORDER
# ------------------------------------------------------------

def get_kb_order(df):

    kb_scores = (
        df.groupby("kb_id")["predicted_risk"]
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
        df.groupby("kb_id")["predicted_risk"]
        .max()
        .sort_values(ascending=False)
    )

    rank = 1

    for kb, score in kb_scores.items():

        rows = df[df["kb_id"] == kb]

        level = classify_risk(score)
        cve_count = len(rows)

        print(
            f"{rank}. {kb} | {level} | Risk: {score:.2f} | CVEs: {cve_count}"
        )

        rank += 1

    print("\n")


# ------------------------------------------------------------
# PRINT PRIORITISATION
# ------------------------------------------------------------

def print_kb_breakdown(df):

    print("\n=== Patch Priority ===\n")

    df_sorted = df.sort_values("predicted_risk", ascending=False)

    kb_order = get_kb_order(df_sorted)

    for kb in kb_order:

        kb_rows = df_sorted[df_sorted["kb_id"] == kb]

        max_risk = kb_rows["predicted_risk"].max()
        cve_count = len(kb_rows)

        kb_level = classify_risk(max_risk)

        print(f"{kb} | {kb_level} | Max Risk: {max_risk:.2f} | CVEs: {cve_count}")

        for _, row in kb_rows.iterrows():

            print(
                f"   ├ {row['cve_id']} | {row['risk_level']} | Risk: {row['predicted_risk']:.2f}"
            )

        print()


# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

def save_results(df):

    output = []

    for kb, rows in df.groupby("kb_id"):

        max_risk = rows["predicted_risk"].max()

        entry = {
            "kb_id": kb,
            "max_risk": float(max_risk),
            "risk_level": classify_risk(max_risk),
            "cves": []
        }

        for _, r in rows.iterrows():

            entry["cves"].append({
                "cve_id": r["cve_id"],
                "risk_score": float(r["predicted_risk"]),
                "risk_level": r["risk_level"]
            })

        output.append(entry)

    output = sorted(output, key=lambda x: x["max_risk"], reverse=True)

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