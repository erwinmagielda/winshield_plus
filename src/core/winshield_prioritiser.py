"""
WinShield Prioritiser

Uses runtime data + trained models:
- Regression → ranking
- Classification → label
- Clustering → behavioural grouping
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
CLUSTER_PATH = os.path.join(MODELS_DIR, "clusterer.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "cluster_scaler.joblib")

RESULTS_PATH = os.path.join(RESULTS_DIR, "ranking_results.json")


# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

def load_runtime_data():

    if not os.path.exists(RUNTIME_FEATURES):
        raise RuntimeError("Run preprocess first.")

    features = pd.read_csv(RUNTIME_FEATURES)
    metadata = pd.read_csv(RUNTIME_VALIDATED)

    if len(features) != len(metadata):
        raise RuntimeError("Feature and metadata mismatch.")

    return features, metadata


# ------------------------------------------------------------
# PREDICT
# ------------------------------------------------------------

def predict(features, metadata):

    regressor = joblib.load(REGRESSOR_PATH)
    classifier = joblib.load(CLASSIFIER_PATH)
    clusterer = joblib.load(CLUSTER_PATH)
    scaler = joblib.load(SCALER_PATH)

    # ensure correct feature count
    features = features.iloc[:, :regressor.n_features_in_]

    # regression
    reg_preds = regressor.predict(features)

    # classification
    clf_preds = classifier.predict(features)

    # clustering (scaled!)
    scaled = scaler.transform(features)
    clusters = clusterer.predict(scaled)

    metadata["regression"] = reg_preds
    metadata["classification"] = clf_preds
    metadata["cluster"] = clusters

    return metadata


# ------------------------------------------------------------
# ORDER KBs
# ------------------------------------------------------------

def get_kb_order(df):

    return (
        df.groupby("kb_id")["regression"]
        .max()
        .sort_values(ascending=False)
        .index
    )


# ------------------------------------------------------------
# PRINT PRIORITY
# ------------------------------------------------------------

def print_kb_breakdown(df):

    print("\n=== Patch Priority ===\n")

    df_sorted = df.sort_values("regression", ascending=False)
    kb_order = get_kb_order(df_sorted)

    for kb in kb_order:

        kb_rows = df_sorted[df_sorted["kb_id"] == kb]

        max_risk = kb_rows["regression"].max()
        cluster = kb_rows["cluster"].mode()[0]
        label = kb_rows["classification"].mode()[0]

        print(
            f"{kb} | Cluster: {cluster} | "
            f"Classification: {label} | "
            f"Max Regression: {max_risk:.2f} | "
            f"CVEs: {len(kb_rows)}"
        )

        for _, row in kb_rows.iterrows():
            print(
                f"   ├ {row['cve_id']} | "
                f"Cluster: {row['cluster']} | "
                f"Classification: {row['classification']} | "
                f"Regression: {row['regression']:.2f}"
            )

        print()


# ------------------------------------------------------------
# PATCH RECOMMENDATION
# ------------------------------------------------------------

def print_patch_recommendation(df):

    print("\n=== Patch Remediation Recommendation ===\n")

    kb_scores = (
        df.groupby("kb_id")["regression"]
        .max()
        .sort_values(ascending=False)
    )

    for i, (kb, score) in enumerate(kb_scores.items(), start=1):

        rows = df[df["kb_id"] == kb]

        cluster = rows["cluster"].mode()[0]
        label = rows["classification"].mode()[0]

        print(
            f"{i}. {kb} | Cluster: {cluster} | "
            f"Classification: {label} | "
            f"Regression: {score:.2f} | "
            f"CVEs: {len(rows)}"
        )

    print()


# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

def save_results(df):

    output = []

    for kb, rows in df.groupby("kb_id"):

        entry = {
            "kb_id": kb,
            "max_regression": float(rows["regression"].max()),
            "classification": rows["classification"].mode()[0],
            "cluster": int(rows["cluster"].mode()[0]),
            "cves": []
        }

        for _, r in rows.iterrows():
            entry["cves"].append({
                "cve_id": r["cve_id"],
                "regression": float(r["regression"]),
                "classification": r["classification"],
                "cluster": int(r["cluster"])
            })

        output.append(entry)

    output = sorted(output, key=lambda x: x["max_regression"], reverse=True)

    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Results saved → {RESULTS_PATH}")


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main():

    print("\n=== WinShield AI Prioritisation ===")

    features, metadata = load_runtime_data()

    df = predict(features, metadata)

    print_kb_breakdown(df)
    print_patch_recommendation(df)
    save_results(df)

    print("[+] Done.\n")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()