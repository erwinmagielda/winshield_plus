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

RUNTIME_DATA = os.path.join(RUNTIME_DIR, "validated_runtime.csv")

REGRESSION_MODEL = os.path.join(MODELS_DIR, "regression_model.joblib")
CLASSIFICATION_MODEL = os.path.join(MODELS_DIR, "classification_model.joblib")
CLUSTERING_MODEL = os.path.join(MODELS_DIR, "clustering_model.joblib")
CLUSTERING_PREPROCESSOR = os.path.join(MODELS_DIR, "clustering_preprocessor.joblib")

RESULTS_PATH = os.path.join(RESULTS_DIR, "ranking_results.json")


# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

def load_runtime_data():

    if not os.path.exists(RUNTIME_DATA):
        raise RuntimeError("Run runtime pipeline first.")

    df = pd.read_csv(RUNTIME_DATA)

    return df


# ------------------------------------------------------------
# PREPARE FEATURES
# ------------------------------------------------------------

def prepare_features(df):

    drop_cols = [
        "kb_id",
        "cve_id",
        "month",
        "published_date",
        "exploitation"
    ]

    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    return X


# ------------------------------------------------------------
# PREDICT
# ------------------------------------------------------------

def predict(df):

    X = prepare_features(df)

    reg_model = joblib.load(REGRESSION_MODEL)
    clf_model = joblib.load(CLASSIFICATION_MODEL)
    cluster_model = joblib.load(CLUSTERING_MODEL)
    cluster_preprocessor = joblib.load(CLUSTERING_PREPROCESSOR)

    # regression
    reg_preds = reg_model.predict(X)

    # classification
    clf_preds = clf_model.predict(X)

    # clustering (needs preprocessing!)
    X_cluster = cluster_preprocessor.transform(X)
    clusters = cluster_model.predict(X_cluster)

    df["regression"] = reg_preds
    df["classification"] = clf_preds
    df["cluster"] = clusters

    return df


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
            f"Risk: {score:.2f} | "
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
            "max_risk": float(rows["regression"].max()),
            "classification": rows["classification"].mode()[0],
            "cluster": int(rows["cluster"].mode()[0]),
            "cves": []
        }

        for _, r in rows.iterrows():
            entry["cves"].append({
                "cve_id": r["cve_id"],
                "risk": float(r["regression"]),
                "classification": r["classification"],
                "cluster": int(r["cluster"])
            })

        output.append(entry)

    output = sorted(output, key=lambda x: x["max_risk"], reverse=True)

    with open(RESULTS_PATH, "w") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Results saved to {RESULTS_PATH}")


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main():

    print("\n=== WinShield AI Prioritisation ===")

    df = load_runtime_data()

    df = predict(df)

    print_kb_breakdown(df)
    print_patch_recommendation(df)
    save_results(df)

    print("[+] Done.\n")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()