import os
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib


# ------------------------------------------------------------
# MODE
# ------------------------------------------------------------

parser = argparse.ArgumentParser()
parser.add_argument("--mode", default="training", choices=["training", "runtime"])
args = parser.parse_args()


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
OUTPUT_DIR = os.path.join(BASE_DIR, "results", "eda")

os.makedirs(OUTPUT_DIR, exist_ok=True)

if args.mode == "runtime":
    INPUT_CSV = os.path.join(DATA_DIR, "runtime", "validated_runtime.csv")
else:
    INPUT_CSV = os.path.join(DATA_DIR, "dataset", "validated_dataset.csv")


# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

print("\n=== LOAD DATA ===\n")

df = pd.read_csv(INPUT_CSV)

print("Dataset shape:", df.shape)
print("\nColumns:\n", df.columns.tolist())
print("\nMissing values:\n", df.isnull().sum())


# ------------------------------------------------------------
# STEP 1 — PRIORITY DISTRIBUTION
# ------------------------------------------------------------

if "priority_label" in df.columns:
    print("\n=== STEP 1: Priority Distribution ===")

    counts = df["priority_label"].value_counts()
    print(counts)

    plt.figure()
    counts.plot(kind="bar")
    plt.title("Priority Label Distribution")
    plt.xlabel("Priority")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "priority_distribution.png"))
    plt.close()


# ------------------------------------------------------------
# STEP 2 — RISK SCORE DISTRIBUTION
# ------------------------------------------------------------

if "risk_score" in df.columns:
    print("\n=== STEP 2: Risk Score Distribution ===")
    print(df["risk_score"].describe())

    plt.figure()
    sns.histplot(df["risk_score"], bins=30)
    plt.title("Risk Score Distribution")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "risk_distribution.png"))
    plt.close()


# ------------------------------------------------------------
# STEP 3 — LABEL vs RISK (VERY IMPORTANT)
# ------------------------------------------------------------

if "priority_label" in df.columns and "risk_score" in df.columns:
    print("\n=== STEP 3: Risk Score by Priority Label ===")

    print(df.groupby("priority_label")["risk_score"].describe())

    plt.figure()
    sns.boxplot(x=df["priority_label"], y=df["risk_score"])
    plt.title("Risk Score by Priority Label")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "label_vs_risk.png"))
    plt.close()


# ------------------------------------------------------------
# STEP 4 — CVSS vs RISK
# ------------------------------------------------------------

if "cvss_score" in df.columns and "risk_score" in df.columns:
    print("\n=== STEP 4: CVSS vs Risk Score ===")

    corr = df[["cvss_score", "risk_score"]].corr()
    print(corr)

    plt.figure()
    sns.scatterplot(x=df["cvss_score"], y=df["risk_score"])
    plt.title("CVSS vs Risk Score")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "cvss_vs_risk.png"))
    plt.close()


# ------------------------------------------------------------
# STEP 5 — CORRELATION WITH TARGET (USEFUL)
# ------------------------------------------------------------

if "risk_score" in df.columns:
    print("\n=== STEP 5: Feature Correlation with Risk Score ===")

    numeric_df = df.select_dtypes(include=["int64", "float64"])

    corr = numeric_df.corr()["risk_score"].sort_values(ascending=False)
    print(corr)


# ------------------------------------------------------------
# STEP 6 — FEATURE IMPORTANCE (MODEL)
# ------------------------------------------------------------

print("\n=== STEP 6: Model Feature Importance ===")

try:
    reg = joblib.load(os.path.join(MODELS_DIR, "regressor.joblib"))

    feature_cols = df.drop(columns=["risk_score", "priority_label"], errors="ignore").columns

    importance_df = pd.DataFrame({
        "feature": feature_cols,
        "importance": reg.feature_importances_
    }).sort_values(by="importance", ascending=False)

    print(importance_df.head(10))

    plt.figure()
    sns.barplot(x="importance", y="feature", data=importance_df.head(10))
    plt.title("Top 10 Feature Importances")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "feature_importance.png"))
    plt.close()

except Exception as e:
    print("[!] Feature importance skipped:", e)


# ------------------------------------------------------------
# STEP 7 — CLUSTER ANALYSIS (CRITICAL)
# ------------------------------------------------------------

print("\n=== STEP 7: Clustering Analysis ===")

try:
    clusterer = joblib.load(os.path.join(MODELS_DIR, "clusterer.joblib"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "cluster_scaler.joblib"))

    X = df.select_dtypes(include=["int64", "float64"]).drop(
        columns=["risk_score"], errors="ignore"
    )

    X_scaled = scaler.transform(X)

    df["cluster"] = clusterer.predict(X_scaled)

    print("\nCluster counts:\n", df["cluster"].value_counts())

    if "risk_score" in df.columns:
        print("\nCluster vs Risk:\n", df.groupby("cluster")["risk_score"].mean())

    if "priority_label" in df.columns:
        print("\nCluster vs Priority:\n", pd.crosstab(df["cluster"], df["priority_label"]))

except Exception as e:
    print("[!] Clustering skipped:", e)


# ------------------------------------------------------------
# DONE
# ------------------------------------------------------------

print("\n=== EDA COMPLETE ===")
print(f"Plots saved to: {OUTPUT_DIR}")