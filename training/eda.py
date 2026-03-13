import os
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


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

if args.mode == "runtime":
    INPUT_CSV = os.path.join(DATA_DIR, "runtime", "validated_runtime.csv")
else:
    INPUT_CSV = os.path.join(DATA_DIR, "dataset", "validated_dataset.csv")


# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

df = pd.read_csv(INPUT_CSV)

print("Dataset shape:", df.shape)
print("\nColumn types:\n", df.dtypes)
print("\nMissing values:\n", df.isnull().sum())


# ------------------------------------------------------------
# PRIORITY DISTRIBUTION
# ------------------------------------------------------------

if "priority_label" in df.columns:

    plt.figure()
    df["priority_label"].value_counts().plot(kind="bar")
    plt.title("Priority Label Distribution")
    plt.xlabel("Priority")
    plt.ylabel("Count")
    plt.show()


# ------------------------------------------------------------
# RISK SCORE DISTRIBUTION
# ------------------------------------------------------------

if "risk_score" in df.columns:

    plt.figure()
    sns.histplot(df["risk_score"], bins=30)
    plt.title("Risk Score Distribution")
    plt.show()


# ------------------------------------------------------------
# CORRELATION MATRIX
# ------------------------------------------------------------

numeric_df = df.select_dtypes(include=["int64", "float64"])

plt.figure()
sns.heatmap(numeric_df.corr(), annot=True, fmt=".2f")
plt.title("Correlation Matrix (Numeric Features)")
plt.show()


# ------------------------------------------------------------
# CVSS VS RISK
# ------------------------------------------------------------

if "cvss_score" in df.columns and "risk_score" in df.columns:

    plt.figure()
    sns.scatterplot(x=df["cvss_score"], y=df["risk_score"])
    plt.title("CVSS vs Risk Score")
    plt.show()