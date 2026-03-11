"""
WinShield Prioritiser

Uses the already preprocessed runtime dataset to predict
patch risk using the trained regression model.
"""

import os
import pandas as pd
import joblib


# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

RUNTIME_DIR = os.path.join(ROOT_DIR, "data", "runtime")
MODELS_DIR = os.path.join(ROOT_DIR, "models")

RUNTIME_FEATURES = os.path.join(RUNTIME_DIR, "preprocessed_runtime.csv")
RUNTIME_VALIDATED = os.path.join(RUNTIME_DIR, "validated_runtime.csv")

MODEL_PATH = os.path.join(MODELS_DIR, "regressor.joblib")


# ------------------------------------------------------------
# Load runtime datasets
# ------------------------------------------------------------

def load_runtime_data():

    if not os.path.exists(RUNTIME_FEATURES):
        raise RuntimeError("Run winshield_runtime.py first.")

    features = pd.read_csv(RUNTIME_FEATURES)
    metadata = pd.read_csv(RUNTIME_VALIDATED)

    if len(features) != len(metadata):
        raise RuntimeError("Feature and metadata rows do not match.")

    return features, metadata


# ------------------------------------------------------------
# Predict risk
# ------------------------------------------------------------

def predict_risk(features, metadata):

    print("Loading regression model...")

    model = joblib.load(MODEL_PATH)

    predictions = model.predict(features)

    metadata["predicted_risk"] = predictions

    return metadata


# ------------------------------------------------------------
# Aggregate KB priority
# ------------------------------------------------------------

def get_kb_order(df):

    kb_scores = (
        df.groupby("kb_id")["predicted_risk"]
        .max()
        .sort_values(ascending=False)
    )

    return kb_scores.index


# ------------------------------------------------------------
# Print prioritisation
# ------------------------------------------------------------

def print_kb_breakdown(df):

    print("\n=== Patch Priority ===\n")

    df_sorted = df.sort_values("predicted_risk", ascending=False)

    kb_order = get_kb_order(df_sorted)

    for kb in kb_order:

        kb_rows = df_sorted[df_sorted["kb_id"] == kb]

        max_risk = kb_rows["predicted_risk"].max()
        cve_count = len(kb_rows)

        print(f"{kb} | Max Risk: {max_risk:.2f} | CVEs: {cve_count}")

        for _, row in kb_rows.iterrows():

            print(
                f"   ├ {row['cve_id']} | Risk: {row['predicted_risk']:.2f}"
            )

        print()


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    print("\n=== WinShield AI Prioritisation ===")

    features, metadata = load_runtime_data()

    df = predict_risk(features, metadata)

    print_kb_breakdown(df)


# ------------------------------------------------------------

if __name__ == "__main__":
    main()