"""
WinShield Prioritiser

Loads the latest runtime scan and predicts patch risk using the
trained ML model.
"""

import os
import json
import pandas as pd
import joblib


# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

RUNTIME_DIR = os.path.join(ROOT_DIR, "data", "runtime")
MODELS_DIR = os.path.join(ROOT_DIR, "models")

PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "preprocessor.joblib")
REGRESSOR_PATH = os.path.join(MODELS_DIR, "regressor.joblib")


# ------------------------------------------------------------
# Find newest runtime scan
# ------------------------------------------------------------

def get_latest_runtime_scan():

    files = [
        f for f in os.listdir(RUNTIME_DIR)
        if f.startswith("scan_") and f.endswith(".json")
    ]

    if not files:
        raise RuntimeError("No runtime scans found.")

    files.sort(reverse=True)

    latest = files[0]

    return os.path.join(RUNTIME_DIR, latest), latest


# ------------------------------------------------------------
# Load scan JSON
# ------------------------------------------------------------

def load_runtime_scan():

    path, name = get_latest_runtime_scan()

    print(f"Using runtime scan: {name}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------
# Convert scan → dataframe
# ------------------------------------------------------------

def build_dataframe(scan_data):

    rows = []

    for entry in scan_data.get("KbEntries", []):

        kb = entry.get("KB")
        cves = entry.get("Cves", [])

        for cve in cves:

            rows.append({
                "kb_id": kb,
                "cve_id": cve,
                "cve_count": len(cves)
            })

    df = pd.DataFrame(rows)

    return df


# ------------------------------------------------------------
# Align runtime features with model features
# ------------------------------------------------------------

def align_features(df, preprocessor):

    model_features = preprocessor.feature_names_in_

    for col in model_features:
        if col not in df.columns:
            df[col] = 0

    df = df[model_features]

    return df


# ------------------------------------------------------------
# Predict risk
# ------------------------------------------------------------

def predict_risk(df):

    print("Loading models...")

    preprocessor = joblib.load(PREPROCESSOR_PATH)
    model = joblib.load(REGRESSOR_PATH)

    df_aligned = align_features(df.copy(), preprocessor)

    X_processed = preprocessor.transform(df_aligned)

    predictions = model.predict(X_processed)

    df["predicted_risk"] = predictions

    return df


# ------------------------------------------------------------
# Sort by priority
# ------------------------------------------------------------

def prioritise(df):

    return df.sort_values(
        by="predicted_risk",
        ascending=False
    )


# ------------------------------------------------------------
# Print top priorities
# ------------------------------------------------------------

def print_priorities(df):

    print("\n=== Patch Prioritisation ===\n")

    for _, row in df.head(15).iterrows():

        kb = row.get("kb_id", "UnknownKB")
        cve = row.get("cve_id", "UnknownCVE")

        risk = row["predicted_risk"]

        print(f"{kb} | {cve} | Risk: {risk:.2f}")


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    print("\n=== WinShield AI Prioritisation ===")

    scan_data = load_runtime_scan()

    df = build_dataframe(scan_data)

    if df.empty:
        print("No vulnerabilities detected.")
        return

    df = predict_risk(df)

    df = prioritise(df)

    print_priorities(df)


if __name__ == "__main__":
    main()