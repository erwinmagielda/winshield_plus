import os
import json
import pandas as pd
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RUNTIME_SCAN = os.path.join(BASE_DIR, "data", "runtime", "scan_runtime.json")
MODELS_DIR = os.path.join(BASE_DIR, "models")

PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "preprocessor.joblib")
REGRESSOR_PATH = os.path.join(MODELS_DIR, "regressor.joblib")


def load_runtime_scan():
    with open(RUNTIME_SCAN, "r", encoding="utf-8") as f:
        return json.load(f)


def build_dataframe(scan_data):
    rows = []

    for entry in scan_data["KbEntries"]:
        kb = entry.get("KB")

        for cve in entry.get("Cves", []):
            rows.append({
                "kb_id": kb,
                "cve_id": cve
            })

    return pd.DataFrame(rows)


def predict_risk(df):

    preprocessor = joblib.load(PREPROCESSOR_PATH)
    model = joblib.load(REGRESSOR_PATH)

    X_processed = preprocessor.transform(df)

    predictions = model.predict(X_processed)

    df["predicted_risk"] = predictions

    return df


def prioritise(df):

    df_sorted = df.sort_values(
        by="predicted_risk",
        ascending=False
    )

    return df_sorted


def print_priorities(df):

    print("\n=== Patch Prioritisation ===\n")

    for _, row in df.head(10).iterrows():
        print(
            f"{row['kb_id']} | "
            f"{row['cve_id']} | "
            f"Risk: {row['predicted_risk']:.2f}"
        )


def main():

    scan_data = load_runtime_scan()

    df = build_dataframe(scan_data)

    if df.empty:
        print("No vulnerabilities to prioritise.")
        return

    df = predict_risk(df)

    df = prioritise(df)

    print_priorities(df)


if __name__ == "__main__":
    main()