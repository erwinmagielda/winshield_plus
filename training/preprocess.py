import os
import argparse
import pandas as pd
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split

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

os.makedirs(MODELS_DIR, exist_ok=True)

if args.mode == "runtime":

    WORK_DIR = os.path.join(DATA_DIR, "runtime")
    INPUT_CSV = os.path.join(WORK_DIR, "validated_runtime.csv")
    OUTPUT_CSV = os.path.join(WORK_DIR, "preprocessed_runtime.csv")

else:

    WORK_DIR = os.path.join(DATA_DIR, "dataset")
    INPUT_CSV = os.path.join(WORK_DIR, "validated_dataset.csv")
    OUTPUT_CSV = os.path.join(WORK_DIR, "preprocessed_dataset.csv")

PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "preprocessor.joblib")

# ------------------------------------------------------------
# TRAINING PREPROCESS
# ------------------------------------------------------------

def training_preprocess():

    df = pd.read_csv(INPUT_CSV)

    y_reg = df["risk_score"]
    y_clf = df["priority_label"]

    drop_cols = [
        "risk_score",
        "priority_label",
        "host_id",
        "kb_id",
        "cve_id",
        "month",
        "published_date"
    ]

    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    numeric_cols = X.select_dtypes(include=["int64", "float64"]).columns.tolist()
    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()

    numeric_transformer = Pipeline(
        steps=[("imputer", SimpleImputer(strategy="median"))]
    )

    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore"))
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_cols),
            ("cat", categorical_transformer, categorical_cols)
        ]
    )

    X_processed = preprocessor.fit_transform(X)

    joblib.dump(preprocessor, PREPROCESSOR_PATH)

    feature_names = preprocessor.get_feature_names_out()

    X_df = pd.DataFrame(
        X_processed.toarray() if hasattr(X_processed, "toarray") else X_processed,
        columns=feature_names
    )

    X_df["risk_score"] = y_reg
    X_df["priority_label"] = y_clf

    X_df.to_csv(OUTPUT_CSV, index=False)

    print(f"Preprocessed dataset written to: {OUTPUT_CSV}")
    print(f"Preprocessor saved to: {PREPROCESSOR_PATH}")

# ------------------------------------------------------------
# RUNTIME PREPROCESS
# ------------------------------------------------------------

def runtime_preprocess():

    df = pd.read_csv(INPUT_CSV)

    drop_cols = [
        "host_id",
        "kb_id",
        "cve_id",
        "month",
        "published_date"
    ]

    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    preprocessor = joblib.load(PREPROCESSOR_PATH)

    X_processed = preprocessor.transform(X)

    feature_names = preprocessor.get_feature_names_out()

    X_df = pd.DataFrame(
        X_processed.toarray() if hasattr(X_processed, "toarray") else X_processed,
        columns=feature_names
    )

    X_df.to_csv(OUTPUT_CSV, index=False)

    print(f"Runtime features written to: {OUTPUT_CSV}")

# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":

    if args.mode == "runtime":
        runtime_preprocess()
    else:
        training_preprocess()