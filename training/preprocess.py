import os
import argparse
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

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
    WORK_DIR = os.path.join(DATA_DIR, "runtime")
    INPUT_CSV = os.path.join(WORK_DIR, "validated_runtime.csv")
    OUTPUT_CSV = os.path.join(WORK_DIR, "preprocessed_runtime.csv")
else:
    WORK_DIR = os.path.join(DATA_DIR, "dataset")
    INPUT_CSV = os.path.join(WORK_DIR, "validated_dataset.csv")
    OUTPUT_CSV = os.path.join(WORK_DIR, "preprocessed_dataset.csv")

os.makedirs(WORK_DIR, exist_ok=True)

# ------------------------------------------------------------
# LOAD + PREPROCESS (USED DURING TRAINING)
# ------------------------------------------------------------

def load_and_preprocess(test_size=0.2, random_state=42):

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
        "published_date",
        "exploited_flag",
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
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_cols),
            ("cat", categorical_transformer, categorical_cols),
        ]
    )

    X_train, X_test, y_train_reg, y_test_reg, y_train_clf, y_test_clf = train_test_split(
        X,
        y_reg,
        y_clf,
        test_size=test_size,
        random_state=random_state,
        stratify=y_clf,
    )

    return (
        X_train,
        X_test,
        y_train_reg,
        y_test_reg,
        y_train_clf,
        y_test_clf,
        preprocessor,
    )


# ------------------------------------------------------------
# EXPORT FULL PREPROCESSED DATASET
# ------------------------------------------------------------

def export_full_preprocessed():

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
        "published_date",
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
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_cols),
            ("cat", categorical_transformer, categorical_cols),
        ]
    )

    X_processed = preprocessor.fit_transform(X)

    feature_names = preprocessor.get_feature_names_out()

    X_df = pd.DataFrame(
        X_processed.toarray() if hasattr(X_processed, "toarray") else X_processed,
        columns=feature_names,
    )

    X_df["risk_score"] = y_reg
    X_df["priority_label"] = y_clf

    X_df.to_csv(OUTPUT_CSV, index=False)

    print(f"Preprocessed dataset written to: {OUTPUT_CSV}")


# ------------------------------------------------------------

if __name__ == "__main__":
    export_full_preprocessed()