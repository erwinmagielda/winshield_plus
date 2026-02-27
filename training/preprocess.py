import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_CSV = os.path.join(BASE_DIR, "data", "validated_dataset.csv")


def load_and_preprocess(test_size=0.2, random_state=42):
    df = pd.read_csv(INPUT_CSV)

    # Targets
    y_reg = df["risk_score"]
    y_clf = df["priority_label"]

    # Drop Leakage / Identifiers
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

    X = df.drop(columns=[col for col in drop_cols if col in df.columns])

    # Detect Numeric vs Categorical
    numeric_cols = X.select_dtypes(include=["int64", "float64"]).columns.tolist()
    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()

    # Pipelines
    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
        ]
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

    # Train/Test Split
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

    X = df.drop(columns=[col for col in drop_cols if col in df.columns])

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

    X_df = pd.DataFrame(X_processed.toarray() if hasattr(X_processed, "toarray") else X_processed,
                        columns=feature_names)

    X_df["risk_score"] = y_reg
    X_df["priority_label"] = y_clf

    output_path = os.path.join(BASE_DIR, "data", "preprocessed_dataset.csv")
    X_df.to_csv(output_path, index=False)

    print(f"Preprocessed dataset written to: {output_path}")


if __name__ == "__main__":
    export_full_preprocessed()