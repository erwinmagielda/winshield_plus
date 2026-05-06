"""
WinShield+ regression model training.

Trains a RandomForestRegressor to predict risk scores from validated
WinShield+ vulnerability data. Saves the trained model and preprocessing
pipeline for runtime prioritisation.
"""

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

DATA_PATH = BASE_DIR / "data" / "dataset" / "validated_dataset.csv"
MODELS_DIR = BASE_DIR / "models"

MODEL_PATH = MODELS_DIR / "regression_model.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "regression_preprocessor.joblib"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

RANDOM_STATE = 2137
TEST_SIZE = 0.2


# ------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------

def load_training_data() -> pd.DataFrame:
    """Load validated training data."""

    if not DATA_PATH.is_file():
        raise RuntimeError("Validated dataset not found. Run data_pipeline.py first.")

    return pd.read_csv(DATA_PATH)


# ------------------------------------------------------------
# FEATURE PREPARATION
# ------------------------------------------------------------

def add_exploitation_flag(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Create a binary exploitation flag from MSRC exploitation text."""

    training_data = dataframe.copy()

    training_data["exploited_flag"] = training_data["exploitation"].apply(
        lambda value: 1 if "Exploited:Yes" in str(value) else 0
    )

    return training_data


def split_features_and_target(
    training_data: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.Series]:
    """Split validated data into model features and regression target."""

    drop_columns = [
        "risk_score",
        "priority_label",
        "kb_id",
        "cve_id",
        "month",
        "published_date",
        "exploitation",
    ]

    features = training_data.drop(columns=drop_columns)
    target = training_data["risk_score"]

    return features, target


def build_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    """Build preprocessing transformer for categorical features."""

    categorical_features = features.select_dtypes(
        include=["object", "string"]
    ).columns

    return ColumnTransformer(
        [
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features,
            )
        ],
        remainder="passthrough",
    )


# ------------------------------------------------------------
# REPORTING
# ------------------------------------------------------------

def print_feature_summary(features: pd.DataFrame) -> None:
    """Print numeric and categorical feature groups."""

    numeric_features = features.select_dtypes(include=["int64", "float64"]).columns
    categorical_features = features.select_dtypes(include=["object", "string"]).columns

    print("\nNumeric features:", list(numeric_features))
    print("Categorical features:", list(categorical_features))


def print_processed_preview(
    processed_features: Any,
    preprocessor: ColumnTransformer,
    rows: int = 20,
) -> None:
    """Print a small preview of the processed training matrix."""

    feature_names = preprocessor.get_feature_names_out().astype(str)

    if hasattr(processed_features, "toarray"):
        preview_data = processed_features[:rows].toarray()
    else:
        preview_data = processed_features[:rows]

    preview = pd.DataFrame(preview_data, columns=feature_names)

    print("\n=== Processed Dataset Preview (Top 20) ===")
    print(preview.head(rows))


def print_feature_importance(
    model: RandomForestRegressor,
    preprocessor: ColumnTransformer,
) -> None:
    """Print the top feature importances from the trained model."""

    feature_names = preprocessor.get_feature_names_out().astype(str)

    importance_data = pd.DataFrame(
        {
            "feature": feature_names,
            "importance": model.feature_importances_,
        }
    ).sort_values(by="importance", ascending=False)

    print("\nTop 10 Feature Importances:")

    for _, row in importance_data.head(10).iterrows():
        print(f"{row['feature']} -> {row['importance']:.4f}")


# ------------------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------------------

def train_model(
    training_features: pd.DataFrame,
    training_target: pd.Series,
) -> RandomForestRegressor:
    """Train the regression model."""

    model = RandomForestRegressor(
        n_estimators=200,
        random_state=RANDOM_STATE,
    )

    model.fit(training_features, training_target)

    return model


def evaluate_model(
    model: RandomForestRegressor,
    test_features: pd.DataFrame,
    test_target: pd.Series,
) -> None:
    """Evaluate the trained regression model."""

    predictions = model.predict(test_features)

    mae = mean_absolute_error(test_target, predictions)
    rmse = np.sqrt(mean_squared_error(test_target, predictions))
    r2 = r2_score(test_target, predictions)

    print("\n=== Results ===")
    print(f"MAE:  {mae:.4f}")
    print(f"RMSE: {rmse:.4f}")
    print(f"R2:   {r2:.4f}")


# ------------------------------------------------------------
# MODEL EXPORT
# ------------------------------------------------------------

def save_artifacts(
    model: RandomForestRegressor,
    preprocessor: ColumnTransformer,
) -> None:
    """Save trained model and preprocessor."""

    joblib.dump(model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)

    print("\n[+] Model saved to:", MODEL_PATH)
    print("[+] Preprocessor saved to:", PREPROCESSOR_PATH)


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> None:
    print("\n=== Regression Training ===\n")

    training_data = load_training_data()
    training_data = add_exploitation_flag(training_data)

    print("Dataset shape:", training_data.shape)

    print("\nExploitation flag distribution:")
    print(training_data["exploited_flag"].value_counts())

    features, target = split_features_and_target(training_data)

    train_features, test_features, train_target, test_target = train_test_split(
        features,
        target,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )

    print("\nTrain shape:", train_features.shape)
    print("Test shape:", test_features.shape)

    print_feature_summary(train_features)

    preprocessor = build_preprocessor(train_features)

    processed_train_features = preprocessor.fit_transform(train_features)
    processed_test_features = preprocessor.transform(test_features)

    print("\nProcessed shape (train):", processed_train_features.shape)
    print("Processed shape (test):", processed_test_features.shape)

    print_processed_preview(
        processed_features=processed_train_features,
        preprocessor=preprocessor,
    )

    model = train_model(
        training_features=processed_train_features,
        training_target=train_target,
    )

    evaluate_model(
        model=model,
        test_features=processed_test_features,
        test_target=test_target,
    )

    print_feature_importance(
        model=model,
        preprocessor=preprocessor,
    )

    save_artifacts(
        model=model,
        preprocessor=preprocessor,
    )

    print("\n=== Training Complete ===\n")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()