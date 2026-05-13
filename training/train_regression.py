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
TOP_FEATURES = 10


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a standard regression section heading."""

    print()
    print(f"--- {title} ---")


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------

def load_training_data() -> pd.DataFrame:
    """Load validated training data."""

    if not DATA_PATH.is_file():
        raise RuntimeError("Validated dataset missing. Run Data Pipeline first.")

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
    """Print concise numeric and categorical feature counts."""

    numeric_features = features.select_dtypes(include=["int64", "float64"]).columns
    categorical_features = features.select_dtypes(include=["object", "string"]).columns

    print(f"[+] Feature columns: {len(features.columns)}")
    print(f"[i] Numeric features: {len(numeric_features)}")
    print(f"[i] Categorical features: {len(categorical_features)}")


def print_target_summary(target: pd.Series) -> None:
    """Print concise regression target summary."""

    print(f"[+] Target rows: {len(target)}")
    print(f"[i] Risk score min: {target.min():.2f}")
    print(f"[i] Risk score max: {target.max():.2f}")
    print(f"[i] Risk score mean: {target.mean():.2f}")


def print_feature_importance(
    model: RandomForestRegressor,
    preprocessor: ColumnTransformer,
) -> None:
    """Print top feature importances from the trained model."""

    feature_names = preprocessor.get_feature_names_out().astype(str)

    importance_data = pd.DataFrame(
        {
            "feature": feature_names,
            "importance": model.feature_importances_,
        }
    ).sort_values(by="importance", ascending=False)

    print(f"[+] Top features: {TOP_FEATURES}")

    for _, row in importance_data.head(TOP_FEATURES).iterrows():
        print(f"[i] {row['feature']}: {row['importance']:.4f}")


def print_evaluation(
    model: RandomForestRegressor,
    test_features: Any,
    test_target: pd.Series,
) -> None:
    """Print concise regression evaluation metrics."""

    predictions = model.predict(test_features)

    mae = mean_absolute_error(test_target, predictions)
    rmse = np.sqrt(mean_squared_error(test_target, predictions))
    r2 = r2_score(test_target, predictions)

    print(f"[+] MAE: {mae:.4f}")
    print(f"[+] RMSE: {rmse:.4f}")
    print(f"[+] R2: {r2:.4f}")


# ------------------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------------------

def train_model(
    training_features: Any,
    training_target: pd.Series,
) -> RandomForestRegressor:
    """Train the regression model."""

    model = RandomForestRegressor(
        n_estimators=200,
        random_state=RANDOM_STATE,
    )

    model.fit(training_features, training_target)

    return model


# ------------------------------------------------------------
# MODEL EXPORT
# ------------------------------------------------------------

def save_artefacts(
    model: RandomForestRegressor,
    preprocessor: ColumnTransformer,
) -> None:
    """Save trained model and preprocessor."""

    joblib.dump(model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)

    print(f"[+] Model saved: {relative_path(MODEL_PATH)}")
    print(f"[+] Preprocessor saved: {relative_path(PREPROCESSOR_PATH)}")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> None:
    """Run regression model training."""

    print()
    print("=" * 60)
    print("WinShield+ - Regression Training")
    print("=" * 60)

    print_section("Load Data")
    training_data = load_training_data()
    training_data = add_exploitation_flag(training_data)

    print(f"[+] Dataset rows: {len(training_data)}")
    print(f"[+] Dataset columns: {len(training_data.columns)}")

    features, target = split_features_and_target(training_data)

    print_section("Prepare Features")
    print_feature_summary(features)
    print_target_summary(target)

    train_features, test_features, train_target, test_target = train_test_split(
        features,
        target,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )

    print(f"[+] Training rows: {len(train_features)}")
    print(f"[+] Test rows: {len(test_features)}")

    preprocessor = build_preprocessor(train_features)

    processed_train_features = preprocessor.fit_transform(train_features)
    processed_test_features = preprocessor.transform(test_features)

    print_section("Train Model")
    print("[*] Training RandomForestRegressor")

    model = train_model(
        training_features=processed_train_features,
        training_target=train_target,
    )

    print_evaluation(
        model=model,
        test_features=processed_test_features,
        test_target=test_target,
    )

    print_section("Feature Importance")
    print_feature_importance(
        model=model,
        preprocessor=preprocessor,
    )

    print_section("Export")
    save_artefacts(
        model=model,
        preprocessor=preprocessor,
    )

    print()
    print("[+] Regression Training completed")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()