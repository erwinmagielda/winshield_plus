"""
WinShield+ regression model training.

Trains a RandomForestRegressor to learn the policy-generated risk score from
validated WinShield+ vulnerability features. Saves the trained model and
preprocessing pipeline for runtime prioritisation.
"""

from __future__ import annotations

import sys
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
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import (  # noqa: E402
    print_error,
    print_info,
    print_section,
    print_step,
    print_success,
    print_warning,
)
from utils.winshield_paths import (  # noqa: E402
    ensure_directory,
    get_models_dir,
    get_validated_dataset_path,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

DATA_PATH = get_validated_dataset_path()
MODELS_DIR = get_models_dir()

MODEL_PATH = MODELS_DIR / "regression_model.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "regression_preprocessor.joblib"


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

RANDOM_STATE = 2137
TEST_SIZE = 0.2
TOP_FEATURES = 10


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------

def load_training_data() -> pd.DataFrame:
    """Load validated training data."""

    if not DATA_PATH.is_file():
        raise RuntimeError("Validated dataset missing. Run Data pipeline first.")

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
        "policy_risk",
        "policy_priority",
        "policy_drivers",
        "top_driver",
        "kb_id",
        "cve_id",
        "month",
        "published_date",
        "exploitation",
    ]

    features = training_data.drop(columns=drop_columns, errors="ignore")
    target = training_data["risk_score"]

    return features, target


def build_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    """Build preprocessing transformer for categorical and numeric features."""

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
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_dataset_summary(training_data: pd.DataFrame) -> None:
    """Print dataset summary."""

    print_success(f"Dataset rows: {len(training_data)}")
    print_success(f"Dataset columns: {len(training_data.columns)}")
    print_info(f"Input: {relative_path(DATA_PATH)}")


def print_feature_summary(features: pd.DataFrame) -> None:
    """Print numeric and categorical feature counts."""

    numeric_features = features.select_dtypes(include=["int64", "float64"]).columns
    categorical_features = features.select_dtypes(include=["object", "string"]).columns

    print_success(f"Feature columns: {len(features.columns)}")
    print_info(f"Numeric features: {len(numeric_features)}")
    print_info(f"Categorical features: {len(categorical_features)}")
    print_info("Policy output columns excluded from model features")


def print_target_summary(target: pd.Series) -> None:
    """Print regression target summary."""

    print_success(f"Target rows: {len(target)}")
    print_info(f"Risk score min: {target.min():.2f}")
    print_info(f"Risk score max: {target.max():.2f}")
    print_info(f"Risk score mean: {target.mean():.2f}")


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

    print_success(f"Top features: {TOP_FEATURES}")

    for _, row in importance_data.head(TOP_FEATURES).iterrows():
        print_info(f"{row['feature']}: {row['importance']:.4f}")


def print_evaluation(
    model: RandomForestRegressor,
    test_features: Any,
    test_target: pd.Series,
) -> None:
    """Print regression evaluation metrics."""

    predictions = model.predict(test_features)

    mae = mean_absolute_error(test_target, predictions)
    rmse = np.sqrt(mean_squared_error(test_target, predictions))
    r2 = r2_score(test_target, predictions)

    print_success(f"MAE: {mae:.4f}")
    print_success(f"RMSE: {rmse:.4f}")
    print_success(f"R2: {r2:.4f}")


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

    ensure_directory(MODELS_DIR)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)

    print_success(f"Model saved: {relative_path(MODEL_PATH)}")
    print_success(f"Preprocessor saved: {relative_path(PREPROCESSOR_PATH)}")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run regression model training."""

    try:
        print()
        print("Regression training")
        print("=" * 60)

        print_section("Load data")
        training_data = load_training_data()
        training_data = add_exploitation_flag(training_data)
        print_dataset_summary(training_data)

        features, target = split_features_and_target(training_data)

        print_section("Prepare features")
        print_feature_summary(features)
        print_target_summary(target)

        train_features, test_features, train_target, test_target = train_test_split(
            features,
            target,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
        )

        print_success(f"Training rows: {len(train_features)}")
        print_success(f"Test rows: {len(test_features)}")

        preprocessor = build_preprocessor(train_features)

        processed_train_features = preprocessor.fit_transform(train_features)
        processed_test_features = preprocessor.transform(test_features)

        print_section("Train model")
        print_step("Training RandomForestRegressor")
        print_info("Estimators: 200")
        print_info(f"Random state: {RANDOM_STATE}")

        model = train_model(
            training_features=processed_train_features,
            training_target=train_target,
        )

        print_evaluation(
            model=model,
            test_features=processed_test_features,
            test_target=test_target,
        )

        print_section("Export")
        save_artefacts(
            model=model,
            preprocessor=preprocessor,
        )

        print()
        print_success("Regression training completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Regression training cancelled")
        return 130

    except Exception as exc:
        print_error(f"Regression training failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())