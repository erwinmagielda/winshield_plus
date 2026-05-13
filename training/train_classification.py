"""
WinShield+ classification model training.

Trains a LogisticRegression classifier to predict priority labels from
validated WinShield+ vulnerability data. Saves the trained model and
preprocessing pipeline for runtime prioritisation.
"""

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

DATA_PATH = BASE_DIR / "data" / "dataset" / "validated_dataset.csv"
MODELS_DIR = BASE_DIR / "models"

MODEL_PATH = MODELS_DIR / "classification_model.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "classification_preprocessor.joblib"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

RANDOM_STATE = 2137
TEST_SIZE = 0.2


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a standard classification section heading."""

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
    """Split validated data into model features and classification target."""

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
    target = training_data["priority_label"]

    return features, target


def build_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    """Build preprocessing transformer for numeric and categorical features."""

    numeric_features = features.select_dtypes(include=["int64", "float64"]).columns
    categorical_features = features.select_dtypes(
        include=["object", "string"]
    ).columns

    return ColumnTransformer(
        [
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
        ]
    )


# ------------------------------------------------------------
# REPORTING
# ------------------------------------------------------------

def print_class_distribution(target: pd.Series) -> None:
    """Print class distribution for the training target."""

    distribution = target.value_counts()

    print("[+] Class labels:", len(distribution))

    for label, count in distribution.items():
        print(f"[i] {label}: {count}")


def print_feature_summary(features: pd.DataFrame) -> None:
    """Print concise numeric and categorical feature counts."""

    numeric_features = features.select_dtypes(include=["int64", "float64"]).columns
    categorical_features = features.select_dtypes(include=["object", "string"]).columns

    print(f"[+] Feature columns: {len(features.columns)}")
    print(f"[i] Numeric features: {len(numeric_features)}")
    print(f"[i] Categorical features: {len(categorical_features)}")


def print_evaluation(
    test_target: pd.Series,
    predictions: pd.Series,
) -> None:
    """Print concise classification evaluation metrics."""

    accuracy = accuracy_score(test_target, predictions)
    f1 = f1_score(test_target, predictions, average="weighted")

    print(f"[+] Accuracy: {accuracy:.4f}")
    print(f"[+] Weighted F1: {f1:.4f}")


# ------------------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------------------

def train_model(
    training_features: Any,
    training_target: pd.Series,
) -> LogisticRegression:
    """Train the classification model."""

    model = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )

    model.fit(training_features, training_target)

    return model


# ------------------------------------------------------------
# MODEL EXPORT
# ------------------------------------------------------------

def save_artefacts(
    model: LogisticRegression,
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
    """Run classification model training."""

    print()
    print("=" * 60)
    print("WinShield+ - Classification Training")
    print("=" * 60)

    print_section("Load Data")
    training_data = load_training_data()
    training_data = add_exploitation_flag(training_data)

    print(f"[+] Dataset rows: {len(training_data)}")
    print(f"[+] Dataset columns: {len(training_data.columns)}")

    features, target = split_features_and_target(training_data)

    print_section("Prepare Features")
    print_class_distribution(target)

    train_features, test_features, train_target, test_target = train_test_split(
        features,
        target,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=target,
    )

    print(f"[+] Training rows: {len(train_features)}")
    print(f"[+] Test rows: {len(test_features)}")
    print_feature_summary(train_features)

    preprocessor = build_preprocessor(train_features)

    processed_train_features = preprocessor.fit_transform(train_features)
    processed_test_features = preprocessor.transform(test_features)

    print_section("Train Model")
    print("[*] Training LogisticRegression classifier")

    model = train_model(
        training_features=processed_train_features,
        training_target=train_target,
    )

    predictions = model.predict(processed_test_features)

    print_evaluation(
        test_target=test_target,
        predictions=predictions,
    )

    print_section("Export")
    save_artefacts(
        model=model,
        preprocessor=preprocessor,
    )

    print()
    print("[+] Classification Training completed")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()