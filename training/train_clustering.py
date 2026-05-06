"""
WinShield+ clustering model training.

Trains a KMeans clustering model on validated WinShield+ vulnerability data.
Uses the elbow method for exploratory cluster selection, then saves the final
clustering model, preprocessor, and feature list for runtime prioritisation.
"""

from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

DATA_PATH = BASE_DIR / "data" / "dataset" / "validated_dataset.csv"
MODELS_DIR = BASE_DIR / "models"

MODEL_PATH = MODELS_DIR / "clustering_model.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "clustering_preprocessor.joblib"
FEATURES_PATH = MODELS_DIR / "clustering_features.joblib"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

RANDOM_STATE = 2137
MAX_K = 10
OPTIMAL_K = 5


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


def build_features(training_data: pd.DataFrame) -> pd.DataFrame:
    """Build clustering features from validated training data."""

    drop_columns = [
        "risk_score",
        "priority_label",
        "kb_id",
        "cve_id",
        "month",
        "published_date",
        "exploitation",
    ]

    return training_data.drop(columns=drop_columns)


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


def print_cluster_summary(training_data: pd.DataFrame) -> None:
    """Print cluster distribution and basic cluster interpretation metrics."""

    print("\n=== Cluster Distribution ===")
    print(training_data["cluster"].value_counts())

    print("\n=== Cluster vs Risk Score ===")
    print(training_data.groupby("cluster")["risk_score"].mean())

    print("\n=== Cluster vs CVSS ===")
    print(training_data.groupby("cluster")["cvss_score"].mean())

    print("\n=== Cluster vs Exploited ===")
    print(training_data.groupby("cluster")["exploited_flag"].mean())


# ------------------------------------------------------------
# ELBOW ANALYSIS
# ------------------------------------------------------------

def calculate_wcss(processed_features: Any, max_k: int = MAX_K) -> list[float]:
    """Calculate WCSS values for KMeans elbow analysis."""

    wcss: list[float] = []

    for cluster_count in range(1, max_k + 1):
        model = KMeans(
            n_clusters=cluster_count,
            random_state=RANDOM_STATE,
        )

        model.fit(processed_features)
        wcss.append(model.inertia_)

    return wcss


def plot_elbow_curve(wcss: list[float]) -> None:
    """Plot the elbow curve for visual K selection."""

    plt.figure()
    plt.plot(range(1, len(wcss) + 1), wcss, marker="o")
    plt.title("Elbow Method")
    plt.xlabel("Number of Clusters (K)")
    plt.ylabel("WCSS")
    plt.show()


def plot_cluster_scatter(training_data: pd.DataFrame) -> None:
    """Plot CVSS score against risk score using cluster assignments."""

    plt.figure()
    plt.scatter(
        training_data["cvss_score"],
        training_data["risk_score"],
        c=training_data["cluster"],
        alpha=0.5,
    )
    plt.title("CVSS vs Risk Score")
    plt.xlabel("CVSS Score")
    plt.ylabel("Risk Score")
    plt.show()


# ------------------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------------------

def train_model(processed_features: Any, cluster_count: int = OPTIMAL_K) -> KMeans:
    """Train the final KMeans clustering model."""

    model = KMeans(
        n_clusters=cluster_count,
        random_state=RANDOM_STATE,
    )

    model.fit(processed_features)

    return model


# ------------------------------------------------------------
# MODEL EXPORT
# ------------------------------------------------------------

def save_artifacts(
    model: KMeans,
    preprocessor: ColumnTransformer,
    features: pd.DataFrame,
) -> None:
    """Save trained clustering model, preprocessor, and feature list."""

    joblib.dump(model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)
    joblib.dump(features.columns.tolist(), FEATURES_PATH)

    print("\n[+] Model saved to:", MODEL_PATH)
    print("[+] Preprocessor saved to:", PREPROCESSOR_PATH)
    print("[+] Feature list saved to:", FEATURES_PATH)


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> None:
    print("\n=== Clustering Training ===\n")

    training_data = load_training_data()
    training_data = add_exploitation_flag(training_data)

    print("Dataset shape:", training_data.shape)

    print("\nExploitation flag distribution:")
    print(training_data["exploited_flag"].value_counts())

    features = build_features(training_data)

    print("\nFeature shape:", features.shape)
    print_feature_summary(features)

    preprocessor = build_preprocessor(features)
    processed_features = preprocessor.fit_transform(features)

    print("\nProcessed shape:", processed_features.shape)

    print_processed_preview(
        processed_features=processed_features,
        preprocessor=preprocessor,
    )

    wcss = calculate_wcss(processed_features)

    print("\nWCSS values:")
    print(wcss)

    plot_elbow_curve(wcss)

    print(f"\nSelected K = {OPTIMAL_K}")

    model = train_model(
        processed_features=processed_features,
        cluster_count=OPTIMAL_K,
    )

    training_data["cluster"] = model.predict(processed_features)

    print_cluster_summary(training_data)
    plot_cluster_scatter(training_data)

    save_artifacts(
        model=model,
        preprocessor=preprocessor,
        features=features,
    )

    print("\n=== Training Complete ===\n")


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    main()