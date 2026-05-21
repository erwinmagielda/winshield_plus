"""
WinShield+ clustering model training.

Trains a KMeans clustering model on validated WinShield+ vulnerability data.

Uses elbow analysis for cluster selection support, then saves the final
clustering model, preprocessor, feature list, and chart artefacts for runtime
prioritisation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


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
    get_clustering_elbow_chart_path,
    get_clustering_scatter_chart_path,
    get_models_dir,
    get_validated_dataset_path,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

DATA_PATH = get_validated_dataset_path()
MODELS_DIR = get_models_dir()

MODEL_PATH = MODELS_DIR / "clustering_model.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "clustering_preprocessor.joblib"
FEATURES_PATH = MODELS_DIR / "clustering_features.joblib"

ELBOW_CHART_PATH = get_clustering_elbow_chart_path()
SCATTER_CHART_PATH = get_clustering_scatter_chart_path()


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

RANDOM_STATE = 2137
MAX_K = 10
OPTIMAL_K = 5


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


def build_features(training_data: pd.DataFrame) -> pd.DataFrame:
    """Build clustering features from validated training data."""

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

    return training_data.drop(columns=drop_columns, errors="ignore")


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
# ELBOW ANALYSIS
# ------------------------------------------------------------

def calculate_wcss(processed_features: Any, max_k: int = MAX_K) -> list[float]:
    """Calculate WCSS values for KMeans elbow analysis."""

    wcss: list[float] = []

    for cluster_count in range(1, max_k + 1):
        model = KMeans(
            n_clusters=cluster_count,
            random_state=RANDOM_STATE,
            n_init=10,
        )

        model.fit(processed_features)
        inertia = float(model.inertia_)
        wcss.append(inertia)

        print_info(f"K={cluster_count}: WCSS={inertia:.2f}")

    return wcss


def save_elbow_curve(wcss: list[float]) -> None:
    """Save the elbow curve without opening a GUI window."""

    ensure_directory(ELBOW_CHART_PATH.parent)

    plt.figure()
    plt.plot(range(1, len(wcss) + 1), wcss, marker="o")
    plt.title("Elbow Method")
    plt.xlabel("Number of Clusters (K)")
    plt.ylabel("WCSS")
    plt.savefig(ELBOW_CHART_PATH, bbox_inches="tight")
    plt.close()

    print_success(f"Elbow chart saved: {relative_path(ELBOW_CHART_PATH)}")


def save_cluster_scatter(training_data: pd.DataFrame) -> None:
    """Save CVSS score against risk score using cluster assignments."""

    ensure_directory(SCATTER_CHART_PATH.parent)

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
    plt.savefig(SCATTER_CHART_PATH, bbox_inches="tight")
    plt.close()

    print_success(f"Cluster chart saved: {relative_path(SCATTER_CHART_PATH)}")


# ------------------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------------------

def train_model(processed_features: Any, cluster_count: int = OPTIMAL_K) -> KMeans:
    """Train the final KMeans clustering model."""

    model = KMeans(
        n_clusters=cluster_count,
        random_state=RANDOM_STATE,
        n_init=10,
    )

    model.fit(processed_features)

    return model


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
    print_info("Policy output columns excluded from clustering features")


def print_cluster_summary(training_data: pd.DataFrame) -> None:
    """Print cluster distribution and risk summary."""

    distribution = training_data["cluster"].value_counts().sort_index()
    average_risk = training_data.groupby("cluster")["risk_score"].mean().round(2)

    print_success(f"Clusters created: {len(distribution)}")

    for cluster_id, count in distribution.items():
        mean_risk = average_risk.get(cluster_id, 0)
        print_info(f"Cluster {cluster_id}: {count} rows | Avg risk: {mean_risk}")


# ------------------------------------------------------------
# MODEL EXPORT
# ------------------------------------------------------------

def save_artefacts(
    model: KMeans,
    preprocessor: ColumnTransformer,
    features: pd.DataFrame,
) -> None:
    """Save trained clustering model, preprocessor, and feature list."""

    ensure_directory(MODELS_DIR)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)
    joblib.dump(features.columns.tolist(), FEATURES_PATH)

    print_success(f"Model saved: {relative_path(MODEL_PATH)}")
    print_success(f"Preprocessor saved: {relative_path(PREPROCESSOR_PATH)}")
    print_success(f"Feature list saved: {relative_path(FEATURES_PATH)}")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run clustering model training."""

    try:
        print()
        print("Clustering training")
        print("=" * 60)

        print_section("Load data")
        training_data = load_training_data()
        training_data = add_exploitation_flag(training_data)
        print_dataset_summary(training_data)

        print_section("Prepare features")
        features = build_features(training_data)
        print_feature_summary(features)

        preprocessor = build_preprocessor(features)
        processed_features = preprocessor.fit_transform(features)

        print_success(f"Processed feature matrix rows: {processed_features.shape[0]}")
        print_success(f"Processed feature matrix columns: {processed_features.shape[1]}")

        print_section("Elbow analysis")
        print_step(f"Running elbow analysis: K=1 to K={MAX_K}")
        wcss = calculate_wcss(processed_features)
        save_elbow_curve(wcss)

        print_section("Train model")
        print_step(f"Training KMeans model: K={OPTIMAL_K}")
        print_info(f"Random state: {RANDOM_STATE}")

        model = train_model(
            processed_features=processed_features,
            cluster_count=OPTIMAL_K,
        )

        training_data["cluster"] = model.predict(processed_features)

        print_cluster_summary(training_data)
        save_cluster_scatter(training_data)

        print_section("Export")
        save_artefacts(
            model=model,
            preprocessor=preprocessor,
            features=features,
        )

        print()
        print_success("Clustering training completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Clustering training cancelled")
        return 130

    except Exception as exc:
        print_error(f"Clustering training failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())