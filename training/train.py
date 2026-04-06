import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans
from sklearn.metrics import (
    mean_absolute_error,
    mean_squared_error,
    r2_score,
    accuracy_score,
    f1_score,
    classification_report
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_PATH = os.path.join(BASE_DIR, "data", "dataset", "preprocessed_dataset.csv")

MODELS_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "preprocessor.joblib")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


# ------------------------------------------------------------
# TRAIN
# ------------------------------------------------------------

def train():

    df = pd.read_csv(DATASET_PATH)

    y_reg = df["risk_score"]
    y_clf = df["priority_label"]

    X = df.drop(columns=["risk_score", "priority_label"])

    X_train, X_test, y_train_reg, y_test_reg, y_train_clf, y_test_clf = train_test_split(
        X,
        y_reg,
        y_clf,
        test_size=0.2,
        random_state=2137
    )

    X_train_processed = X_train
    X_test_processed = X_test


# ------------------------------------------------------------
# REGRESSION MODEL
# ------------------------------------------------------------

    reg_model = RandomForestRegressor(
        n_estimators=200,
        random_state=2137
    )

    reg_model.fit(X_train_processed, y_train_reg)

    reg_preds = reg_model.predict(X_test_processed)

    mae = mean_absolute_error(y_test_reg, reg_preds)
    rmse = np.sqrt(mean_squared_error(y_test_reg, reg_preds))
    r2 = r2_score(y_test_reg, reg_preds)

    print("\n=== Regression Results ===")
    print(f"MAE:  {mae:.4f}")
    print(f"RMSE: {rmse:.4f}")
    print(f"R2:   {r2:.4f}")


# ------------------------------------------------------------
# FEATURE IMPORTANCE
# ------------------------------------------------------------

    feature_names = X.columns
    importances = reg_model.feature_importances_

    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance": importances
    }).sort_values(by="importance", ascending=False)

    print("\n=== Top 10 Feature Importances (Regression) ===")
    print(importance_df.head(10))


# ------------------------------------------------------------
# CLASSIFICATION MODEL
# ------------------------------------------------------------

    clf_pipeline = Pipeline([
        ("scaler", StandardScaler(with_mean=False)),
        ("classifier", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=2137
        ))
    ])

    clf_pipeline.fit(X_train_processed, y_train_clf)

    clf_preds = clf_pipeline.predict(X_test_processed)

    acc = accuracy_score(y_test_clf, clf_preds)
    f1 = f1_score(y_test_clf, clf_preds, average="weighted")

    print("\n=== Classification Results ===")
    print(f"Accuracy: {acc:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test_clf, clf_preds))


# ------------------------------------------------------------
# UNSUPERVISED MODEL (K-MEANS) — FIXED
# ------------------------------------------------------------

    print("\n=== Unsupervised Clustering (K-Means) ===")

    scaler = StandardScaler()
    X_unsup_scaled = scaler.fit_transform(X_train_processed)

    wcss = []

    for i in range(1, 11):
        km = KMeans(n_clusters=i, random_state=2137)
        km.fit(X_unsup_scaled)
        wcss.append(km.inertia_)

    print("WCSS values (Elbow Method):")
    print(wcss)

    optimal_k = 3

    kmeans = KMeans(n_clusters=optimal_k, random_state=2137)
    kmeans.fit(X_unsup_scaled)

    print(f"KMeans trained with K={optimal_k}")


# ------------------------------------------------------------
# CLUSTER INTERPRETATION
# ------------------------------------------------------------

    cluster_labels = kmeans.predict(X_unsup_scaled)

    cluster_df = pd.DataFrame({
        "cluster": cluster_labels,
        "risk_score": y_train_reg
    })

    print("\n=== Cluster Risk Distribution ===")
    print(cluster_df.groupby("cluster")["risk_score"].mean())


# ------------------------------------------------------------
# SAVE MODELS
# ------------------------------------------------------------

    joblib.dump(reg_model, os.path.join(MODELS_DIR, "regressor.joblib"))
    joblib.dump(clf_pipeline, os.path.join(MODELS_DIR, "classifier.joblib"))
    joblib.dump(kmeans, os.path.join(MODELS_DIR, "clusterer.joblib"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "cluster_scaler.joblib"))

    print("\nModels saved to /models directory.")


# ------------------------------------------------------------
# SAVE TRAINING SUMMARY
# ------------------------------------------------------------

    summary = {
        "dataset": {
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test))
        },
        "regression": {
            "model": "RandomForestRegressor",
            "mae": float(mae),
            "rmse": float(rmse),
            "r2": float(r2)
        },
        "classification": {
            "model": "LogisticRegression",
            "accuracy": float(acc),
            "f1_score": float(f1)
        },
        "unsupervised": {
            "model": "KMeans",
            "k": optimal_k,
            "wcss": [float(x) for x in wcss]
        },
        "top_features": importance_df.head(10).to_dict(orient="records")
    }

    summary_path = os.path.join(RESULTS_DIR, "training_summary.json")

    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=4)

    print(f"\nTraining summary saved to: {summary_path}")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    train()