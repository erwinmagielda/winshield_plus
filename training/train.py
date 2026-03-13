import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    mean_absolute_error,
    mean_squared_error,
    r2_score,
    accuracy_score,
    f1_score,
    classification_report
)
from preprocess import load_and_preprocess
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def train():

    # --- Load & preprocess ---
    (
        X_train,
        X_test,
        y_train_reg,
        y_test_reg,
        y_train_clf,
        y_test_clf,
        preprocessor,
    ) = load_and_preprocess()

    # Fit preprocessing on training only
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    # =========================
    # REGRESSION (PRIMARY)
    # =========================

    reg_model = RandomForestRegressor(
        n_estimators=200,
        random_state=42
    )

    reg_model.fit(X_train_processed, y_train_reg)
    reg_preds = reg_model.predict(X_test_processed)

    mae = mean_absolute_error(y_test_reg, reg_preds)
    rmse = np.sqrt(mean_squared_error(y_test_reg, reg_preds))
    r2 = r2_score(y_test_reg, reg_preds)

    print("\n=== Regression Results ===")
    print(f"MAE:  {mae:.4f}")
    # Mean Absolute Error (MAE)
    # Average absolute difference between predicted risk scores and the true values.
    # Lower values indicate better predictive accuracy.
    print(f"RMSE: {rmse:.4f}")
    # Root Mean Squared Error (RMSE)
    # Similar to MAE but penalises larger errors more heavily.
    # Useful for identifying when the model makes large prediction mistakes.
    print(f"R2:   {r2:.4f}")
    # R² Score (Coefficient of Determination)
    # Measures how well the model explains variance in the target variable.
    # 1.0 = perfect prediction, 0 = no predictive power.

    # =========================
    # Feature Importance (Regression)
    # =========================

    import pandas as pd

    feature_names = preprocessor.get_feature_names_out()
    importances = reg_model.feature_importances_

    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance": importances
    }).sort_values(by="importance", ascending=False)

    print("\n=== Top 10 Feature Importances (Regression) ===")
    print(importance_df.head(10))


    # =========================
    # CLASSIFICATION (SECONDARY)
    # =========================

    clf_pipeline = Pipeline([
        ("scaler", StandardScaler(with_mean=False)),  # sparse-safe
        ("classifier", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42
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


    # =========================
    # Save artefacts
    # =========================

    joblib.dump(preprocessor, os.path.join(MODEL_DIR, "preprocessor.joblib"))
    joblib.dump(reg_model, os.path.join(MODEL_DIR, "regressor.joblib"))
    joblib.dump(clf_pipeline, os.path.join(MODEL_DIR, "classifier.joblib"))

    print("\nModels saved to /models directory.")


if __name__ == "__main__":
    train()