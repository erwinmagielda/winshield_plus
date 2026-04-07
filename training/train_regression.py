import os
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "dataset", "validated_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODELS_DIR, exist_ok=True)


# ------------------------------------------------------------
# STEP 1: LOAD DATA
# ------------------------------------------------------------

df = pd.read_csv(DATA_PATH)

print("\n=== Regression Training ===\n")
print("Dataset shape:", df.shape)


# ------------------------------------------------------------
# STEP 2: DEFINE FEATURES (X) AND TARGET (y)
# ------------------------------------------------------------

drop_cols = [
    "risk_score",
    "priority_label",
    "kb_id",
    "cve_id",
    "month",
    "published_date",
    "exploitation"
]

X = df.drop(columns=[c for c in drop_cols if c in df.columns])
y = df["risk_score"]


# ------------------------------------------------------------
# STEP 3: TRAIN / TEST SPLIT
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=2137
)


# ------------------------------------------------------------
# STEP 4: FEATURE TYPE SEPARATION
# ------------------------------------------------------------

numeric_features = X.select_dtypes(include=["int64", "float64"]).columns
categorical_features = X.select_dtypes(include=["object"]).columns

print("\nNumeric features:", list(numeric_features))
print("Categorical features:", list(categorical_features))


# ------------------------------------------------------------
# STEP 5: PREPROCESSING (ONLY ENCODING)
# ------------------------------------------------------------

preprocessor = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
], remainder="passthrough")  # keep numeric as-is


# ------------------------------------------------------------
# STEP 6: MODEL DEFINITION
# ------------------------------------------------------------

model = RandomForestRegressor(
    n_estimators=200,
    random_state=2137
)


# ------------------------------------------------------------
# STEP 7: PIPELINE
# ------------------------------------------------------------

pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("regressor", model)
])


# ------------------------------------------------------------
# STEP 8: TRAIN MODEL
# ------------------------------------------------------------

pipeline.fit(X_train, y_train)


# ------------------------------------------------------------
# STEP 9: EVALUATE MODEL
# ------------------------------------------------------------

preds = pipeline.predict(X_test)

mae = mean_absolute_error(y_test, preds)
rmse = np.sqrt(mean_squared_error(y_test, preds))
r2 = r2_score(y_test, preds)

print("\n=== Results ===")
print(f"MAE:  {mae:.4f}")
print(f"RMSE: {rmse:.4f}")
print(f"R2:   {r2:.4f}")


# ------------------------------------------------------------
# OPTIONAL: FEATURE IMPORTANCE
# ------------------------------------------------------------

# get feature names after encoding
encoded_features = pipeline.named_steps["preprocessor"].get_feature_names_out()

importances = pipeline.named_steps["regressor"].feature_importances_

importance_df = pd.DataFrame({
    "feature": encoded_features,
    "importance": importances
}).sort_values(by="importance", ascending=False)

print("\nTop 10 Feature Importances:")
print(importance_df.head(10))


# ------------------------------------------------------------
# STEP 10: SAVE MODEL + FEATURE SCHEMA
# ------------------------------------------------------------

joblib.dump(pipeline, os.path.join(MODELS_DIR, "regression_model.joblib"))
joblib.dump(X.columns.tolist(), os.path.join(MODELS_DIR, "regression_features.joblib"))

print("\nModel saved to /models/")