import os
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "dataset", "validated_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


# ------------------------------------------------------------
# STEP 1: LOAD DATA
# ------------------------------------------------------------

df = pd.read_csv(DATA_PATH)

print("\n=== Regression Training ===\n")
print("Dataset shape:", df.shape)


# ------------------------------------------------------------
# STEP 2: TRANSFORM FEATURE
# ------------------------------------------------------------

df["exploited_flag"] = df["exploitation"].apply(
    lambda x: 1 if "Exploited:Yes" in str(x) else 0
)

print("\nExploitation flag distribution:")
print(df["exploited_flag"].value_counts())


# ------------------------------------------------------------
# STEP 3: DEFINE FEATURES (X) AND TARGET (y)
# ------------------------------------------------------------

X = df.drop([
    "risk_score",
    "priority_label",
    "kb_id",
    "cve_id",
    "month",
    "published_date",
    "exploitation"
    ], axis=1)

y = df["risk_score"]


# ------------------------------------------------------------
# STEP 4: TRAIN / TEST SPLIT
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=2137
)

print("\nTrain shape:", X_train.shape)
print("Test shape:", X_test.shape)


# ------------------------------------------------------------
# STEP 5: FEATURE TYPE SEPARATION
# ------------------------------------------------------------

numeric_features = X_train.select_dtypes(include=["int64", "float64"]).columns
categorical_features = X_train.select_dtypes(include=["object", "string"]).columns

print("\nNumeric features:", list(numeric_features))
print("Categorical features:", list(categorical_features))


# ------------------------------------------------------------
# STEP 6: ENCODING
# ------------------------------------------------------------

preprocessor = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
], remainder="passthrough")

X_train_processed = preprocessor.fit_transform(X_train)
X_test_processed = preprocessor.transform(X_test)

print("\nProcessed shape (train):", X_train_processed.shape)
print("Processed shape (test):", X_test_processed.shape)

# SET READY
feature_names = preprocessor.get_feature_names_out().astype(str)

X_preview = pd.DataFrame(X_train_processed, columns=feature_names)

print("\n=== Processed Dataset Preview (Top 20) ===")
print(X_preview.head(20))


# ------------------------------------------------------------
# STEP 7: MODEL TRAINING
# ------------------------------------------------------------

model = RandomForestRegressor(
    n_estimators=200,
    random_state=2137
)

model.fit(X_train_processed, y_train)


# ------------------------------------------------------------
# STEP 8: PREDICTIONS
# ------------------------------------------------------------

y_pred = model.predict(X_test_processed)


# ------------------------------------------------------------
# STEP 9: EVALUATION
# ------------------------------------------------------------

mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mean_squared_error(y_test, y_pred))
r2 = r2_score(y_test, y_pred)

print("\n=== Results ===")
print(f"MAE:  {mae:.4f}")
print(f"RMSE: {rmse:.4f}")
print(f"R2:   {r2:.4f}")


# ------------------------------------------------------------
# STEP 10: FEATURE IMPORTANCE
# ------------------------------------------------------------

feature_names = preprocessor.get_feature_names_out().astype(str)

importance_df = pd.DataFrame({
    "feature": feature_names,
    "importance": model.feature_importances_
}).sort_values(by="importance", ascending=False)

print("\nTop 10 Feature Importances:")
for i, row in importance_df.head(10).iterrows():
    print(f"{row['feature']} -> {row['importance']:.4f}")


# ------------------------------------------------------------
# STEP 11: SAVE MODEL + PREPROCESSOR
# ------------------------------------------------------------

model_path = os.path.join(MODELS_DIR, "regression_model.joblib")
preprocessor_path = os.path.join(MODELS_DIR, "regression_preprocessor.joblib")

joblib.dump(model, model_path)
joblib.dump(preprocessor, preprocessor_path)

print("\n[+] Model saved to:", model_path)
print("[+] Preprocessor saved to:", preprocessor_path)

# ------------------------------------------------------------
# DONE
# ------------------------------------------------------------

print("\n=== Training Complete ===\n")