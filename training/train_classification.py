import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix
)


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

print("\n=== Classification Training ===\n")
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

y = df["priority_label"]

print("\nClass distribution:")
print(y.value_counts())


# ------------------------------------------------------------
# STEP 4: TRAIN / TEST SPLIT
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=2137, stratify=y
)

print("\nTrain shape:", X_train.shape)
print("Test shape:", X_test.shape)


# ------------------------------------------------------------
# STEP 5: FEATURE TYPE SEPARATION
# ------------------------------------------------------------

numeric_features = X_train.select_dtypes(include=["int64", "float64"]).columns
categorical_features = X_train.select_dtypes(include=["object"]).columns

print("\nNumeric features:", list(numeric_features))
print("Categorical features:", list(categorical_features))


# ------------------------------------------------------------
# STEP 6: PREPROCESSING
# ------------------------------------------------------------

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), numeric_features),
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
])

X_train_processed = preprocessor.fit_transform(X_train)
X_test_processed = preprocessor.transform(X_test)


# ------------------------------------------------------------
# STEP 7: MODEL TRAINING
# ------------------------------------------------------------

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=2137
)

model.fit(X_train_processed, y_train)


# ------------------------------------------------------------
# STEP 8: PREDICTIONS
# ------------------------------------------------------------

preds = model.predict(X_test_processed)


# ------------------------------------------------------------
# STEP 9: EVALUATION
# ------------------------------------------------------------

acc = accuracy_score(y_test, preds)
f1 = f1_score(y_test, preds, average="weighted")

labels = sorted(y.unique())
cm = confusion_matrix(y_test, preds, labels=labels)

print("\n=== Results ===")
print(f"Accuracy: {acc:.4f}")
print(f"F1 Score: {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, preds))


# ------------------------------------------------------------
# STEP 10: SAVE MODEL + PREPROCESSOR
# ------------------------------------------------------------

model_path = os.path.join(MODELS_DIR, "classification_model.joblib")
preprocessor_path = os.path.join(MODELS_DIR, "classification_preprocessor.joblib")

joblib.dump(model, model_path)
joblib.dump(preprocessor, preprocessor_path)

print("\n[+] Model saved to:", model_path)
print("[+] Preprocessor saved to:", preprocessor_path)


# ------------------------------------------------------------
# DONE
# ------------------------------------------------------------

print("\n=== Training Complete ===\n")