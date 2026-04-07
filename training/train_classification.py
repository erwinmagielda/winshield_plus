import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix
)

import seaborn as sns
import matplotlib.pyplot as plt


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
y = df["priority_label"]

print("\nClass distribution:")
print(y.value_counts())


# ------------------------------------------------------------
# STEP 3: TRAIN / TEST SPLIT
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=2137,
    stratify=y
)


# ------------------------------------------------------------
# STEP 4: FEATURE TYPE SEPARATION
# ------------------------------------------------------------

numeric_features = X.select_dtypes(include=["int64", "float64"]).columns
categorical_features = X.select_dtypes(include=["object"]).columns

print("\nNumeric features:", list(numeric_features))
print("Categorical features:", list(categorical_features))


# ------------------------------------------------------------
# STEP 5: PREPROCESSING (ENCODING + SCALING)
# ------------------------------------------------------------

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), numeric_features),
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
])


# ------------------------------------------------------------
# STEP 6: MODEL DEFINITION
# ------------------------------------------------------------

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=2137
)


# ------------------------------------------------------------
# STEP 7: PIPELINE (PREPROCESS + MODEL)
# ------------------------------------------------------------

pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", model)
])


# ------------------------------------------------------------
# STEP 8: TRAIN MODEL
# ------------------------------------------------------------

pipeline.fit(X_train, y_train)


# ------------------------------------------------------------
# STEP 9: EVALUATE MODEL
# ------------------------------------------------------------

preds = pipeline.predict(X_test)

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
# STEP 10: SAVE MODEL + FEATURE SCHEMA
# ------------------------------------------------------------

joblib.dump(pipeline, os.path.join(MODELS_DIR, "classification_model.joblib"))
joblib.dump(X.columns.tolist(), os.path.join(MODELS_DIR, "classification_features.joblib"))

print("\nClassification model saved.")