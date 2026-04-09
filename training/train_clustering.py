import os
import joblib
import pandas as pd

from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.cluster import KMeans
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

print("\n=== Clustering Training ===\n")
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
# STEP 3: DEFINE FEATURES (NO TARGET)
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

print("\nFeature shape:", X.shape)


# ------------------------------------------------------------
# STEP 4: FEATURE TYPE SEPARATION
# ------------------------------------------------------------

numeric_features = X.select_dtypes(include=["int64", "float64"]).columns
categorical_features = X.select_dtypes(include=["object"]).columns

print("\nNumeric features:", list(numeric_features))
print("Categorical features:", list(categorical_features))


# ------------------------------------------------------------
# STEP 5: PREPROCESSING (ENCODE + SCALE)
# ------------------------------------------------------------

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), numeric_features),
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
])

X_processed = preprocessor.fit_transform(X)

print("\nProcessed shape:", X_processed.shape)


# ------------------------------------------------------------
# STEP 6: ELBOW METHOD
# ------------------------------------------------------------

wcss = []

for i in range(1, 11):
    km = KMeans(n_clusters=i, random_state=2137)
    km.fit(X_processed)
    wcss.append(km.inertia_)

print("\nWCSS values:")
print(wcss)

plt.figure()
plt.plot(range(1, 11), wcss, marker='o')
plt.title("Elbow Method")
plt.xlabel("Number of Clusters (K)")
plt.ylabel("WCSS")
plt.show()


# ------------------------------------------------------------
# STEP 7: SELECT K
# ------------------------------------------------------------

optimal_k = 4
print(f"\nSelected K = {optimal_k}")


# ------------------------------------------------------------
# STEP 8: TRAIN FINAL MODEL
# ------------------------------------------------------------

kmeans = KMeans(n_clusters=optimal_k, random_state=2137)
kmeans.fit(X_processed)


# ------------------------------------------------------------
# STEP 9: CLUSTER ASSIGNMENT
# ------------------------------------------------------------

clusters = kmeans.predict(X_processed)
df["cluster"] = clusters


# ------------------------------------------------------------
# STEP 10: CLUSTER INTERPRETATION
# ------------------------------------------------------------

print("\n=== Cluster Distribution ===")
print(df["cluster"].value_counts())

print("\n=== Cluster vs Risk Score ===")
print(df.groupby("cluster")["risk_score"].mean())

print("\n=== Cluster vs CVSS ===")
print(df.groupby("cluster")["cvss_score"].mean())

print("\n=== Cluster vs Exploited ===")
print(df.groupby("cluster")["exploited_flag"].mean())


# ------------------------------------------------------------
# STEP 11: SAVE MODEL + PREPROCESSOR
# ------------------------------------------------------------

joblib.dump(kmeans, os.path.join(MODELS_DIR, "clustering_model.joblib"))
joblib.dump(preprocessor, os.path.join(MODELS_DIR, "clustering_preprocessor.joblib"))
joblib.dump(X.columns.tolist(), os.path.join(MODELS_DIR, "clustering_features.joblib"))

print("\nClustering model saved.")