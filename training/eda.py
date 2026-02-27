import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_CSV = os.path.join(BASE_DIR, "data", "validated_dataset.csv")

df = pd.read_csv(INPUT_CSV)

print("Dataset shape:", df.shape)
print("\nColumn types:\n", df.dtypes)
print("\nMissing values:\n", df.isnull().sum())

# 1. Priority distribution 
plt.figure()
df["priority_label"].value_counts().plot(kind="bar")
plt.title("Priority Label Distribution")
plt.xlabel("Priority")
plt.ylabel("Count")
plt.show()

# 2. Risk score distribution 
plt.figure()
sns.histplot(df["risk_score"], bins=30)
plt.title("Risk Score Distribution")
plt.show()

# 3. Numeric feature correlation
numeric_df = df.select_dtypes(include=["int64", "float64"])
plt.figure()
sns.heatmap(numeric_df.corr(), annot=True, fmt=".2f")
plt.title("Correlation Matrix (Numeric Features)")
plt.show()

# 4. CVSS vs Risk Score
if "cvss_score" in df.columns:
    plt.figure()
    sns.scatterplot(x=df["cvss_score"], y=df["risk_score"])
    plt.title("CVSS vs Risk Score")
    plt.show()