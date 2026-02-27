import csv
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_CSV = os.path.join(BASE_DIR, "data", "enriched_dataset.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "labelled_dataset.csv")


def compute_risk_score(row):
    score = 0.0

    # Base CVSS
    try:
        score += float(row["cvss_score"])
    except:
        pass

    # Exploitation bonus (binary)
    exploited_flag = 1 if "Exploited:Yes" in row.get("exploitation", "") else 0
    score += exploited_flag * 2

    # Attack vector
    av = row.get("attack_vector")
    if av == "N":
        score += 1
    elif av == "A":
        score += 0.5

    # Privileges required
    pr = row.get("privileges_required")
    if pr == "N":
        score += 1
    elif pr == "L":
        score += 0.5

    # Patch age
    try:
        age = float(row.get("patch_age_days", 0))
        score += age / 60
    except:
        pass

    return round(score, 2), exploited_flag


def assign_priority(score):
    if score >= 9:
        return "High"
    elif score >= 6:
        return "Medium"
    else:
        return "Low"


rows = []

with open(INPUT_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        risk_score, exploited_flag = compute_risk_score(row)
        priority = assign_priority(risk_score)

        # Replace raw exploitation column with clean binary feature
        row["exploited_flag"] = exploited_flag
        row.pop("exploitation", None)

        row["risk_score"] = risk_score
        row["priority_label"] = priority

        rows.append(row)


fieldnames = list(rows[0].keys())

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Labelled dataset written to: {OUTPUT_CSV}")