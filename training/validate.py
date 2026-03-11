import csv
import os
import argparse

# ------------------------------------------------------------
# MODE
# ------------------------------------------------------------

parser = argparse.ArgumentParser()
parser.add_argument("--mode", default="training", choices=["training", "runtime"])
args = parser.parse_args()

# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

if args.mode == "runtime":
    WORK_DIR = os.path.join(DATA_DIR, "runtime")
    INPUT_CSV = os.path.join(WORK_DIR, "enriched_runtime.csv")
    OUTPUT_CSV = os.path.join(WORK_DIR, "validated_runtime.csv")
else:
    WORK_DIR = os.path.join(DATA_DIR, "dataset")
    INPUT_CSV = os.path.join(WORK_DIR, "labelled_dataset.csv")
    OUTPUT_CSV = os.path.join(WORK_DIR, "validated_dataset.csv")

os.makedirs(WORK_DIR, exist_ok=True)

# ------------------------------------------------------------
# VALIDATION FUNCTIONS
# ------------------------------------------------------------

def is_valid_cve(row):
    cve = row.get("cve_id", "")
    return cve.startswith("CVE-")


def has_complete_enrichment(row):

    if args.mode == "runtime":

        required_fields = [
            "cvss_score",
            "attack_vector",
            "privileges_required"
        ]

    else:

        required_fields = [
            "cvss_score",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "scope",
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
            "published_date",
            "exploited_flag"
        ]

    for field in required_fields:

        value = row.get(field)

        if value is None or value == "":
            return False

    return True


# ------------------------------------------------------------
# VALIDATE DATA
# ------------------------------------------------------------

rows = []
seen = set()

with open(INPUT_CSV, newline="", encoding="utf-8") as f:

    reader = csv.DictReader(f)

    for row in reader:

        if not is_valid_cve(row):
            continue

        if not has_complete_enrichment(row):
            continue

        key = (row.get("host_id"), row.get("cve_id"))

        if key in seen:
            continue

        seen.add(key)
        rows.append(row)

# ------------------------------------------------------------
# WRITE OUTPUT
# ------------------------------------------------------------

if not rows:
    print("No valid rows after validation.")
    exit()

fieldnames = list(rows[0].keys())

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:

    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Validated dataset written to: {OUTPUT_CSV}")
print(f"Rows kept: {len(rows)}")