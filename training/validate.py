import csv
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_CSV = os.path.join(BASE_DIR, "data", "labelled_dataset.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "validated_dataset.csv")


def is_valid_cve(row):
    cve = row.get("cve_id", "")
    return cve.startswith("CVE-")


def has_complete_enrichment(row):
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


rows = []
seen = set()  # For deduplication (host_id, cve_id)

with open(INPUT_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:

        # Keep only real CVEs
        if not is_valid_cve(row):
            continue

        # Drop incomplete enrichment
        if not has_complete_enrichment(row):
            continue

        # Remove true duplicates
        key = (row.get("host_id"), row.get("cve_id"))
        if key in seen:
            continue

        seen.add(key)
        rows.append(row)


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