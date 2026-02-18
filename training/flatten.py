import json
import os
import csv

# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw_scans")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "flattened_dataset.csv")

# ------------------------------------------------------------
# FLATTEN LOGIC
# ------------------------------------------------------------

rows = []

for filename in os.listdir(RAW_DIR):
    if not filename.endswith(".json"):
        continue

    file_path = os.path.join(RAW_DIR, filename)

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    host_id = os.path.splitext(filename)[0]

    baseline = data.get("Baseline", {})
    os_build = baseline.get("Build", "")

    missing_kbs = set(data.get("MissingKbs", []))
    kb_entries = data.get("KbEntries", [])

    kb_lookup = {entry["KB"]: entry for entry in kb_entries if "KB" in entry}

    for kb in missing_kbs:
        entry = kb_lookup.get(kb)
        if not entry:
            continue

        months = entry.get("Months", [])
        month = months[0] if months else ""

        for cve in entry.get("Cves", []):
            rows.append([
                host_id,
                os_build,
                kb,
                cve,
                month
            ])

# ------------------------------------------------------------
# WRITE CSV
# ------------------------------------------------------------

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)

    writer.writerow([
        "host_id",
        "os_build",
        "kb_id",
        "cve_id",
        "month"
    ])

    writer.writerows(rows)

print(f"Flattened dataset written to: {OUTPUT_CSV}")
print(f"Total rows: {len(rows)}")