import csv
import json
import os
import subprocess
from datetime import datetime, UTC

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_CSV = os.path.join(BASE_DIR, "data", "flattened_dataset.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "enriched_dataset.csv")
POWERSHELL_SCRIPT = os.path.join(BASE_DIR, "src", "powershell", "winshield_metadata.ps1")


def parse_cvss_vector(vector: str) -> dict:
    if not vector:
        return {}

    parts = vector.split("/")
    metrics = {}

    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value

    return {
        "attack_vector": metrics.get("AV"),
        "attack_complexity": metrics.get("AC"),
        "privileges_required": metrics.get("PR"),
        "user_interaction": metrics.get("UI"),
        "scope": metrics.get("S"),
        "confidentiality_impact": metrics.get("C"),
        "integrity_impact": metrics.get("I"),
        "availability_impact": metrics.get("A"),
    }


# ------------------------------------------------------------
# LOAD FLATTENED DATA
# ------------------------------------------------------------

rows = []
unique_months = set()

with open(INPUT_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append(row)
        unique_months.add(row["month"])

print(f"Rows: {len(rows)}")
print(f"Months queried: {len(unique_months)}")

# ------------------------------------------------------------
# FETCH METADATA FROM POWERSHELL
# ------------------------------------------------------------

cmd = [
    "powershell.exe",
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", POWERSHELL_SCRIPT,
    "-MonthIds", ",".join(unique_months)
]

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode != 0:
    raise RuntimeError(result.stderr)

cve_metadata = json.loads(result.stdout)

# ------------------------------------------------------------
# ENRICH
# ------------------------------------------------------------

today = datetime.now(UTC)
enriched_rows = []

for row in rows:
    cve = row["cve_id"]
    meta = cve_metadata.get(cve, {})

    vector_features = parse_cvss_vector(meta.get("Vector"))

    published_date = meta.get("PublishedDate")
    patch_age_days = None

    if published_date:
        try:
            pub_dt = datetime.fromisoformat(published_date.replace("Z", "")).replace(tzinfo=UTC)
            patch_age_days = (today - pub_dt).days
        except:
            pass

    enriched_row = {
        **row,
        "severity": meta.get("Severity"),
        "cvss_score": meta.get("BaseScore"),
        "published_date": published_date,
        "patch_age_days": patch_age_days,
        "exploitation": meta.get("Exploitation"),
        **vector_features
    }

    enriched_rows.append(enriched_row)

# ------------------------------------------------------------
# WRITE OUTPUT
# ------------------------------------------------------------

fieldnames = list(enriched_rows[0].keys())

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(enriched_rows)

print(f"\nEnriched dataset written to: {OUTPUT_CSV}")
