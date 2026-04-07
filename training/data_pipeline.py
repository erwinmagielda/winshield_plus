import os
import json
import csv
import argparse
import subprocess
from datetime import datetime, UTC
import pandas as pd


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

SCANS_DIR = os.path.join(DATA_DIR, "scans")
RUNTIME_DIR = os.path.join(DATA_DIR, "runtime")
DATASET_DIR = os.path.join(DATA_DIR, "dataset")

POWERSHELL_SCRIPT = os.path.join(BASE_DIR, "src", "powershell", "winshield_metadata.ps1")

os.makedirs(RUNTIME_DIR, exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)


# ------------------------------------------------------------
# STEP 1: FLATTEN
# ------------------------------------------------------------

def flatten(mode):

    def get_latest_runtime_scan():
        scans = [
            os.path.join(RUNTIME_DIR, f)
            for f in os.listdir(RUNTIME_DIR)
            if f.startswith("scan_") and f.endswith(".json")
        ]
        return max(scans, key=os.path.getmtime)

    if mode == "training":
        scan_files = [
            os.path.join(SCANS_DIR, f)
            for f in os.listdir(SCANS_DIR)
            if f.endswith(".json")
        ]
        output = os.path.join(DATASET_DIR, "flattened_dataset.csv")
    else:
        scan_files = [get_latest_runtime_scan()]
        output = os.path.join(RUNTIME_DIR, "flattened_runtime.csv")

    rows = []

    for path in scan_files:
        with open(path, "r", encoding="utf-8") as f:
            scan = json.load(f)

        for patch in scan.get("KbEntries", []):
            kb = patch.get("KB")
            months = patch.get("Months", [])
            cves = patch.get("Cves", [])

            if not kb or not months or not cves:
                continue

            for cve in cves:
                for m in months:
                    rows.append({
                        "kb_id": kb,
                        "cve_id": cve,
                        "month": m
                    })

    df = pd.DataFrame(rows)
    df.to_csv(output, index=False)

    print(f"[+] Flatten saved to {output}")
    return output


# ------------------------------------------------------------
# STEP 2: ENRICH
# ------------------------------------------------------------

def parse_cvss(vector):
    if not vector:
        return {}

    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

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


def enrich(input_csv, mode):

    output = input_csv.replace("flattened", "enriched")

    df = pd.read_csv(input_csv)

    months = df["month"].dropna().unique()
    month_ids = ",".join(months)

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", POWERSHELL_SCRIPT,
            "-MonthIds", month_ids
        ],
        capture_output=True,
        text=True
    )

    metadata = json.loads(result.stdout)

    today = datetime.now(UTC)

    enriched = []

    for _, row in df.iterrows():

        meta = metadata.get(row["cve_id"], {})

        patch_age = None
        pub = meta.get("PublishedDate")

        if pub:
            try:
                dt = datetime.fromisoformat(pub.replace("Z", "")).replace(tzinfo=UTC)
                patch_age = (today - dt).days
            except:
                pass

        enriched.append({
            **row,
            "cvss_score": meta.get("BaseScore"),
            "severity": meta.get("Severity"),
            "published_date": pub,
            "patch_age_days": patch_age,
            "exploitation": meta.get("Exploitation"),
            **parse_cvss(meta.get("Vector"))
        })

    pd.DataFrame(enriched).to_csv(output, index=False)

    print(f"[+] Enrich saved to {output}")
    return output


# ------------------------------------------------------------
# STEP 3: LABEL (TRAINING ONLY)
# ------------------------------------------------------------

def label(input_csv):

    df = pd.read_csv(input_csv)

    def compute(row):
        score = float(row.get("cvss_score") or 0)

        if "Exploited:Yes" in str(row.get("exploitation")):
            score += 2

        if row.get("attack_vector") == "N":
            score += 1

        age = row.get("patch_age_days")
        if pd.notna(age):
            score += float(age) / 60

        if score >= 9:
            label = "High"
        elif score >= 6:
            label = "Medium"
        else:
            label = "Low"

        return round(score, 2), label

    df[["risk_score", "priority_label"]] = df.apply(
        lambda r: pd.Series(compute(r)), axis=1
    )

    output = input_csv.replace("enriched", "labelled")
    df.to_csv(output, index=False)

    print(f"[+] Label saved to {output}")
    return output


# ------------------------------------------------------------
# STEP 4: VALIDATE
# ------------------------------------------------------------

def validate(input_csv, mode):

    df = pd.read_csv(input_csv)

    df = df[df["cve_id"].str.startswith("CVE-")]

    df = df.dropna(subset=["cvss_score", "attack_vector"])

    output = input_csv.replace(
        "labelled" if mode == "training" else "enriched",
        "validated"
    )

    df.to_csv(output, index=False)

    print(f"[+] Validate saved to {output}")
    return output


# ------------------------------------------------------------
# MAIN PIPELINE
# ------------------------------------------------------------

def run():

    print(f"\n=== Data Pipeline ({args.mode}) ===\n")

    f = flatten(args.mode)
    f = enrich(f, args.mode)

    if args.mode == "training":
        f = label(f)

    f = validate(f, args.mode)

    print("\n=== Pipeline Complete ===\n")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    run()