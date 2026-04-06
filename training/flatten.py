"""
WinShield Flatten

Converts WinShield scan JSON files into a flat CVE dataset
used by the enrichment and ML pipeline.

Modes
-----
training : processes all scans from data/scans
runtime  : processes only the newest scan from data/runtime
"""

import os
import json
import argparse
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

DATASET_OUTPUT = os.path.join(DATASET_DIR, "flattened_dataset.csv")
RUNTIME_OUTPUT = os.path.join(RUNTIME_DIR, "flattened_runtime.csv")

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(RUNTIME_DIR, exist_ok=True)


# ------------------------------------------------------------
# GET LATEST RUNTIME SCAN
# ------------------------------------------------------------

def get_latest_runtime_scan():

    scans = [
        os.path.join(RUNTIME_DIR, f)
        for f in os.listdir(RUNTIME_DIR)
        if f.startswith("scan_") and f.endswith(".json")
    ]

    if not scans:
        raise RuntimeError("No runtime scan files found.")

    return max(scans, key=os.path.getmtime)


# ------------------------------------------------------------
# LOAD SCANS
# ------------------------------------------------------------

def load_scan_paths(mode):

    if mode == "training":

        scans = [
            os.path.join(SCANS_DIR, f)
            for f in os.listdir(SCANS_DIR)
            if f.endswith(".json")
        ]

    elif mode == "runtime":

        scans = [get_latest_runtime_scan()]

    else:
        raise ValueError("Invalid mode")

    if not scans:
        raise RuntimeError(f"No scan files found for mode: {mode}")

    return scans


# ------------------------------------------------------------
# FLATTEN
# ------------------------------------------------------------

def flatten_scans(mode):

    scan_files = load_scan_paths(mode)

    rows = []

    for scan_path in scan_files:

        with open(scan_path, "r", encoding="utf-8") as f:
            scan = json.load(f)

        kb_entries = scan.get("KbEntries", [])

        for patch in kb_entries:

            kb = patch.get("KB")
            months = patch.get("Months", [])
            cves = patch.get("Cves", [])

            # skip invalid entries
            if not kb or not cves or not months:
                continue

            for cve in cves:
                for month in months:
                    rows.append({
                        "kb_id": kb,
                        "cve_id": cve,
                        "month": month
                    })

    if not rows:
        raise RuntimeError("No rows generated during flattening.")

    df = pd.DataFrame(rows)

    output_path = DATASET_OUTPUT if mode == "training" else RUNTIME_OUTPUT

    df.to_csv(output_path, index=False)

    print(f"[+] Flatten complete ({mode})")
    print(f"[+] Output: {output_path}")
    print(f"[+] Rows: {len(df)}")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":
    flatten_scans(args.mode)