"""
WinShield Flatten

Converts WinShield scan JSON files into a flat CVE dataset
used by the enrichment and ML pipeline.

Modes
-----
training : processes all dataset scans
runtime  : processes only the newest runtime scan
"""

import os
import json
import argparse
import pandas as pd


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_DIR = os.path.join(BASE_DIR, "data", "dataset")
RUNTIME_DIR = os.path.join(BASE_DIR, "data", "runtime")

DATASET_OUTPUT = os.path.join(DATASET_DIR, "flattened_dataset.csv")
RUNTIME_OUTPUT = os.path.join(RUNTIME_DIR, "flattened_runtime.csv")


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
            os.path.join(DATASET_DIR, f)
            for f in os.listdir(DATASET_DIR)
            if f.endswith(".json")
        ]

    elif mode == "runtime":

        scans = [get_latest_runtime_scan()]

    else:
        raise ValueError("Invalid mode")

    if not scans:
        raise RuntimeError("No scan files found.")

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

            for cve in cves:

                for month in months:

                    rows.append({
                        "kb_id": kb,
                        "cve_id": cve,
                        "month": month
                    })

    df = pd.DataFrame(rows)

    if mode == "training":
        output_path = DATASET_OUTPUT
    else:
        output_path = RUNTIME_OUTPUT

    df.to_csv(output_path, index=False)

    print(f"Flattened data written to: {output_path}")
    print(f"Total rows: {len(df)}")


# ------------------------------------------------------------
# ENTRYPOINT
# ------------------------------------------------------------

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)

    args = parser.parse_args()

    flatten_scans(args.mode)