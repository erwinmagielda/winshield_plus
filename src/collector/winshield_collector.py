import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from typing import Dict, List, Set


# ------------------------------------------------------------
# PATH RESOLUTION (DEV + PYINSTALLER SAFE)
# ------------------------------------------------------------

if getattr(sys, "frozen", False):
    BASE_PATH = os.path.dirname(sys.executable)
else:
    BASE_PATH = os.path.dirname(os.path.abspath(__file__))

POWERSHELL_DIR = os.path.join(BASE_PATH, "powershell")
RESULTS_DIR = os.path.join(BASE_PATH, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)


BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"


# ------------------------------------------------------------
# POWERSHELL EXECUTION
# ------------------------------------------------------------

def run_powershell_script(script_name: str, extra_args: List[str] | None = None) -> dict:
    args = extra_args or []
    script_path = os.path.join(POWERSHELL_DIR, script_name)

    if not os.path.exists(script_path):
        raise FileNotFoundError(f"Missing PowerShell script: {script_path}")

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", script_path,
        *args,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed:\n{result.stderr.strip()}"
        )

    output = result.stdout.strip()
    if not output:
        raise RuntimeError(f"{script_name} returned empty output")

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{script_name} returned invalid JSON"
        ) from exc


# ------------------------------------------------------------
# MONTH RANGE BUILDER
# ------------------------------------------------------------

def build_month_ids_from_lcu(baseline: dict) -> List[str]:
    start_id = baseline.get("LcuMonthId")
    end_id = baseline.get("MsrcLatestMonthId")

    if not start_id or not end_id:
        return []

    start = datetime.strptime(start_id, "%Y-%b").replace(day=1, tzinfo=UTC)
    end = datetime.strptime(end_id, "%Y-%b").replace(day=1, tzinfo=UTC)

    month_ids = []
    year, month = start.year, start.month

    while True:
        current = datetime(year, month, 1, tzinfo=UTC)
        if current > end:
            break

        month_ids.append(current.strftime("%Y-%b"))

        if current == end:
            break

        month += 1
        if month == 13:
            month = 1
            year += 1

    return month_ids


# ------------------------------------------------------------
# MERGE KB ENTRIES
# ------------------------------------------------------------

def merge_kb_entries(existing: Dict[str, dict], incoming: List[dict]) -> None:
    for entry in incoming:
        kb_id = entry.get("KB")
        if not kb_id:
            continue

        target = existing.setdefault(
            kb_id,
            {"KB": kb_id, "Months": [], "Cves": [], "Supersedes": []},
        )

        for field in ("Months", "Cves", "Supersedes"):
            for value in entry.get(field) or []:
                if value and value not in target[field]:
                    target[field].append(value)


# ------------------------------------------------------------
# COMPUTE MISSING
# ------------------------------------------------------------

def compute_missing(kb_entries: List[dict], installed_kbs: Set[str]) -> List[str]:
    expected = {e["KB"] for e in kb_entries}
    return sorted(expected - installed_kbs)


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main() -> None:
    try:
        # COLLECT BASELINE + INVENTORY
        baseline = run_powershell_script(BASELINE_SCRIPT)
        inventory = run_powershell_script(INVENTORY_SCRIPT)

        installed_kbs = set(inventory.get("AllInstalledKbs") or [])

        # BUILD MONTH RANGE
        month_ids = build_month_ids_from_lcu(baseline)
        product_name_hint = baseline.get("ProductNameHint")

        if not product_name_hint:
            raise RuntimeError("ProductNameHint could not be resolved")

        # QUERY MSRC
        merged: Dict[str, dict] = {}

        for month in month_ids:
            msrc_data = run_powershell_script(
                ADAPTER_SCRIPT,
                extra_args=[
                    "-MonthIds", month,
                    "-ProductNameHint", product_name_hint,
                ],
            )

            merge_kb_entries(merged, msrc_data.get("KbEntries") or [])

        kb_entries = list(merged.values())
        missing = compute_missing(kb_entries, installed_kbs)

        # SAVE RESULT
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(RESULTS_DIR, f"scan_{timestamp}.json")

        result = {
            "Baseline": baseline,
            "InstalledKbs": sorted(installed_kbs),
            "MonthsRequested": month_ids,
            "KbEntries": kb_entries,
            "MissingKbs": missing,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        print("\nScan complete.")
        print(f"Saved to: {output_path}")
        print("Please email this file to: em1253@live.mdx.ac.uk")

    except Exception as e:
        print("\nScan failed.")
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
