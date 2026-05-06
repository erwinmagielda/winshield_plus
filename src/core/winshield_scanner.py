"""
WinShield+ scanner.

Coordinates PowerShell collectors, correlates installed Windows updates
with MSRC CVRF data, resolves supersedence, and exports a runtime scan
for downstream prioritisation.
"""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# SCRIPT NAMES
# ------------------------------------------------------------

BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parents[1]

POWERSHELL_DIR = ROOT_DIR / "src" / "powershell"
DATA_DIR = ROOT_DIR / "data"
RUNTIME_DIR = DATA_DIR / "runtime"

RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# POWERSHELL EXECUTION
# ------------------------------------------------------------

def run_powershell_script(
    script_name: str,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Execute a PowerShell script and return parsed JSON output."""

    script_path = POWERSHELL_DIR / script_name
    args = extra_args or []

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        *args,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip())
        raise RuntimeError(f"{script_name} execution failed")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"{script_name} returned no output")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc


# ------------------------------------------------------------
# MONTH RANGE HANDLING
# ------------------------------------------------------------

def build_month_ids_from_lcu(
    baseline: dict[str, Any],
    max_months: int = 48,
) -> list[str]:
    """Build a MonthId range from installed LCU month to latest MSRC month."""

    if not baseline.get("IsAdmin"):
        raise RuntimeError("Baseline collected without administrative privileges")

    start_id = baseline.get("LcuMonthId")
    if not start_id:
        raise RuntimeError("Baseline did not provide LcuMonthId")

    end_id = baseline.get("MsrcLatestMonthId")
    end_date = (
        datetime.strptime(end_id, "%Y-%b").replace(day=1, tzinfo=UTC)
        if end_id
        else datetime.now(UTC).replace(day=1)
    )

    start_date = datetime.strptime(start_id, "%Y-%b").replace(day=1, tzinfo=UTC)
    if start_date > end_date:
        start_date = end_date

    month_ids: list[str] = []
    year = start_date.year
    month = start_date.month

    while True:
        current_date = datetime(year, month, 1, tzinfo=UTC)

        if current_date > end_date or len(month_ids) >= max_months:
            break

        month_ids.append(current_date.strftime("%Y-%b"))

        if current_date == end_date:
            break

        month += 1
        if month == 13:
            month = 1
            year += 1

    return month_ids


def chunk_list(items: list[str], size: int) -> list[list[str]]:
    """Split a list into fixed-size chunks."""

    return [items[index:index + size] for index in range(0, len(items), size)]


# ------------------------------------------------------------
# KB ENTRY MERGING
# ------------------------------------------------------------

def merge_kb_entries(
    existing: dict[str, dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> None:
    """Merge MSRC adapter KB entries into an indexed KB map."""

    for entry in incoming:
        kb_id = entry.get("KB")
        if not kb_id:
            continue

        target = existing.setdefault(
            kb_id,
            {
                "KB": kb_id,
                "Months": [],
                "Cves": [],
                "Supersedes": [],
            },
        )

        for field in ("Months", "Cves", "Supersedes"):
            for value in entry.get(field) or []:
                if value and value not in target[field]:
                    target[field].append(value)


# ------------------------------------------------------------
# SUPERSEDENCE RESOLUTION
# ------------------------------------------------------------

def compute_supersedence(
    kb_entries: list[dict[str, Any]],
    installed_kbs: set[str],
) -> tuple[set[str], dict[str, list[str]]]:
    """Expand logical KB presence using supersedence relationships."""

    supersedes_map: dict[str, set[str]] = {}

    for entry in kb_entries:
        kb_id = entry.get("KB")
        if not kb_id:
            continue

        for superseded_kb in entry.get("Supersedes") or []:
            supersedes_map.setdefault(kb_id, set()).add(superseded_kb)

    logical_present_kbs = set(installed_kbs)
    superseded_by: dict[str, set[str]] = {}

    for root_kb in installed_kbs:
        stack = [root_kb]
        seen = {root_kb}

        while stack:
            current_kb = stack.pop()

            for superseded_kb in supersedes_map.get(current_kb, set()):
                logical_present_kbs.add(superseded_kb)
                superseded_by.setdefault(superseded_kb, set()).add(root_kb)

                if superseded_kb not in seen:
                    seen.add(superseded_kb)
                    stack.append(superseded_kb)

    return logical_present_kbs, {
        kb_id: sorted(replacing_kbs)
        for kb_id, replacing_kbs in superseded_by.items()
    }


# ------------------------------------------------------------
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_kb_table(
    kb_entries: list[dict[str, Any]],
    installed_kbs: set[str],
    logical_present_kbs: set[str],
    superseded_by: dict[str, list[str]],
) -> None:
    """Print KB correlation results in a readable console table."""

    kb_index: dict[str, dict[str, Any]] = {
        entry["KB"]: entry
        for entry in kb_entries
        if entry.get("KB")
    }

    all_kbs = sorted(set(kb_index) | installed_kbs | logical_present_kbs)

    col_kb_width = 11
    col_type_width = 12
    col_status_width = 40
    col_months_width = 20

    print("=== Correlation ===")
    print(
        f"{'KB':<{col_kb_width}} "
        f"{'Type':<{col_type_width}} "
        f"{'Status':<{col_status_width}} "
        f"{'Months':<{col_months_width}} "
        f"CVEs"
    )
    print("-" * 110)

    for kb_id in all_kbs:
        entry = kb_index.get(
            kb_id,
            {
                "KB": kb_id,
                "Months": [],
                "Cves": [],
                "Supersedes": [],
                "UpdateType": "Unmapped",
            },
        )

        months = list(entry.get("Months") or [])
        cves = list(entry.get("Cves") or [])
        update_type = entry.get("UpdateType", "")

        if kb_id in installed_kbs:
            status = "Installed"
        elif kb_id in logical_present_kbs:
            replacing_kbs = superseded_by.get(kb_id, [])
            status = (
                f"Superseded ({', '.join(replacing_kbs)})"
                if replacing_kbs
                else "Superseded"
            )
        else:
            status = "Missing"

        if not months:
            months = [""]
        if not cves:
            cves = [""]

        row_height = max(len(months), len(cves))

        for index in range(row_height):
            kb_cell = kb_id if index == 0 else ""
            type_cell = update_type if index == 0 else ""
            status_cell = status if index == 0 else ""
            month_cell = months[index] if index < len(months) else ""
            cve_cell = cves[index] if index < len(cves) else ""

            print(
                f"{kb_cell:<{col_kb_width}} "
                f"{type_cell:<{col_type_width}} "
                f"{status_cell:<{col_status_width}} "
                f"{month_cell:<{col_months_width}} "
                f"{cve_cell}"
            )

        print("-" * 110)


def print_missing_kbs(
    missing_kbs: list[str],
    kb_entries: list[dict[str, Any]],
) -> None:
    """Print missing KB summary with associated months and CVE counts."""

    print("=== Missing ===")

    if not missing_kbs:
        print("None")
        return

    for kb_id in missing_kbs:
        entry = next((item for item in kb_entries if item.get("KB") == kb_id), {})
        months = ", ".join(entry.get("Months") or [])
        cve_count = len(entry.get("Cves") or [])

        print(f"- {kb_id} | Months: {months}, CVEs: {cve_count}")


# ------------------------------------------------------------
# RUNTIME EXPORT
# ------------------------------------------------------------

def export_runtime_scan(scan_result: dict[str, Any]) -> Path:
    """Write runtime scan output to the data/runtime directory."""

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    runtime_scan_path = RUNTIME_DIR / f"scan_{timestamp}.json"

    with runtime_scan_path.open("w", encoding="utf-8") as file:
        json.dump(scan_result, file, indent=2)

    return runtime_scan_path


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    print("[*] Collecting baseline...")
    baseline = run_powershell_script(BASELINE_SCRIPT)

    product_name_hint = baseline.get("ProductNameHint")
    if not product_name_hint:
        print("[!] Failed to resolve ProductNameHint")
        return 1

    print(
        f"[+] {baseline.get('OsName')} "
        f"{baseline.get('DisplayVersion')} "
        f"({baseline.get('Build')})"
    )
    print(f"[+] Product: {product_name_hint}")
    print()

    print("[*] Collecting inventory...")
    inventory = run_powershell_script(INVENTORY_SCRIPT)
    installed_kbs = set(inventory.get("AllInstalledKbs") or [])

    print(f"[+] Installed KBs: {len(installed_kbs)}")
    print()

    print("[*] Building MonthId range...")
    month_ids = build_month_ids_from_lcu(baseline)

    print(f"[+] Months: {', '.join(month_ids)}")
    print()

    merged_entries: dict[str, dict[str, Any]] = {}
    months_with_entries: list[str] = []

    print("[*] Querying MSRC...")
    for month_chunk in chunk_list(month_ids, 3):
        msrc_data = run_powershell_script(
            ADAPTER_SCRIPT,
            extra_args=[
                "-MonthIds",
                ",".join(month_chunk),
                "-ProductNameHint",
                product_name_hint,
            ],
        )

        entries = msrc_data.get("KbEntries") or []
        if entries:
            months_with_entries.extend(month_chunk)
            merge_kb_entries(merged_entries, entries)

    if not merged_entries:
        print("[!] No KB data returned")
        return 0

    kb_entries = list(merged_entries.values())

    for entry in kb_entries:
        entry["Months"] = sorted(set(entry.get("Months") or []))
        entry["Cves"] = sorted(set(entry.get("Cves") or []))
        entry["Supersedes"] = sorted(set(entry.get("Supersedes") or []))
        entry["UpdateType"] = "Superseding" if entry["Supersedes"] else "Standalone"

    logical_present_kbs, superseded_by = compute_supersedence(
        kb_entries=kb_entries,
        installed_kbs=installed_kbs,
    )

    expected_kbs = {entry["KB"] for entry in kb_entries}
    missing_kbs = sorted(expected_kbs - logical_present_kbs)

    print()
    print("=== Summary ===")
    print(f"Expected KBs: {len(expected_kbs)}")
    print(f"Missing KBs:  {len(missing_kbs)}")
    print()

    print_kb_table(
        kb_entries=kb_entries,
        installed_kbs=installed_kbs,
        logical_present_kbs=logical_present_kbs,
        superseded_by=superseded_by,
    )

    print()
    print_missing_kbs(
        missing_kbs=missing_kbs,
        kb_entries=kb_entries,
    )

    scan_result = {
        "Baseline": baseline,
        "InstalledKbs": sorted(installed_kbs),
        "MonthsRequested": month_ids,
        "MonthsWithEntries": sorted(set(months_with_entries)),
        "KbEntries": sorted(kb_entries, key=lambda item: item["KB"]),
        "MissingKbs": missing_kbs,
    }

    runtime_scan_path = export_runtime_scan(scan_result)
    print(f"[+] Runtime scan exported to {runtime_scan_path}")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())