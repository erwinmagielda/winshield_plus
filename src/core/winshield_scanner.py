"""
WinShield+ scanner.

Coordinates PowerShell collectors, correlates installed Windows updates with
MSRC CVRF data, resolves supersedence, and exports a runtime scan for downstream
risk prioritisation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import (  # noqa: E402
    print_error,
    print_info,
    print_section,
    print_step,
    print_success,
    print_warning,
)
from utils.winshield_paths import (  # noqa: E402
    ensure_directory,
    get_powershell_dir,
    get_runtime_dir,
)


# ------------------------------------------------------------
# SCRIPT NAMES
# ------------------------------------------------------------

BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

POWERSHELL_DIR = get_powershell_dir()
RUNTIME_DIR = get_runtime_dir()


# ------------------------------------------------------------
# CONSOLE LIMITS
# ------------------------------------------------------------

KB_TABLE_LIMIT = 10


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean console output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def is_preserved_placeholder(path: Path) -> bool:
    """Return True if the path is a preserved repository placeholder."""

    return path.name == ".gitkeep"


def normalise_kb_id(value: Any) -> str:
    """Return a normalised KB identifier."""

    return str(value).strip().upper()


def count_cves(entry: dict[str, Any]) -> int:
    """Return the number of CVEs attached to a KB entry."""

    return len(entry.get("Cves") or [])


def format_months(entry: dict[str, Any]) -> str:
    """Return a compact MonthId display string."""

    months = entry.get("Months") or []

    if not months:
        return "-"

    return ", ".join(months)


def format_update_window(baseline: dict[str, Any]) -> str:
    """Return a compact update window from baseline MonthIds."""

    start_id = baseline.get("LcuMonthId")
    end_id = baseline.get("MsrcLatestMonthId")

    if not start_id and not end_id:
        return "-"

    if start_id == end_id or not end_id:
        return str(start_id)

    if not start_id:
        return str(end_id)

    return f"{start_id} to {end_id}"


def get_kb_status(
    kb_id: str,
    installed_kbs: set[str],
    logical_present_kbs: set[str],
    superseded_by: dict[str, list[str]],
) -> str:
    """Return the resolved status for a KB."""

    if kb_id in installed_kbs:
        return "Installed"

    if kb_id in logical_present_kbs:
        replacing_kbs = superseded_by.get(kb_id, [])

        if replacing_kbs:
            return f"Superseded by {', '.join(replacing_kbs)}"

        return "Superseded"

    return "Missing"


def get_kb_type(entry: dict[str, Any] | None) -> str:
    """Return the mapped update type for a KB."""

    if not entry:
        return "Unmapped"

    return entry.get("UpdateType") or "Mapped"


# ------------------------------------------------------------
# RUNTIME CLEANUP
# ------------------------------------------------------------

def clear_runtime_directory() -> int:
    """
    Clear existing runtime artefacts before starting a new scan.

    Preserves .gitkeep so the runtime directory remains tracked by Git.
    """

    ensure_directory(RUNTIME_DIR)

    removed_count = 0

    for item in RUNTIME_DIR.iterdir():
        if is_preserved_placeholder(item):
            continue

        if item.is_dir():
            shutil.rmtree(item)
            removed_count += 1
            continue

        item.unlink()
        removed_count += 1

    print_success(f"Runtime directory ready: {relative_path(RUNTIME_DIR)}")

    return removed_count


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

    if not script_path.is_file():
        raise RuntimeError(f"PowerShell script missing: {relative_path(script_path)}")

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
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"{script_name} returned unexpected JSON structure")

    return data


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

    return [
        items[index:index + size]
        for index in range(0, len(items), size)
    ]


def format_month_range(month_ids: list[str]) -> str:
    """Return a compact display value for a MonthId range."""

    if not month_ids:
        return "-"

    if len(month_ids) == 1:
        return month_ids[0]

    return f"{month_ids[0]} to {month_ids[-1]}"


# ------------------------------------------------------------
# KB ENTRY MERGING
# ------------------------------------------------------------

def merge_kb_entries(
    existing: dict[str, dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> None:
    """Merge MSRC adapter KB entries into an indexed KB map."""

    for entry in incoming:
        kb_id = normalise_kb_id(entry.get("KB"))

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


def finalise_kb_entries(kb_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort and normalise merged KB entries before analysis."""

    for entry in kb_entries:
        entry["KB"] = normalise_kb_id(entry.get("KB"))
        entry["Months"] = sorted(set(entry.get("Months") or []))
        entry["Cves"] = sorted(set(entry.get("Cves") or []))
        entry["Supersedes"] = sorted(
            normalise_kb_id(kb)
            for kb in set(entry.get("Supersedes") or [])
            if normalise_kb_id(kb)
        )
        entry["UpdateType"] = "Superseding" if entry["Supersedes"] else "Standalone"

    return sorted(kb_entries, key=lambda item: item["KB"])


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
        kb_id = normalise_kb_id(entry.get("KB"))

        if not kb_id:
            continue

        for superseded_kb in entry.get("Supersedes") or []:
            supersedes_map.setdefault(kb_id, set()).add(normalise_kb_id(superseded_kb))

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

def build_kb_rows(
    kb_entries: list[dict[str, Any]],
    installed_kbs: set[str],
    logical_present_kbs: set[str],
    superseded_by: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Build compact mapped KB rows for console display."""

    rows: list[dict[str, Any]] = []

    for entry in sorted(kb_entries, key=lambda item: item.get("KB", "")):
        kb_id = normalise_kb_id(entry.get("KB"))

        if not kb_id:
            continue

        rows.append(
            {
                "kb_id": kb_id,
                "type": get_kb_type(entry),
                "status": get_kb_status(
                    kb_id=kb_id,
                    installed_kbs=installed_kbs,
                    logical_present_kbs=logical_present_kbs,
                    superseded_by=superseded_by,
                ),
                "months": format_months(entry),
                "cve_count": count_cves(entry),
            }
        )

    return rows


def print_kb_summary_table(rows: list[dict[str, Any]]) -> None:
    """Print a compact KB correlation table without expanding every CVE."""

    print_section("KB Correlation")

    if not rows:
        print_warning("No mapped KB rows available")
        return

    print(
        f"{'KB':<12} "
        f"{'Type':<12} "
        f"{'Status':<28} "
        f"{'Months':<18} "
        f"{'CVEs':>5}"
    )
    print("-" * 82)

    for row in rows[:KB_TABLE_LIMIT]:
        print(
            f"{row['kb_id']:<12} "
            f"{row['type']:<12} "
            f"{row['status']:<28} "
            f"{row['months']:<18} "
            f"{row['cve_count']:>5}"
        )

    remaining_rows = len(rows) - KB_TABLE_LIMIT

    if remaining_rows > 0:
        print_info(f"Additional mapped KB rows hidden: {remaining_rows}")
        print_info("Full KB/CVE details are saved in the runtime JSON")


# ------------------------------------------------------------
# RUNTIME EXPORT
# ------------------------------------------------------------

def export_runtime_scan(scan_result: dict[str, Any]) -> Path:
    """Write runtime scan output to the data/runtime directory."""

    ensure_directory(RUNTIME_DIR)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    runtime_scan_path = RUNTIME_DIR / f"scan_{timestamp}.json"

    with runtime_scan_path.open("w", encoding="utf-8") as file:
        json.dump(scan_result, file, indent=2)

    return runtime_scan_path


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ system scan workflow."""

    try:
        print_section("Runtime Preparation")
        clear_runtime_directory()

        print_section("Baseline")
        print_step("Collecting OS baseline")
        baseline = run_powershell_script(BASELINE_SCRIPT)

        product_name_hint = baseline.get("ProductNameHint")
        if not product_name_hint:
            print_error("ProductNameHint could not be resolved")
            return 1

        print_success(
            f"OS: {baseline.get('OsName')} "
            f"{baseline.get('DisplayVersion')} "
            f"({baseline.get('Build')})"
        )
        print_success(f"Product: {product_name_hint}")
        print_info(f"Update window: {format_update_window(baseline)}")

        print_section("Inventory")
        print_step("Collecting installed KB inventory")
        inventory = run_powershell_script(INVENTORY_SCRIPT)
        installed_kbs = {
            normalise_kb_id(kb)
            for kb in inventory.get("AllInstalledKbs") or []
            if normalise_kb_id(kb)
        }

        print_success(f"Installed KBs: {len(installed_kbs)}")

        print_section("MSRC Correlation")
        month_ids = build_month_ids_from_lcu(baseline)
        month_chunks = chunk_list(month_ids, 3)

        print_step("Querying MSRC CVRF data")
        print_success(f"Month range: {format_month_range(month_ids)}")

        merged_entries: dict[str, dict[str, Any]] = {}
        months_with_entries: list[str] = []
        total_entries_returned = 0

        for month_chunk in month_chunks:
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
            total_entries_returned += len(entries)

            if entries:
                months_with_entries.extend(month_chunk)
                merge_kb_entries(merged_entries, entries)

        if not merged_entries:
            print_warning("No KB data returned from MSRC")
            return 0

        kb_entries = finalise_kb_entries(list(merged_entries.values()))
        print_success(f"KB entries mapped: {len(kb_entries)}")

        print_section("Supersedence")
        print_step("Resolving logical KB presence")
        logical_present_kbs, superseded_by = compute_supersedence(
            kb_entries=kb_entries,
            installed_kbs=installed_kbs,
        )
        print_success(f"Installed KBs: {len(installed_kbs)}")
        print_success(f"Logical present KBs: {len(logical_present_kbs)}")
        print_success(f"Superseded KB mappings: {len(superseded_by)}")

        expected_kbs = {entry["KB"] for entry in kb_entries}
        missing_kbs = sorted(expected_kbs - logical_present_kbs)

        print_section("Scan Summary")
        print_success(f"Expected KBs: {len(expected_kbs)}")
        print_success(f"Installed or superseded KBs: {len(expected_kbs - set(missing_kbs))}")

        if missing_kbs:
            print_warning(f"Missing KBs: {len(missing_kbs)}")
        else:
            print_success("Missing KBs: 0")

        kb_rows = build_kb_rows(
            kb_entries=kb_entries,
            installed_kbs=installed_kbs,
            logical_present_kbs=logical_present_kbs,
            superseded_by=superseded_by,
        )

        print_kb_summary_table(kb_rows)

        scan_result = {
            "Baseline": baseline,
            "InstalledKbs": sorted(installed_kbs),
            "MonthsRequested": month_ids,
            "MonthsWithEntries": sorted(set(months_with_entries)),
            "RawKbEntriesReturned": total_entries_returned,
            "KbEntries": kb_entries,
            "MissingKbs": missing_kbs,
        }

        runtime_scan_path = export_runtime_scan(scan_result)

        print_section("Export")
        print_success(f"Runtime scan saved: {relative_path(runtime_scan_path)}")

        print()
        print_success("Scan System completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Scan System cancelled")
        return 130

    except Exception as exc:
        print_error(f"Scan System failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())