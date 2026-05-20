"""
WinShield+ artefact cleanup utility.

Removes generated pipeline artefacts while preserving source training scans
and repository placeholder files.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import (  # noqa: E402
    print_error,
    print_info,
    print_step,
    print_success,
    print_warning,
)
from utils.winshield_paths import (  # noqa: E402
    ensure_directory,
    get_dataset_dir,
    get_downloads_dir,
    get_logs_dir,
    get_models_dir,
    get_results_dir,
    get_runtime_dir,
    get_scan_source_dir,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCANS_DIR = get_scan_source_dir()

GENERATED_DIRS = {
    "dataset": get_dataset_dir(),
    "runtime": get_runtime_dir(),
    "logs": get_logs_dir(),
    "downloads": get_downloads_dir(),
    "models": get_models_dir(),
    "results": get_results_dir(),
}


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def is_preserved_placeholder(path: Path) -> bool:
    """Return True if the path is a preserved repository placeholder."""

    return path.name == ".gitkeep"


# ------------------------------------------------------------
# CLEANUP HELPERS
# ------------------------------------------------------------

def prepare_generated_directories() -> None:
    """Ensure all generated artefact directories exist."""

    for directory in GENERATED_DIRS.values():
        ensure_directory(directory)


def clear_directory_contents(directory: Path) -> int:
    """
    Clear generated contents from a directory.

    Preserves .gitkeep files so empty directories remain tracked by Git.
    Returns the number of removed items.
    """

    ensure_directory(directory)

    removed_count = 0

    for item in directory.iterdir():

        if is_preserved_placeholder(item):
            continue

        if item.is_dir():
            shutil.rmtree(item)
            removed_count += 1
            continue

        item.unlink()
        removed_count += 1

    return removed_count


def confirm_cleanup() -> bool:
    """Ask the operator to confirm cleanup before deleting generated files."""

    print_warning("Generated artefacts will be removed")
    print_info("Directories selected:")

    for directory in GENERATED_DIRS.values():
        print(f"    - {relative_path(directory)}")

    print()
    print_success(f"Preserved: {relative_path(SCANS_DIR)}")
    print()

    response = input("Type YES to continue: ").strip()

    return response == "YES"


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ artefact cleanup workflow."""

    print_step("Checking source training scans")

    prepare_generated_directories()

    if not SCANS_DIR.exists():
        print_error(f"Source training scans missing: {relative_path(SCANS_DIR)}")
        print_info("Cleanup stopped to avoid removing data unexpectedly")
        return 1

    print_success(f"Source training scans preserved: {relative_path(SCANS_DIR)}")
    print()

    if not confirm_cleanup():
        print()
        print_info("Clear Artefacts cancelled")
        return 0

    print()
    print_step("Clearing generated artefacts")

    removed_total = 0
    removed_by_directory: dict[str, int] = {}

    for label, directory in GENERATED_DIRS.items():
        removed_count = clear_directory_contents(directory)
        removed_by_directory[label] = removed_count
        removed_total += removed_count

    print()
    print_success(f"Removed artefacts: {removed_total}")

    for label, removed_count in removed_by_directory.items():
        print(f"    {label}: {removed_count}")

    print()
    print_success("Clear Artefacts completed")
    print_success("Source training scans preserved")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())