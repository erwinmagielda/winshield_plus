"""
WinShield+ artefact cleanup utility.

Removes generated pipeline artefacts, Python cache files, and runtime output
while preserving source training scans and repository placeholder files.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
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
    get_charts_dir,
    get_dataset_dir,
    get_downloads_dir,
    get_logs_dir,
    get_models_dir,
    get_rankings_dir,
    get_reports_dir,
    get_results_dir,
    get_runtime_dir,
    get_scan_source_dir,
    get_summaries_dir,
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
    "reports": get_reports_dir(),
    "rankings": get_rankings_dir(),
    "summaries": get_summaries_dir(),
    "charts": get_charts_dir(),
}

PLACEHOLDER_DIRS = [
    get_dataset_dir(),
    get_runtime_dir(),
    get_logs_dir(),
    get_downloads_dir(),
    get_models_dir(),
    get_results_dir(),
    get_reports_dir(),
    get_rankings_dir(),
    get_summaries_dir(),
    get_charts_dir(),
]


# ------------------------------------------------------------
# DATA MODELS
# ------------------------------------------------------------

@dataclass
class CleanupResult:
    """Store cleanup counts and skipped paths."""

    removed_count: int = 0
    skipped_locked: list[Path] = field(default_factory=list)
    skipped_other: list[Path] = field(default_factory=list)


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def is_preserved_placeholder(path: Path) -> bool:
    """Return True if the path is a preserved repository placeholder."""

    return path.name == ".gitkeep"


def is_locked_file_error(error: OSError) -> bool:
    """Return True if Windows reports that a file is currently locked."""

    return getattr(error, "winerror", None) == 32


# ------------------------------------------------------------
# DIRECTORY PREPARATION
# ------------------------------------------------------------

def prepare_generated_directories() -> None:
    """Ensure generated artefact directories exist."""

    for directory in PLACEHOLDER_DIRS:
        ensure_directory(directory)


def write_gitkeep_files() -> None:
    """Ensure .gitkeep placeholders exist in generated directories."""

    for directory in PLACEHOLDER_DIRS:
        ensure_directory(directory)

        gitkeep_path = directory / ".gitkeep"

        if not gitkeep_path.exists():
            gitkeep_path.write_text("", encoding="utf-8")


# ------------------------------------------------------------
# CLEANUP HELPERS
# ------------------------------------------------------------

def remove_file(path: Path, result: CleanupResult) -> None:
    """Remove a file while safely handling locked files."""

    try:
        path.unlink()
        result.removed_count += 1

    except PermissionError as exc:
        if is_locked_file_error(exc):
            result.skipped_locked.append(path)
            return

        result.skipped_other.append(path)

    except OSError:
        result.skipped_other.append(path)


def remove_directory(path: Path, result: CleanupResult) -> None:
    """Remove a directory while safely handling locked files."""

    try:
        shutil.rmtree(path)
        result.removed_count += 1

    except PermissionError as exc:
        if is_locked_file_error(exc):
            result.skipped_locked.append(path)
            return

        result.skipped_other.append(path)

    except OSError:
        result.skipped_other.append(path)


def clear_directory_contents(directory: Path) -> CleanupResult:
    """
    Clear generated contents from a directory.

    Preserves .gitkeep files so empty directories remain tracked by Git.
    """

    ensure_directory(directory)

    result = CleanupResult()

    for item in directory.iterdir():

        if is_preserved_placeholder(item):
            continue

        if item.is_dir():
            remove_directory(item, result)
            continue

        remove_file(item, result)

    return result


def clear_python_cache() -> CleanupResult:
    """
    Remove Python cache folders and compiled bytecode files.

    Locked cache artefacts are skipped so cleanup does not crash.
    """

    result = CleanupResult()

    for cache_dir in ROOT_DIR.rglob("__pycache__"):
        if cache_dir.is_dir():
            remove_directory(cache_dir, result)

    for bytecode_file in ROOT_DIR.rglob("*.pyc"):
        if bytecode_file.is_file():
            remove_file(bytecode_file, result)

    return result


def merge_results(target: CleanupResult, source: CleanupResult) -> None:
    """Merge one cleanup result into another."""

    target.removed_count += source.removed_count
    target.skipped_locked.extend(source.skipped_locked)
    target.skipped_other.extend(source.skipped_other)


# ------------------------------------------------------------
# OPERATOR CONFIRMATION
# ------------------------------------------------------------

def confirm_cleanup() -> bool:
    """Ask the operator to confirm cleanup before deleting generated files."""

    print_warning("Generated artefacts will be removed")
    print_info("Directories selected:")

    for directory in GENERATED_DIRS.values():
        print(f"    - {relative_path(directory)}")

    print("    - Python cache artefacts")
    print()
    print_success(f"Preserved: {relative_path(SCANS_DIR)}")
    print_success("Preserved: .gitkeep placeholders")
    print()

    print("Type YES to continue: ", end="", flush=True)
    response = input().strip()

    return response == "YES"


# ------------------------------------------------------------
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_cleanup_plan() -> None:
    """Print cleanup scope before confirmation."""

    print_step("Checking source training scans")
    print_success(f"Source training scans preserved: {relative_path(SCANS_DIR)}")
    print_info(f"Generated directories checked: {len(GENERATED_DIRS)}")
    print_info(f"Placeholder directories checked: {len(PLACEHOLDER_DIRS)}")
    print()


def print_removed_counts(removed_by_category: dict[str, int]) -> None:
    """Print removed artefact counts by category."""

    for label, removed_count in removed_by_category.items():
        print(f"    {label}: {removed_count}")


def print_skipped_paths(title: str, paths: list[Path]) -> None:
    """Print skipped paths in a compact format."""

    if not paths:
        return

    print_warning(f"{title}: {len(paths)}")

    for path in paths[:10]:
        print(f"    - {relative_path(path)}")

    if len(paths) > 10:
        print(f"    - ... {len(paths) - 10} more")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ artefact cleanup workflow."""

    prepare_generated_directories()

    if not SCANS_DIR.exists():
        print_error(f"Source training scans missing: {relative_path(SCANS_DIR)}")
        print_info("Cleanup stopped to avoid removing data unexpectedly")
        return 1

    print_cleanup_plan()

    if not confirm_cleanup():
        print()
        print_info("Clear Artefacts cancelled")
        return 0

    print()
    print_step("Clearing generated artefacts")

    total_result = CleanupResult()
    removed_by_category: dict[str, int] = {}

    for label, directory in GENERATED_DIRS.items():
        result = clear_directory_contents(directory)
        removed_by_category[label] = result.removed_count
        merge_results(total_result, result)

    pycache_result = clear_python_cache()
    removed_by_category["pycache"] = pycache_result.removed_count
    merge_results(total_result, pycache_result)

    write_gitkeep_files()

    print()
    print_success(f"Removed artefacts: {total_result.removed_count}")
    print_removed_counts(removed_by_category)

    print_skipped_paths("Locked artefacts skipped", total_result.skipped_locked)
    print_skipped_paths("Artefacts skipped due to errors", total_result.skipped_other)

    print()
    print_success("Clear Artefacts completed")
    print_success("Source training scans preserved")
    print_success("Generated directory structure preserved")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())