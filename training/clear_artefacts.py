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
    print_section,
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
# ARTEFACT COUNTING
# ------------------------------------------------------------

def count_directory_artefacts(directory: Path) -> int:
    """Count removable generated artefacts inside a directory."""

    ensure_directory(directory)

    removable_count = 0

    for item in directory.iterdir():
        if is_preserved_placeholder(item):
            continue

        removable_count += 1

    return removable_count


def count_python_cache_artefacts() -> int:
    """Count removable Python cache artefacts."""

    cache_count = 0

    for cache_dir in ROOT_DIR.rglob("__pycache__"):
        if cache_dir.is_dir():
            cache_count += 1

    for bytecode_file in ROOT_DIR.rglob("*.pyc"):
        if bytecode_file.is_file():
            cache_count += 1

    return cache_count


def count_generated_artefacts() -> int:
    """Count all removable generated artefacts before cleanup."""

    directory_count = sum(
        count_directory_artefacts(directory)
        for directory in GENERATED_DIRS.values()
    )

    return directory_count + count_python_cache_artefacts()


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

    print_section("User Confirmation")
    print("[!] Remove generated artefacts [Y/n]?: ", end="", flush=True)

    try:
        response = input().strip().lower()
    except EOFError:
        print()
        print_warning("Input stream unavailable")
        return False

    return response in {"y", "yes"}


# ------------------------------------------------------------
# CONSOLE OUTPUT
# ------------------------------------------------------------

def print_cleanup_scope(artefact_count: int) -> None:
    """Print compact cleanup scope before confirmation."""

    print_section("Cleanup Scope")
    print_success(f"Preserved: {relative_path(SCANS_DIR)}")
    print_success("Preserved: .gitkeep placeholders")
    print_info(f"Generated artefacts found: {artefact_count}")


def print_skipped_paths(title: str, paths: list[Path]) -> None:
    """Print skipped paths in a compact format."""

    if not paths:
        return

    print_warning(f"{title}: {len(paths)}")

    for path in paths[:5]:
        print(f"    - {relative_path(path)}")

    if len(paths) > 5:
        print(f"    - ... {len(paths) - 5} more")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ artefact cleanup workflow."""

    try:
        prepare_generated_directories()

        if not SCANS_DIR.exists():
            print_error(f"Source training scans missing: {relative_path(SCANS_DIR)}")
            print_info("Cleanup stopped to avoid removing data unexpectedly")
            return 1

        artefact_count = count_generated_artefacts()

        print_cleanup_scope(artefact_count)

        if artefact_count == 0:
            print()
            print_success("No generated artefacts found")
            print_success("Clear Artefacts completed")
            return 0

        if not confirm_cleanup():
            print()
            print_info("Clear Artefacts cancelled")
            return 0

        print_section("Cleanup Execution")
        print_step("Clearing generated artefacts")

        total_result = CleanupResult()

        for directory in GENERATED_DIRS.values():
            result = clear_directory_contents(directory)
            merge_results(total_result, result)

        pycache_result = clear_python_cache()
        merge_results(total_result, pycache_result)

        write_gitkeep_files()

        print_success(f"Removed artefacts: {total_result.removed_count}")
        print_success("Directory structure preserved")

        print_skipped_paths("Locked artefacts skipped", total_result.skipped_locked)
        print_skipped_paths("Artefacts skipped due to errors", total_result.skipped_other)

        print()
        print_success("Clear Artefacts completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Clear Artefacts cancelled")
        return 130

    except Exception as exc:
        print_error(f"Clear Artefacts failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())