"""
WinShield+ artefact cleanup utility.

Removes generated pipeline artefacts while preserving source training scans.
Use this before rebuilding the project pipeline from data/scans/.
"""

import shutil
from pathlib import Path


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]

DATA_DIR = ROOT_DIR / "data"
SCANS_DIR = DATA_DIR / "scans"

GENERATED_DIRS = [
    DATA_DIR / "dataset",
    DATA_DIR / "runtime",
    ROOT_DIR / "models",
    ROOT_DIR / "results",
    ROOT_DIR / "downloads",
]


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a standard cleanup section heading."""

    print()
    print(f"--- {title} ---")


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------

def remove_directory(path: Path) -> None:
    """Remove a generated directory if it exists."""

    if path.exists():
        shutil.rmtree(path)
        print(f"[+] Removed: {relative_path(path)}")
    else:
        print(f"[i] Already clean: {relative_path(path)}")


def recreate_directory(path: Path) -> None:
    """Recreate an empty generated directory."""

    path.mkdir(parents=True, exist_ok=True)
    print(f"[+] Recreated: {relative_path(path)}")


def confirm_cleanup() -> bool:
    """Ask the operator to confirm cleanup before deleting generated files."""

    print_section("Confirmation")

    print("[!] Generated artefacts will be removed")
    print("[i] Directories selected:")

    for path in GENERATED_DIRS:
        print(f"    - {relative_path(path)}")

    print()
    print(f"[+] Preserved: {relative_path(SCANS_DIR)}")
    print()

    response = input("Type YES to continue: ").strip()

    return response == "YES"


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ artefact cleanup workflow."""

    print()
    print("=" * 60)
    print("WinShield+ - Clear Artefacts")
    print("=" * 60)

    print_section("Pre-flight")
    print("[*] Checking source training scans")

    if not SCANS_DIR.exists():
        print(f"[X] Source training scans missing: {relative_path(SCANS_DIR)}")
        print("[i] Cleanup stopped to avoid removing data unexpectedly")
        return 1

    print(f"[+] Source training scans preserved: {relative_path(SCANS_DIR)}")

    if not confirm_cleanup():
        print()
        print("[i] Clear Artefacts cancelled")
        return 0

    print_section("Cleanup")

    for path in GENERATED_DIRS:
        remove_directory(path)
        recreate_directory(path)

    print()
    print("[+] Clear Artefacts completed")
    print("[+] Source training scans preserved")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())