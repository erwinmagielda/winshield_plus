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
# CLEANUP
# ------------------------------------------------------------

def remove_directory(path: Path) -> None:
    """Remove a generated directory if it exists."""

    if path.exists():
        shutil.rmtree(path)
        print(f"[+] Removed: {path}")
    else:
        print(f"[i] Already clean: {path}")


def recreate_directory(path: Path) -> None:
    """Recreate an empty generated directory."""

    path.mkdir(parents=True, exist_ok=True)
    print(f"[+] Recreated: {path}")


def confirm_cleanup() -> bool:
    """Ask the operator to confirm cleanup before deleting generated files."""

    print("This will remove generated WinShield+ artefacts:")
    for path in GENERATED_DIRS:
        print(f"  - {path}")

    print()
    print(f"This will preserve: {SCANS_DIR}")
    print()

    response = input("Continue? Type YES to confirm: ").strip()

    return response == "YES"


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ artefact cleanup workflow."""

    print("\n=== WinShield+ Artefact Cleanup ===\n")

    if not SCANS_DIR.exists():
        print(f"[!] Warning: scans directory not found: {SCANS_DIR}")
        print("[!] Cleanup stopped to avoid removing data unexpectedly.")
        return 1

    if not confirm_cleanup():
        print("[i] Cleanup cancelled.")
        return 0

    for path in GENERATED_DIRS:
        remove_directory(path)
        recreate_directory(path)

    print()
    print("[+] Cleanup complete.")
    print("[+] Source training scans preserved.")
    print()

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())