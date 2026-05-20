"""
WinShield+ installer.

Installs an operator-selected Windows update package from the downloads
directory. Supports .msu packages through WUSA and .cab packages through DISM.

Requires administrative privileges and does not restart the system automatically.
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import sys
from pathlib import Path


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import (
    print_error,
    print_info,
    print_section,
    print_step,
    print_success,
    print_warning,
)
from utils.winshield_paths import (
    ensure_directory,
    get_downloads_dir,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

DOWNLOADS_DIR = get_downloads_dir()


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# PRIVILEGE CHECK
# ------------------------------------------------------------

def is_admin() -> bool:
    """Return True if the current process has administrative privileges."""

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------------------
# PACKAGE DISCOVERY
# ------------------------------------------------------------

def find_packages(downloads_dir: Path) -> list[Path]:
    """Return sorted .msu and .cab packages from the downloads directory."""

    ensure_directory(downloads_dir)

    packages: list[Path] = []

    for path in downloads_dir.iterdir():
        if not path.is_file():
            continue

        if path.suffix.lower() in (".msu", ".cab"):
            packages.append(path)

    return sorted(packages, key=lambda path: path.name.lower())


def extract_kb_label(filename: str) -> str:
    """Extract a KB identifier from a filename if present."""

    match = re.search(r"(KB\d{4,8})", filename, flags=re.IGNORECASE)

    return match.group(1).upper() if match else filename


# ------------------------------------------------------------
# COMMAND EXECUTION
# ------------------------------------------------------------

def run_command(command: list[str]) -> int:
    """Execute an installer command and return its exit code."""

    result = subprocess.run(
        command,
        text=True,
        check=False,
    )

    return int(result.returncode or 0)


def install_package(package_path: Path) -> int:
    """Install a selected .msu or .cab package using the matching Windows tool."""

    extension = package_path.suffix.lower()

    if extension == ".msu":
        return run_command(
            [
                "wusa.exe",
                str(package_path),
                "/quiet",
                "/norestart",
            ]
        )

    if extension == ".cab":
        return run_command(
            [
                "dism.exe",
                "/online",
                "/add-package",
                f"/packagepath:{package_path}",
                "/quiet",
                "/norestart",
            ]
        )

    raise RuntimeError(f"Unsupported package type: {relative_path(package_path)}")


# ------------------------------------------------------------
# OPERATOR INPUT
# ------------------------------------------------------------

def safe_input(prompt: str) -> str:
    """Read operator input without raising EOF errors."""

    try:
        return input(prompt)
    except EOFError:
        return ""


def select_package(packages: list[Path]) -> Path | None:
    """Ask the operator to select a package from the available downloads."""

    print_section("Available Packages")

    for index, package_path in enumerate(packages, start=1):
        kb_label = extract_kb_label(package_path.name)
        print(f"{index}) {kb_label} | {package_path.name}")

    raw_selection = safe_input("\nSelect package: ").strip()

    if not raw_selection.isdigit():
        print_error("Invalid selection")
        return None

    selected_index = int(raw_selection)

    if selected_index < 1 or selected_index > len(packages):
        print_error("Selection out of range")
        return None

    return packages[selected_index - 1]


# ------------------------------------------------------------
# INSTALL RESULT HANDLING
# ------------------------------------------------------------

def print_install_result(exit_code: int) -> int:
    """Print a clean installer result and return the workflow exit code."""

    print_success(f"Installer exit code: {exit_code}")

    if exit_code == 0:
        print_success("Installation completed")
        return 0

    if exit_code == 3010:
        print_warning("Installation completed")
        print_info("Restart required")
        return 0

    print_error("Installation failed or was rejected by Windows servicing")
    return 1


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ update installer workflow."""

    try:
        print_section("Pre-flight")
        print_step("Checking administrator privileges")

        if not is_admin():
            print_error("Administrator privileges required")
            return 1

        print_success("Administrator privileges confirmed")
        print_success(f"Downloads directory: {relative_path(DOWNLOADS_DIR)}")

        print_section("Package Discovery")
        packages = find_packages(DOWNLOADS_DIR)

        if not packages:
            print_success("No update packages found")
            return 0

        print_success(f"Packages found: {len(packages)}")

        selected_package = select_package(packages)

        if not selected_package:
            return 1

        kb_label = extract_kb_label(selected_package.name)

        print_section("Install")
        print_step(f"Selected package: {kb_label}")
        print_info(f"Source: {relative_path(selected_package)}")
        print_info("Automatic restart disabled")

        exit_code = install_package(selected_package)

        print_section("Result")
        workflow_exit_code = print_install_result(exit_code)

        if workflow_exit_code == 0:
            print()
            print_success("Install Update completed")

        return workflow_exit_code

    except KeyboardInterrupt:
        print()
        print_warning("Install Update cancelled")
        return 130

    except Exception as exc:
        print_error(f"Install Update failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())