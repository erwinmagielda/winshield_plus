"""
WinShield+ installer.

Installs an operator-selected Windows update package from the downloads
directory. Supports .msu packages through WUSA and .cab packages through DISM.

Requires administrative privileges and does not restart the system automatically.
"""

import ctypes
import re
import subprocess
from pathlib import Path


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parents[1]

DOWNLOADS_DIR = ROOT_DIR / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)


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

    raise RuntimeError(f"Unsupported package type: {package_path}")


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

    print()

    for index, package_path in enumerate(packages, start=1):
        print(f"{index}) {package_path.name}")

    raw_selection = safe_input("Select package number: ").strip()

    if not raw_selection.isdigit():
        print("[!] Invalid selection")
        return None

    selected_index = int(raw_selection)

    if selected_index < 1 or selected_index > len(packages):
        print("[!] Selection out of range")
        return None

    return packages[selected_index - 1]


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    print("[*] Running WinShield+ installer")

    if not is_admin():
        print("[!] Administrator privileges are required")
        return 1

    packages = find_packages(DOWNLOADS_DIR)

    if not packages:
        print("[+] No update packages found")
        return 0

    selected_package = select_package(packages)

    if not selected_package:
        return 1

    kb_label = extract_kb_label(selected_package.name)

    print(f"[*] Installing {kb_label}")
    print("[*] Automatic restart is disabled")

    exit_code = install_package(selected_package)

    print(f"[+] Installer exit code: {exit_code}")

    if exit_code == 3010:
        print("[!] Installation completed and requires restart")
        return 0

    if exit_code == 0:
        print("[+] Installation completed")
        return 0

    print("[!] Installation failed or was rejected by Windows servicing")
    return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())