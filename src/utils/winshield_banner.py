"""
WinShield+ terminal banner utilities.

Keeps menu headers, workflow headers, section headers, and status messages
consistent across the command-line interface.
"""

from __future__ import annotations


# ------------------------------------------------------------
# BANNER
# ------------------------------------------------------------

WINSHIELD_LOGO = r"""
 /██      /██ /██            /██████  /██       /██           /██       /██
| ██  /█ | ██|__/           /██__  ██| ██      |__/          | ██      | ██    /██
| ██ /███| ██ /██ /███████ | ██  \__/| ███████  /██  /██████ | ██  /███████   | ██
| ██/██ ██ ██| ██| ██__  ██|  ██████ | ██__  ██| ██ /██__  ██| ██ /██__  ██ /████████
| ████_  ████| ██| ██  \ ██ \____  ██| ██  \ ██| ██| ████████| ██| ██  | ██|__  ██__/
| ███/ \  ███| ██| ██  | ██ /██  \ ██| ██  | ██| ██| ██_____/| ██| ██  | ██   | ██
| ██/   \  ██| ██| ██  | ██|  ██████/| ██  | ██| ██|  ███████| ██|  ███████   |__/
|__/     \__/|__/|__/  |__/ \______/ |__/  |__/|__/ \_______/|__/ \_______/
"""

PROJECT_SUBTITLE = "Windows Patch Risk Prioritisation"
HEADER_LINE = "=" * 60


# ------------------------------------------------------------
# HEADER PRINTING
# ------------------------------------------------------------

def print_menu_header() -> None:
    """Print the WinShield+ main menu header."""

    print()
    print(WINSHIELD_LOGO)
    print(PROJECT_SUBTITLE)
    print()
    print(HEADER_LINE)
    print()


def print_menu_title() -> None:
    """Print a compact menu title without repeating the logo."""

    print()
    print("WinShield+ Operator Menu")
    print(HEADER_LINE)
    print()


def print_workflow_header(title: str) -> None:
    """Print a top-level workflow header without repeating the logo."""

    print()
    print(title)
    print(HEADER_LINE)
    print()


def print_section(title: str) -> None:
    """Print an internal workflow section header."""

    print()
    print(title)
    print("-" * len(title))


# ------------------------------------------------------------
# STATUS PRINTING
# ------------------------------------------------------------

def print_step(message: str) -> None:
    """Print an active operation message."""

    print(f"[*] {message}")


def print_success(message: str) -> None:
    """Print a successful operation message."""

    print(f"[+] {message}")


def print_info(message: str) -> None:
    """Print an informational message."""

    print(f"[i] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""

    print(f"[!] {message}")


def print_error(message: str) -> None:
    """Print an error message."""

    print(f"[X] {message}")