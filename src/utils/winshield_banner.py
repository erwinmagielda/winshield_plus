"""
WinShield+ terminal banner utilities.

Keeps menu and workflow headers consistent across the CLI.
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
LINE = "=" * 60


# ------------------------------------------------------------
# HEADER PRINTING
# ------------------------------------------------------------

def print_menu_header() -> None:
    """Print the WinShield+ main menu header."""

    print()
    print(WINSHIELD_LOGO)
    print(PROJECT_SUBTITLE)
    print()
    print(LINE)
    print()


def print_workflow_header(title: str) -> None:
    """Print a workflow section header without repeating the logo."""

    print()
    print(title)
    print(LINE)
    print()


def print_section(title: str) -> None:
    """Print a smaller section title."""

    print()
    print(title)
    print("-" * len(title))


# ------------------------------------------------------------
# STATUS PRINTING
# ------------------------------------------------------------

def print_info(message: str) -> None:
    """Print an informational message."""

    print(f"[i] {message}")


def print_step(message: str) -> None:
    """Print a running step message."""

    print(f"[*] {message}")


def print_success(message: str) -> None:
    """Print a success message."""

    print(f"[+] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""

    print(f"[!] {message}")


def print_error(message: str) -> None:
    """Print an error message."""

    print(f"[X] {message}")