"""
WinShield+ downloader.

Resolves and downloads an operator-selected missing Windows update package
from the Microsoft Update Catalog using baseline constraints from the latest
runtime scan.

This module does not install updates. It only downloads a selected package.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parents[1]

RUNTIME_DIR = ROOT_DIR / "data" / "runtime"
DOWNLOADS_DIR = ROOT_DIR / "downloads"

DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# CATALOG SETTINGS
# ------------------------------------------------------------

CATALOG_BASE_URL = "https://www.catalog.update.microsoft.com"
SEARCH_URL = f"{CATALOG_BASE_URL}/Search.aspx"
DOWNLOAD_DIALOG_URL = f"{CATALOG_BASE_URL}/DownloadDialog.aspx"

DEFAULT_TIMEOUT = 30
MIN_CONFIDENCE_SCORE = 90
REJECT_SCORE = -10_000


# ------------------------------------------------------------
# DATA MODELS
# ------------------------------------------------------------

@dataclass(frozen=True)
class MissingKbItem:
    kb_id: str
    update_type: str


@dataclass(frozen=True)
class CatalogCandidate:
    update_id: str
    title: str
    products: str
    classification: str
    last_updated: str
    version: str
    size: str


@dataclass(frozen=True)
class BaselineConstraints:
    windows_gen: str
    display_version: str
    build_major: str
    catalog_arch: str


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a standard downloader section heading."""

    print()
    print(f"--- {title} ---")


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------

def find_latest_runtime_scan() -> Path:
    """Return the newest runtime scan exported by winshield_scanner.py."""

    scan_files = sorted(
        RUNTIME_DIR.glob("scan_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not scan_files:
        raise RuntimeError("Runtime scan missing. Run Scan System first.")

    return scan_files[0]


def load_scan_result(path: Path) -> dict[str, Any]:
    """Load scanner output JSON from disk."""

    if not path.is_file():
        raise RuntimeError(f"Runtime scan not found: {relative_path(path)}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


# ------------------------------------------------------------
# OPERATOR INPUT
# ------------------------------------------------------------

def safe_input(prompt: str) -> str:
    """Read operator input without raising EOF errors."""

    try:
        return input(prompt)
    except EOFError:
        return ""


# ------------------------------------------------------------
# BASELINE CONSTRAINTS
# ------------------------------------------------------------

def build_constraints(baseline: dict[str, Any]) -> BaselineConstraints:
    """Derive Microsoft Update Catalog matching constraints from baseline metadata."""

    os_name = str(baseline.get("OsName") or "").lower()
    display_version = str(baseline.get("DisplayVersion") or "").strip()
    architecture = str(baseline.get("Architecture") or "").lower()
    build = str(baseline.get("Build") or "")

    build_major = build.split(".", 1)[0] if build else ""

    if "windows 11" in os_name:
        windows_gen = "windows 11"
    elif "windows 10" in os_name:
        windows_gen = "windows 10"
    else:
        windows_gen = ""

    if architecture in ("x64", "amd64"):
        catalog_arch = "x64"
    elif "arm64" in architecture:
        catalog_arch = "arm64"
    elif architecture in ("x86", "32-bit"):
        catalog_arch = "x86"
    else:
        catalog_arch = "x64"

    return BaselineConstraints(
        windows_gen=windows_gen,
        display_version=display_version,
        build_major=build_major,
        catalog_arch=catalog_arch,
    )


def print_constraints(constraints: BaselineConstraints) -> None:
    """Print concise catalog matching constraints."""

    print(f"[+] Windows generation: {constraints.windows_gen or 'Unknown'}")
    print(f"[+] Display version: {constraints.display_version or 'Unknown'}")
    print(f"[+] Build major: {constraints.build_major or 'Unknown'}")
    print(f"[+] Architecture: {constraints.catalog_arch}")


# ------------------------------------------------------------
# HTTP SESSION
# ------------------------------------------------------------

def build_session() -> requests.Session:
    """Create an HTTP session with stable request headers."""

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "winshield-plus-downloader",
            "Accept-Language": "en-GB,en;q=0.9",
        }
    )

    return session


def fetch_text(
    session: requests.Session,
    url: str,
    params: dict[str, Any] | None = None,
) -> str:
    """Fetch text content and raise on HTTP errors."""

    response = session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
    response.raise_for_status()

    return response.text


# ------------------------------------------------------------
# MISSING KB SELECTION
# ------------------------------------------------------------

def build_missing_list(scan_result: dict[str, Any]) -> list[MissingKbItem]:
    """Build a display list of missing KBs with update type labels."""

    missing_kbs = scan_result.get("MissingKbs") or []
    kb_entries = scan_result.get("KbEntries") or []

    kb_index = {
        str(entry.get("KB")).upper(): entry
        for entry in kb_entries
        if entry.get("KB")
    }

    missing_items: list[MissingKbItem] = []

    for kb in missing_kbs:
        kb_id = str(kb).strip().upper()
        if not kb_id:
            continue

        update_type = str(kb_index.get(kb_id, {}).get("UpdateType") or "Unknown")
        missing_items.append(
            MissingKbItem(
                kb_id=kb_id,
                update_type=update_type,
            )
        )

    return missing_items


def print_missing_items(missing_items: list[MissingKbItem]) -> None:
    """Print selectable missing KB list."""

    print_section("Missing KBs")

    for index, item in enumerate(missing_items, start=1):
        print(f"{index}) {item.kb_id} [{item.update_type}]")


def select_missing_kb(missing_items: list[MissingKbItem]) -> MissingKbItem | None:
    """Prompt the operator to select a missing KB."""

    raw_selection = safe_input("\nSelect KB: ").strip()

    if not raw_selection.isdigit():
        print("[X] Invalid selection")
        return None

    selected_index = int(raw_selection)

    if selected_index < 1 or selected_index > len(missing_items):
        print("[X] Selection out of range")
        return None

    return missing_items[selected_index - 1]


# ------------------------------------------------------------
# CATALOG SEARCH PARSING
# ------------------------------------------------------------

def parse_search_candidates(html: str) -> list[CatalogCandidate]:
    """Parse Microsoft Update Catalog search results into structured candidates."""

    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table", id="ctl00_catalogBody_updateMatches")

    if not table:
        return []

    candidates: list[CatalogCandidate] = []

    for table_row in table.find_all("tr"):
        row_id = (table_row.get("id") or "").strip()

        if "_R" not in row_id:
            continue

        update_id = row_id.split("_R", 1)[0]
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", update_id):
            continue

        cells = table_row.find_all("td")
        if len(cells) < 8:
            continue

        candidates.append(
            CatalogCandidate(
                update_id=update_id,
                title=cells[1].get_text(" ", strip=True),
                products=cells[2].get_text(" ", strip=True),
                classification=cells[3].get_text(" ", strip=True),
                last_updated=cells[4].get_text(" ", strip=True),
                version=cells[5].get_text(" ", strip=True),
                size=cells[6].get_text(" ", strip=True),
            )
        )

    return candidates


# ------------------------------------------------------------
# CANDIDATE SCORING
# ------------------------------------------------------------

def score_candidate(
    candidate: CatalogCandidate,
    kb_id: str,
    constraints: BaselineConstraints,
) -> int:
    """Score a catalog candidate against baseline constraints."""

    title = candidate.title.lower()
    score = 0

    if kb_id.lower() not in title:
        return REJECT_SCORE

    score += 50

    if constraints.windows_gen:
        if constraints.windows_gen in title:
            score += 40

        if constraints.windows_gen == "windows 10" and "windows 11" in title:
            return REJECT_SCORE

        if constraints.windows_gen == "windows 11" and "windows 10" in title:
            return REJECT_SCORE

    if constraints.windows_gen.startswith("windows") and "server" in title:
        return REJECT_SCORE

    if constraints.catalog_arch == "x64":
        if any(token in title for token in ("arm64-based", "x86-based", "32-bit")):
            return REJECT_SCORE

        if "x64-based" in title:
            score += 25

    elif constraints.catalog_arch == "arm64":
        if any(token in title for token in ("x64-based", "x86-based", "32-bit")):
            return REJECT_SCORE

        if "arm64-based" in title:
            score += 25

    elif constraints.catalog_arch == "x86":
        if any(token in title for token in ("x64-based", "arm64-based")):
            return REJECT_SCORE

        if "x86-based" in title or "32-bit" in title:
            score += 25

    display_version = constraints.display_version.lower()
    if display_version:
        if display_version in title:
            score += 25

        if re.search(r"\b\d{2}h[12]\b", title) and display_version not in title:
            score -= 15

    if constraints.build_major:
        build_match = re.search(r"\(\s*(\d{5})\.", title)

        if build_match:
            score += 10 if build_match.group(1) == constraints.build_major else -5

    return score


def choose_best_candidate(
    candidates: list[CatalogCandidate],
    kb_id: str,
    constraints: BaselineConstraints,
) -> tuple[CatalogCandidate | None, str | None]:
    """Select the highest-confidence candidate or return a rejection reason."""

    scored_candidates = [
        (score_candidate(candidate, kb_id, constraints), candidate)
        for candidate in candidates
    ]

    accepted_candidates = [
        (score, candidate)
        for score, candidate in scored_candidates
        if score >= 0
    ]

    if not accepted_candidates:
        return None, "No candidate matched baseline constraints"

    accepted_candidates.sort(key=lambda item: item[0], reverse=True)
    best_score, best_candidate = accepted_candidates[0]

    if best_score < MIN_CONFIDENCE_SCORE:
        return None, f"Ambiguous match below confidence threshold ({best_score})"

    return best_candidate, None


# ------------------------------------------------------------
# DOWNLOAD URL RESOLUTION
# ------------------------------------------------------------

def build_dialog_params(update_id: str) -> dict[str, str]:
    """Build parameters for the Microsoft Update Catalog download dialog."""

    payload = (
        f'[{{"size":0,"languages":"all",'
        f'"uidInfo":"{update_id}","updateID":"{update_id}"}}]'
    )

    return {"updateIDs": payload}


def extract_download_urls(html: str) -> list[str]:
    """Extract direct .msu or .cab URLs from download dialog HTML."""

    urls = re.findall(
        r"https?://[^\"]+\.(?:msu|cab)(?:\?[^\"]*)?",
        html,
        flags=re.IGNORECASE,
    )

    seen_urls: set[str] = set()
    output: list[str] = []

    for url in urls:
        if url not in seen_urls:
            seen_urls.add(url)
            output.append(url)

    return output


# ------------------------------------------------------------
# FILE DOWNLOAD
# ------------------------------------------------------------

def download_file(
    session: requests.Session,
    url: str,
    output_dir: Path,
) -> Path:
    """Download a resolved update package to disk."""

    filename = url.split("/")[-1].split("?", 1)[0]
    output_path = output_dir / filename

    with session.get(url, stream=True, timeout=DEFAULT_TIMEOUT) as response:
        response.raise_for_status()

        with output_path.open("wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if chunk:
                    file.write(chunk)

    return output_path


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ update downloader workflow."""

    print()
    print("=" * 60)
    print("WinShield+ - Download Update")
    print("=" * 60)

    print_section("Runtime Scan")
    scan_path = find_latest_runtime_scan()
    print(f"[+] Runtime scan: {relative_path(scan_path)}")

    scan_result = load_scan_result(scan_path)

    print_section("Catalog Constraints")
    constraints = build_constraints(scan_result.get("Baseline") or {})
    print_constraints(constraints)

    missing_items = build_missing_list(scan_result)
    if not missing_items:
        print()
        print("[+] No missing KBs detected")
        return 0

    print_missing_items(missing_items)

    selected_item = select_missing_kb(missing_items)
    if not selected_item:
        return 1

    session = build_session()

    print_section("Catalog Search")
    print(f"[*] Searching Microsoft Update Catalog: {selected_item.kb_id}")

    html = fetch_text(session, SEARCH_URL, params={"q": selected_item.kb_id})
    candidates = parse_search_candidates(html)

    print(f"[+] Candidates found: {len(candidates)}")

    best_candidate, rejection_reason = choose_best_candidate(
        candidates=candidates,
        kb_id=selected_item.kb_id,
        constraints=constraints,
    )

    if not best_candidate:
        print(f"[X] {rejection_reason}")
        return 1

    print(f"[+] Selected candidate: {best_candidate.title}")
    print(f"[i] Classification: {best_candidate.classification}")
    print(f"[i] Last updated: {best_candidate.last_updated}")
    print(f"[i] Size: {best_candidate.size}")

    print_section("Resolve Download")
    print("[*] Resolving package URL")

    dialog_html = fetch_text(
        session,
        DOWNLOAD_DIALOG_URL,
        params=build_dialog_params(best_candidate.update_id),
    )

    download_urls = extract_download_urls(dialog_html)
    if not download_urls:
        print("[X] Download URL not found")
        return 1

    print(f"[+] Download URLs found: {len(download_urls)}")

    print_section("Download")
    print("[*] Downloading selected package")

    output_path = download_file(
        session=session,
        url=download_urls[0],
        output_dir=DOWNLOADS_DIR,
    )

    print(f"[+] Package saved: {relative_path(output_path)}")

    print()
    print("[+] Download Update completed")

    return 0


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())