"""
WinShield+ downloader.

Resolves and downloads an operator-selected missing Windows update package from
the Microsoft Update Catalog using baseline constraints from the latest runtime
scan.

This module does not install updates. It only downloads a selected package.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
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
    get_downloads_dir,
    get_runtime_dir,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

RUNTIME_DIR = get_runtime_dir()
DOWNLOADS_DIR = get_downloads_dir()


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
class ScoredCandidate:
    score: int
    candidate: CatalogCandidate


@dataclass(frozen=True)
class BaselineConstraints:
    windows_gen: str
    display_version: str
    build_major: str
    catalog_arch: str


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def normalise_kb_id(value: Any) -> str:
    """Return a normalised KB identifier."""

    return str(value).strip().upper()


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
        data = json.load(file)

    if not isinstance(data, dict):
        raise RuntimeError("Runtime scan has unexpected structure")

    return data


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
    """Print catalog matching constraints."""

    print_success(f"Windows generation: {constraints.windows_gen or 'Unknown'}")
    print_success(f"Display version: {constraints.display_version or 'Unknown'}")
    print_success(f"Build major: {constraints.build_major or 'Unknown'}")
    print_success(f"Architecture: {constraints.catalog_arch}")


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
        normalise_kb_id(entry.get("KB")): entry
        for entry in kb_entries
        if entry.get("KB")
    }

    missing_items: list[MissingKbItem] = []

    for kb in missing_kbs:
        kb_id = normalise_kb_id(kb)

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
    print_success(f"Missing KBs available: {len(missing_items)}")

    for index, item in enumerate(missing_items, start=1):
        print(f"{index}) {item.kb_id} [{item.update_type}]")


def select_missing_kb(missing_items: list[MissingKbItem]) -> MissingKbItem | None:
    """Prompt the operator to select a missing KB."""

    raw_selection = safe_input("\nSelect KB: ").strip()

    if not raw_selection.isdigit():
        print_error("Invalid selection")
        return None

    selected_index = int(raw_selection)

    if selected_index < 1 or selected_index > len(missing_items):
        print_error("Selection out of range")
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


def score_candidates(
    candidates: list[CatalogCandidate],
    kb_id: str,
    constraints: BaselineConstraints,
) -> list[ScoredCandidate]:
    """Score catalog candidates and return accepted candidates."""

    scored_candidates: list[ScoredCandidate] = []

    for candidate in candidates:
        score = score_candidate(candidate, kb_id, constraints)

        if score >= 0:
            scored_candidates.append(
                ScoredCandidate(
                    score=score,
                    candidate=candidate,
                )
            )

    return sorted(scored_candidates, key=lambda item: item.score, reverse=True)


def choose_best_candidate(
    candidates: list[CatalogCandidate],
    kb_id: str,
    constraints: BaselineConstraints,
) -> tuple[ScoredCandidate | None, str | None]:
    """Select the highest-confidence candidate or return a rejection reason."""

    scored_candidates = score_candidates(
        candidates=candidates,
        kb_id=kb_id,
        constraints=constraints,
    )

    if not scored_candidates:
        return None, "No candidate matched baseline constraints"

    best_candidate = scored_candidates[0]

    if best_candidate.score < MIN_CONFIDENCE_SCORE:
        return None, f"Ambiguous match below confidence threshold ({best_candidate.score})"

    return best_candidate, None


def print_candidate_scores(scored_candidates: list[ScoredCandidate]) -> None:
    """Print the highest scoring catalog candidates."""

    print_info(f"Candidates matching baseline: {len(scored_candidates)}")

    for index, scored_candidate in enumerate(scored_candidates[:5], start=1):
        print(
            f"    {index}) Score {scored_candidate.score} | "
            f"{scored_candidate.candidate.title}"
        )


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

    ensure_directory(output_dir)

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

    try:
        print_section("Runtime scan")
        scan_path = find_latest_runtime_scan()
        print_success(f"Runtime scan: {relative_path(scan_path)}")

        scan_result = load_scan_result(scan_path)

        print_section("Catalog constraints")
        constraints = build_constraints(scan_result.get("Baseline") or {})
        print_constraints(constraints)

        missing_items = build_missing_list(scan_result)

        if not missing_items:
            print()
            print_success("No missing KBs detected")
            return 0

        print_missing_items(missing_items)

        selected_item = select_missing_kb(missing_items)

        if not selected_item:
            return 1

        session = build_session()

        print_section("Catalog search")
        print_step(f"Searching Microsoft Update Catalog: {selected_item.kb_id}")

        html = fetch_text(session, SEARCH_URL, params={"q": selected_item.kb_id})
        candidates = parse_search_candidates(html)

        print_success(f"Candidates found: {len(candidates)}")

        scored_candidates = score_candidates(
            candidates=candidates,
            kb_id=selected_item.kb_id,
            constraints=constraints,
        )
        print_candidate_scores(scored_candidates)

        best_candidate, rejection_reason = choose_best_candidate(
            candidates=candidates,
            kb_id=selected_item.kb_id,
            constraints=constraints,
        )

        if not best_candidate:
            print_error(str(rejection_reason))
            return 1

        selected_candidate = best_candidate.candidate

        print_success(f"Selected candidate score: {best_candidate.score}")
        print_success(f"Selected candidate: {selected_candidate.title}")
        print_info(f"Classification: {selected_candidate.classification}")
        print_info(f"Last updated: {selected_candidate.last_updated}")
        print_info(f"Size: {selected_candidate.size}")

        print_section("Resolve download")
        print_step("Resolving package URL")

        dialog_html = fetch_text(
            session,
            DOWNLOAD_DIALOG_URL,
            params=build_dialog_params(selected_candidate.update_id),
        )

        download_urls = extract_download_urls(dialog_html)

        if not download_urls:
            print_error("Download URL not found")
            return 1

        print_success(f"Download URLs found: {len(download_urls)}")

        print_section("Download")
        print_step("Downloading selected package")
        print_info(f"Download directory: {relative_path(DOWNLOADS_DIR)}")

        output_path = download_file(
            session=session,
            url=download_urls[0],
            output_dir=DOWNLOADS_DIR,
        )

        print_success(f"Package saved: {relative_path(output_path)}")

        print()
        print_success("Download Update completed")

        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Download Update cancelled")
        return 130

    except Exception as exc:
        print_error(f"Download Update failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())