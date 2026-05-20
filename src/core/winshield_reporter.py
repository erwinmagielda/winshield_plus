"""
WinShield+ Markdown reporter.

Generates a readable runtime risk report from WinShield+ ranked remediation
results. The report is intended for portfolio review, technical handover, and
operator evidence after Rank Risk completes.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from utils.winshield_paths import load_config


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import print_success
from utils.winshield_paths import (
    ensure_directory,
    get_ranking_results_path,
    get_runtime_report_path,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

RANKING_RESULTS_PATH = get_ranking_results_path()
REPORT_PATH = get_runtime_report_path()


# ------------------------------------------------------------
# REPORT SETTINGS
# ------------------------------------------------------------

REPORT_TITLE = "WinShield+ Runtime Risk Report"
TOOL_NAME = "WinShield+"

def get_tool_version() -> str:
    """Return configured tool version."""

    config = load_config()

    return str(config.get("version", "unknown"))


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def safe_float(value: Any) -> float:
    """Convert a value to float safely."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def safe_int(value: Any) -> int:
    """Convert a value to int safely."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------

def load_ranking_results(path: Path = RANKING_RESULTS_PATH) -> list[dict[str, Any]]:
    """Load ranked remediation results from JSON."""

    if not path.is_file():
        raise RuntimeError(f"Ranking results missing: {relative_path(path)}")

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise RuntimeError("Ranking results have unexpected structure")

    return data


# ------------------------------------------------------------
# SUMMARY BUILDING
# ------------------------------------------------------------

def get_highest_priority(results: list[dict[str, Any]]) -> str:
    """Return the highest priority label present in report results."""

    priorities = {
        str(entry.get("policy_priority", "Unknown"))
        for entry in results
    }

    if "High" in priorities:
        return "High"

    if "Medium" in priorities:
        return "Medium"

    if "Low" in priorities:
        return "Low"

    return "Unknown"


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build report-level summary values."""

    cve_total = sum(safe_int(entry.get("cve_count")) for entry in results)

    highest_policy_risk = max(
        [safe_float(entry.get("policy_risk")) for entry in results],
        default=0.0,
    )

    highest_ml_risk = max(
        [safe_float(entry.get("ml_risk")) for entry in results],
        default=0.0,
    )

    return {
        "missing_kbs_reviewed": len(results),
        "cves_reviewed": cve_total,
        "highest_policy_risk": highest_policy_risk,
        "highest_ml_risk": highest_ml_risk,
        "highest_priority": get_highest_priority(results),
    }


# ------------------------------------------------------------
# MARKDOWN BUILDING
# ------------------------------------------------------------

def build_report(results: list[dict[str, Any]]) -> str:
    """Build the Markdown runtime risk report."""

    generated_at = utc_timestamp()
    summary = build_summary(results)

    lines: list[str] = []

    lines.append(f"# {REPORT_TITLE}")
    lines.append("")
    lines.append(f"**Generated:** {generated_at}")
    lines.append("")
    lines.append(f"**Tool:** {TOOL_NAME}")
    lines.append("")
    lines.append(f"**Version:** {get_tool_version()}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Missing KBs reviewed: {summary['missing_kbs_reviewed']}")
    lines.append(f"- CVEs reviewed: {summary['cves_reviewed']}")
    lines.append(f"- Highest policy risk: {summary['highest_policy_risk']:.2f}")
    lines.append(f"- Highest ML risk: {summary['highest_ml_risk']:.2f}")
    lines.append(f"- Highest priority: {summary['highest_priority']}")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append(
        "WinShield+ ranks missing Windows KBs using a transparent policy risk "
        "score as the primary remediation signal. Machine learning outputs are "
        "included as supporting evidence: regression provides a learned risk "
        "estimate, classification provides a learned priority band, and "
        "clustering groups similar vulnerability rows for triage context."
    )
    lines.append("")
    lines.append("## Ranked Remediation")
    lines.append("")
    lines.append(
        "| Rank | KB | Policy Risk | ML Risk | Priority | ML Priority | Cluster | CVEs | Top Driver |"
    )
    lines.append(
        "|---:|---|---:|---:|---|---|---:|---:|---|"
    )

    for index, entry in enumerate(results, start=1):
        lines.append(
            "| "
            f"{index} | "
            f"{entry.get('kb_id', 'Unknown')} | "
            f"{safe_float(entry.get('policy_risk')):.2f} | "
            f"{safe_float(entry.get('ml_risk')):.2f} | "
            f"{entry.get('policy_priority', 'Unknown')} | "
            f"{entry.get('ml_priority', 'Unknown')} | "
            f"{safe_int(entry.get('cluster'))} | "
            f"{safe_int(entry.get('cve_count'))} | "
            f"{entry.get('top_driver', 'Unknown')} |"
        )

    lines.append("")
    lines.append("## KB Breakdown")
    lines.append("")

    for entry in results:
        kb_id = entry.get("kb_id", "Unknown")
        cves = entry.get("cves", [])

        lines.append(f"### {kb_id}")
        lines.append("")
        lines.append(f"**Policy risk:** {safe_float(entry.get('policy_risk')):.2f}")
        lines.append("")
        lines.append(f"**ML risk:** {safe_float(entry.get('ml_risk')):.2f}")
        lines.append("")
        lines.append(f"**Priority:** {entry.get('policy_priority', 'Unknown')}")
        lines.append("")
        lines.append(f"**Cluster:** {safe_int(entry.get('cluster'))}")
        lines.append("")
        lines.append(f"**CVEs:** {safe_int(entry.get('cve_count'))}")
        lines.append("")
        lines.append(f"**Review reason:** {entry.get('review_reason', 'No review reason provided.')}")
        lines.append("")
        lines.append("| CVE | Policy Risk | ML Risk | Priority | ML Priority | Cluster | Driver |")
        lines.append("|---|---:|---:|---|---|---:|---|")

        for cve in cves:
            lines.append(
                "| "
                f"{cve.get('cve_id', 'Unknown')} | "
                f"{safe_float(cve.get('policy_risk')):.2f} | "
                f"{safe_float(cve.get('ml_risk')):.2f} | "
                f"{cve.get('policy_priority', 'Unknown')} | "
                f"{cve.get('ml_priority', 'Unknown')} | "
                f"{safe_int(cve.get('cluster'))} | "
                f"{cve.get('top_driver', 'Unknown')} |"
            )

        lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append(
        "- Policy risk is the primary ranking signal because it is transparent "
        "and explainable."
    )
    lines.append(
        "- ML risk and ML priority are supporting signals learned from the "
        "training dataset."
    )
    lines.append(
        "- Cluster IDs indicate similarity groups and should not be treated as "
        "severity labels."
    )
    lines.append(
        "- Runtime ranking only includes KBs identified as missing during the "
        "latest scan."
    )
    lines.append("")

    return "\n".join(lines)


# ------------------------------------------------------------
# EXPORT
# ------------------------------------------------------------

def save_report(report: str, output_path: Path = REPORT_PATH) -> Path:
    """Save Markdown report to disk."""

    ensure_directory(output_path.parent)

    with output_path.open("w", encoding="utf-8") as file:
        file.write(report)

    return output_path


def generate_report() -> Path:
    """Generate the WinShield+ Markdown report from ranking results."""

    results = load_ranking_results()
    report = build_report(results)
    output_path = save_report(report)

    return output_path


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Generate a Markdown report from ranking results."""

    try:
        output_path = generate_report()
        print_success(f"Report saved: {relative_path(output_path)}")
        return 0

    except Exception as exc:
        print(f"[X] Report generation failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())