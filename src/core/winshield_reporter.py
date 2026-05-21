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


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from utils.winshield_banner import print_error, print_success  # noqa: E402
from utils.winshield_paths import (  # noqa: E402
    ensure_directory,
    get_model_pipeline_summary_path,
    get_ranking_results_path,
    get_runtime_report_path,
    load_config,
)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

RANKING_RESULTS_PATH = get_ranking_results_path()
REPORT_PATH = get_runtime_report_path()
MODEL_PIPELINE_SUMMARY_PATH = get_model_pipeline_summary_path()


# ------------------------------------------------------------
# REPORT SETTINGS
# ------------------------------------------------------------

REPORT_TITLE = "WinShield+ Risk Report"


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def get_tool_version() -> str:
    """Return configured tool version."""

    config = load_config()

    return str(config.get("version", "unknown"))


def utc_timestamp() -> str:
    """Return UTC timestamp for report metadata."""

    return datetime.now(UTC).isoformat()


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


def format_metric(value: Any, decimals: int = 4) -> str:
    """Format a metric value for Markdown output."""

    if value is None:
        return "Not available"

    try:
        return f"{float(value):.{decimals}f}"
    except (TypeError, ValueError):
        return str(value)


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


def load_model_pipeline_summary(
    path: Path = MODEL_PIPELINE_SUMMARY_PATH,
) -> dict[str, Any] | None:
    """Load model pipeline summary if available."""

    if not path.is_file():
        return None

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        return None

    return data


# ------------------------------------------------------------
# MODEL EVALUATION HELPERS
# ------------------------------------------------------------

def get_stage_by_key(
    summary: dict[str, Any],
    stage_key: str,
) -> dict[str, Any] | None:
    """Return a model pipeline stage by key."""

    stages = summary.get("stages", [])

    if not isinstance(stages, list):
        return None

    for stage in stages:
        if not isinstance(stage, dict):
            continue

        if stage.get("key") == stage_key:
            return stage

    return None


def get_stage_metric(
    summary: dict[str, Any],
    stage_key: str,
    metric_name: str,
) -> Any:
    """Return a metric value from model pipeline summary."""

    stage = get_stage_by_key(summary, stage_key)

    if not stage:
        return None

    evaluation = stage.get("evaluation", {})

    if not isinstance(evaluation, dict):
        return None

    metrics = evaluation.get("metrics", {})

    if not isinstance(metrics, dict):
        return None

    return metrics.get(metric_name)


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
# MARKDOWN SECTION BUILDERS
# ------------------------------------------------------------

def append_runtime_summary(lines: list[str], results: list[dict[str, Any]]) -> None:
    """Append runtime summary."""

    summary = build_summary(results)

    lines.append("## Runtime Summary")
    lines.append("")
    lines.append(f"- Ranking results: `{relative_path(RANKING_RESULTS_PATH)}`")
    lines.append(f"- Markdown report: `{relative_path(REPORT_PATH)}`")
    lines.append(f"- Missing KBs reviewed: {summary['missing_kbs_reviewed']}")
    lines.append(f"- CVEs reviewed: {summary['cves_reviewed']}")
    lines.append(f"- Highest policy risk: {summary['highest_policy_risk']:.2f}")
    lines.append(f"- Highest ML risk: {summary['highest_ml_risk']:.2f}")
    lines.append(f"- Highest priority: {summary['highest_priority']}")
    lines.append("")


def append_model_evaluation(lines: list[str]) -> None:
    """Append model evaluation summary."""

    model_summary = load_model_pipeline_summary()

    lines.append("## Model Evaluation")
    lines.append("")

    if not model_summary:
        lines.append(
            "Model evaluation is not available because "
            f"`{relative_path(MODEL_PIPELINE_SUMMARY_PATH)}` was not found."
        )
        lines.append("")
        return

    lines.append(f"- Model summary: `{relative_path(MODEL_PIPELINE_SUMMARY_PATH)}`")
    lines.append("")
    lines.append("| Model | Metric | Value |")
    lines.append("|---|---|---:|")
    lines.append(
        "| Regression | MAE | "
        f"{format_metric(get_stage_metric(model_summary, 'regression', 'mae'))} |"
    )
    lines.append(
        "| Regression | RMSE | "
        f"{format_metric(get_stage_metric(model_summary, 'regression', 'rmse'))} |"
    )
    lines.append(
        "| Regression | R2 | "
        f"{format_metric(get_stage_metric(model_summary, 'regression', 'r2'))} |"
    )
    lines.append(
        "| Classification | Accuracy | "
        f"{format_metric(get_stage_metric(model_summary, 'classification', 'accuracy'))} |"
    )
    lines.append(
        "| Classification | Weighted F1 | "
        f"{format_metric(get_stage_metric(model_summary, 'classification', 'weighted_f1'))} |"
    )
    lines.append(
        "| Clustering | Clusters created | "
        f"{format_metric(get_stage_metric(model_summary, 'clustering', 'clusters_created'), decimals=0)} |"
    )
    lines.append("")


def append_method(lines: list[str]) -> None:
    """Append prioritisation method."""

    lines.append("## Method")
    lines.append("")
    lines.append(
        "WinShield+ ranks missing Windows KBs using policy risk as the primary "
        "remediation signal. Machine learning outputs are included as supporting "
        "evidence: regression provides a learned risk estimate, classification "
        "provides a learned priority band, and clustering groups similar "
        "vulnerability rows for triage context."
    )
    lines.append("")


def append_ranked_remediation(lines: list[str], results: list[dict[str, Any]]) -> None:
    """Append ranked remediation table."""

    lines.append("## Ranked Remediation")
    lines.append("")
    lines.append(
        "| Rank | KB | Policy Risk | ML Risk | Priority | ML Priority | Cluster | CVEs | Top Driver |"
    )
    lines.append("|---:|---|---:|---:|---|---|---:|---:|---|")

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


def append_review_drivers(lines: list[str], results: list[dict[str, Any]]) -> None:
    """Append concise review drivers below ranked remediation."""

    lines.append("## Review Drivers")
    lines.append("")

    if not results:
        lines.append("No review drivers were generated.")
        lines.append("")
        return

    for entry in results:
        kb_id = entry.get("kb_id", "Unknown")
        reason = entry.get("review_reason", "No review reason provided.")

        lines.append(f"- {kb_id}: {reason}")

    lines.append("")


def append_notes(lines: list[str]) -> None:
    """Append report notes."""

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


# ------------------------------------------------------------
# MARKDOWN BUILDING
# ------------------------------------------------------------

def build_report(results: list[dict[str, Any]]) -> str:
    """Build the Markdown runtime risk report."""

    lines: list[str] = []

    lines.append(f"# {REPORT_TITLE}")
    lines.append("")
    lines.append(f"Generated UTC: {utc_timestamp()}")
    lines.append(f"Tool version: {get_tool_version()}")
    lines.append("")

    append_runtime_summary(lines, results)
    append_model_evaluation(lines)
    append_method(lines)
    append_ranked_remediation(lines, results)
    append_review_drivers(lines, results)
    append_notes(lines)

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

    return save_report(report)


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
        print_error(f"Report generation failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())