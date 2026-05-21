"""
WinShield+ data pipeline.

Builds training and runtime datasets from WinShield+ scan JSON files.

The pipeline flattens KB/CVE/month relationships, enriches CVEs with MSRC
metadata, optionally applies shared policy labels for training, validates
model-ready CVE rows, and exports a structured pipeline summary.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd


# ------------------------------------------------------------
# IMPORT PATH SETUP
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
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
    get_dataset_dir,
    get_powershell_dir,
    get_runtime_dir,
    get_runtime_pipeline_summary_path,
    get_scan_source_dir,
    get_summaries_dir,
    get_training_pipeline_summary_path,
)
from utils.winshield_risk import apply_risk_policy  # noqa: E402


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

SCANS_DIR = get_scan_source_dir()
RUNTIME_DIR = get_runtime_dir()
DATASET_DIR = get_dataset_dir()
SUMMARIES_DIR = get_summaries_dir()

POWERSHELL_SCRIPT = get_powershell_dir() / "winshield_metadata.ps1"


# ------------------------------------------------------------
# ARGUMENT PARSING
# ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Run the WinShield+ training or runtime data pipeline."
    )

    parser.add_argument(
        "--mode",
        default="training",
        choices=["training", "runtime"],
        help="Pipeline mode to run.",
    )

    return parser.parse_args()


# ------------------------------------------------------------
# DISPLAY AND SUMMARY HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a repository-relative path for clean output."""

    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def print_pipeline_header(mode: str) -> None:
    """Print the data pipeline header."""

    print()
    print(f"Data pipeline ({mode})")
    print("=" * 60)


def get_summary_path(mode: str) -> Path:
    """Return the pipeline summary path for the selected mode."""

    if mode == "training":
        return get_training_pipeline_summary_path()

    return get_runtime_pipeline_summary_path()


def prepare_pipeline_directories() -> None:
    """Ensure required pipeline output directories exist."""

    for directory in [RUNTIME_DIR, DATASET_DIR, SUMMARIES_DIR]:
        ensure_directory(directory)


def save_pipeline_summary(mode: str, summary: dict[str, Any]) -> Path:
    """Save pipeline summary JSON to the summaries directory."""

    output_path = get_summary_path(mode)

    ensure_directory(output_path.parent)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print_success(f"Summary saved: {relative_path(output_path)}")

    return output_path


# ------------------------------------------------------------
# SCAN DISCOVERY
# ------------------------------------------------------------

def find_latest_runtime_scan() -> Path:
    """Return the newest runtime scan exported by winshield_scanner.py."""

    scan_files = sorted(
        RUNTIME_DIR.glob("scan_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not scan_files:
        raise RuntimeError("No runtime scans found. Run Scan System first.")

    return scan_files[0]


def find_training_scans() -> list[Path]:
    """Return available training scan JSON files."""

    scan_files = sorted(SCANS_DIR.glob("*.json"))

    if not scan_files:
        raise RuntimeError("No training scans found in data/scans")

    return scan_files


def load_scan(path: Path) -> dict[str, Any]:
    """Load a WinShield+ scan JSON file."""

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise RuntimeError(f"Scan has unexpected structure: {relative_path(path)}")

    return data


# ------------------------------------------------------------
# CVE VALIDATION HELPERS
# ------------------------------------------------------------

def is_cve_id(value: Any) -> bool:
    """Return True if a value looks like a CVE identifier."""

    text = str(value).strip().upper()

    if not text.startswith("CVE-"):
        return False

    parts = text.split("-")

    if len(parts) != 3:
        return False

    year = parts[1]
    sequence = parts[2]

    return year.isdigit() and len(year) == 4 and sequence.isdigit() and len(sequence) >= 4


def normalise_cve_id(value: Any) -> str:
    """Return a normalised uppercase CVE identifier."""

    return str(value).strip().upper()


def normalise_kb_id(value: Any) -> str:
    """Return a normalised uppercase KB identifier."""

    return str(value).strip().upper()


# ------------------------------------------------------------
# STEP 1: FLATTEN
# ------------------------------------------------------------

def get_flatten_sources(mode: str) -> tuple[list[Path], Path, Path]:
    """Return scan files, output path, and source directory for flattening."""

    if mode == "training":
        return find_training_scans(), DATASET_DIR / "flattened_dataset.csv", SCANS_DIR

    return [find_latest_runtime_scan()], RUNTIME_DIR / "flattened_runtime.csv", RUNTIME_DIR


def flatten_scans(mode: str) -> tuple[Path, dict[str, Any]]:
    """Flatten scan JSON files into KB/CVE/month rows."""

    print_section("Flatten")

    scan_files, output_path, source_directory = get_flatten_sources(mode)

    print_step(f"Source directory: {relative_path(source_directory)}")
    print_info(f"Scan files discovered: {len(scan_files)}")

    for scan_path in scan_files:
        print(f"    - {relative_path(scan_path)}")

    rows: list[dict[str, Any]] = []
    skipped_kb_entries = 0
    skipped_non_cve_ids = 0

    for scan_path in scan_files:
        scan = load_scan(scan_path)

        missing_kbs = {
            normalise_kb_id(kb)
            for kb in scan.get("MissingKbs", [])
            if str(kb).strip()
        }

        print_info(f"Processing scan: {relative_path(scan_path)}")
        print_info(f"KB entries available: {len(scan.get('KbEntries', []) or [])}")

        if mode == "runtime":
            print_info(f"Missing KB filter: {len(missing_kbs)} KBs")

        for patch in scan.get("KbEntries", []):
            kb_id = normalise_kb_id(patch.get("KB"))

            if mode == "runtime" and kb_id not in missing_kbs:
                skipped_kb_entries += 1
                continue

            months = patch.get("Months", [])
            cve_ids = patch.get("Cves", [])

            if not kb_id or not months or not cve_ids:
                skipped_kb_entries += 1
                continue

            for cve_id in cve_ids:
                cve_id = normalise_cve_id(cve_id)

                if not is_cve_id(cve_id):
                    skipped_non_cve_ids += 1
                    continue

                for month_id in months:
                    rows.append(
                        {
                            "kb_id": kb_id,
                            "cve_id": cve_id,
                            "month": str(month_id).strip(),
                        }
                    )

    raw_row_count = len(rows)
    flattened_data = pd.DataFrame(rows)

    if not flattened_data.empty:
        flattened_data = flattened_data.drop_duplicates(
            subset=["kb_id", "cve_id", "month"]
        )

    deduplicated_count = len(flattened_data)
    duplicate_rows_removed = raw_row_count - deduplicated_count

    flattened_data.to_csv(output_path, index=False)

    summary = {
        "scan_files": len(scan_files),
        "source_directory": relative_path(source_directory),
        "source_files": [relative_path(path) for path in scan_files],
        "raw_rows_created": int(raw_row_count),
        "duplicate_rows_removed": int(duplicate_rows_removed),
        "rows_created": int(deduplicated_count),
        "skipped_kb_entries": int(skipped_kb_entries),
        "skipped_non_cve_ids": int(skipped_non_cve_ids),
        "unique_kbs": int(flattened_data["kb_id"].nunique()) if not flattened_data.empty else 0,
        "unique_cves": int(flattened_data["cve_id"].nunique()) if not flattened_data.empty else 0,
        "unique_months": int(flattened_data["month"].nunique()) if not flattened_data.empty else 0,
        "output": relative_path(output_path),
    }

    print_success(f"Raw rows created: {summary['raw_rows_created']}")
    print_success(f"Duplicate rows removed: {summary['duplicate_rows_removed']}")
    print_success(f"Rows created: {summary['rows_created']}")
    print_info(f"Skipped KB entries: {summary['skipped_kb_entries']}")
    print_info(f"Skipped non-CVE IDs: {summary['skipped_non_cve_ids']}")
    print_success(f"Unique KBs: {summary['unique_kbs']}")
    print_success(f"Unique CVEs: {summary['unique_cves']}")
    print_success(f"Unique months: {summary['unique_months']}")
    print_success(f"Output: {relative_path(output_path)}")

    return output_path, summary


# ------------------------------------------------------------
# CVSS PARSING
# ------------------------------------------------------------

def empty_cvss_metrics() -> dict[str, str | None]:
    """Return empty CVSS metric fields to preserve DataFrame columns."""

    return {
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "scope": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None,
    }


def parse_cvss(vector: str | None) -> dict[str, str | None]:
    """Parse a CVSS vector into model-friendly metric fields."""

    if not vector:
        return empty_cvss_metrics()

    metrics: dict[str, str] = {}

    for part in str(vector).split("/"):
        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        metrics[key] = value

    parsed_metrics = empty_cvss_metrics()

    parsed_metrics.update(
        {
            "attack_vector": metrics.get("AV"),
            "attack_complexity": metrics.get("AC"),
            "privileges_required": metrics.get("PR"),
            "user_interaction": metrics.get("UI"),
            "scope": metrics.get("S"),
            "confidentiality_impact": metrics.get("C"),
            "integrity_impact": metrics.get("I"),
            "availability_impact": metrics.get("A"),
        }
    )

    return parsed_metrics


# ------------------------------------------------------------
# STEP 2: ENRICH
# ------------------------------------------------------------

def fetch_msrc_metadata(month_ids: list[str]) -> dict[str, Any]:
    """Fetch CVE metadata from MSRC for the supplied MonthIds."""

    if not POWERSHELL_SCRIPT.is_file():
        raise RuntimeError(f"PowerShell script missing: {relative_path(POWERSHELL_SCRIPT)}")

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(POWERSHELL_SCRIPT),
            "-MonthIds",
            ",".join(month_ids),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip())

        raise RuntimeError("MSRC metadata collection failed")

    stdout = result.stdout.strip()

    if not stdout:
        raise RuntimeError("MSRC metadata collection returned no output")

    try:
        metadata = json.loads(stdout)
    except json.JSONDecodeError as exc:
        print(stdout[:1000])
        raise RuntimeError("MSRC metadata collection returned invalid JSON") from exc

    if not isinstance(metadata, dict):
        raise RuntimeError("MSRC metadata collection returned unexpected JSON structure")

    return {
        normalise_cve_id(cve_id): value
        for cve_id, value in metadata.items()
        if is_cve_id(cve_id)
    }


def calculate_patch_age_days(published_date: str | None, today: datetime) -> int | None:
    """Calculate patch age in days from an MSRC publication date."""

    if not published_date:
        return None

    try:
        parsed_date = datetime.fromisoformat(
            str(published_date).replace("Z", "")
        ).replace(tzinfo=UTC)

        return (today - parsed_date).days

    except ValueError:
        return None


def enrich_data(input_csv: Path) -> tuple[Path, dict[str, Any]]:
    """Enrich flattened CVE rows with MSRC metadata and parsed CVSS fields."""

    print_section("Enrich")

    output_path = Path(str(input_csv).replace("flattened", "enriched"))
    flattened_data = pd.read_csv(input_csv)

    if flattened_data.empty:
        raise RuntimeError("Flattened dataset is empty")

    month_ids = sorted(
        str(month).strip()
        for month in flattened_data["month"].dropna().unique()
        if str(month).strip()
    )

    print_step(f"Collecting MSRC metadata: {len(month_ids)} MonthIds")
    print_info(f"PowerShell metadata script: {relative_path(POWERSHELL_SCRIPT)}")

    metadata = fetch_msrc_metadata(month_ids)

    requested_cves = sorted(
        normalise_cve_id(cve)
        for cve in flattened_data["cve_id"].dropna().unique()
        if is_cve_id(cve)
    )

    matched_cves = [
        cve
        for cve in requested_cves
        if cve in metadata
    ]

    missing_metadata_cves = [
        cve
        for cve in requested_cves
        if cve not in metadata
    ]

    print_success(f"Metadata CVEs returned: {len(metadata)}")
    print_success(f"Requested CVEs: {len(requested_cves)}")
    print_success(f"Matched CVEs: {len(matched_cves)}")
    print_info(f"Missing metadata CVEs: {len(missing_metadata_cves)}")

    if missing_metadata_cves:
        print_info("First missing metadata CVEs:")
        for cve in missing_metadata_cves[:10]:
            print(f"    - {cve}")

    today = datetime.now(UTC)
    enriched_rows: list[dict[str, Any]] = []

    for _, row in flattened_data.iterrows():
        cve_id = normalise_cve_id(row["cve_id"])
        cve_metadata = metadata.get(cve_id, {})

        published_date = cve_metadata.get("PublishedDate")
        patch_age_days = calculate_patch_age_days(published_date, today)

        enriched_rows.append(
            {
                **row,
                "kb_id": normalise_kb_id(row["kb_id"]),
                "cve_id": cve_id,
                "cvss_score": cve_metadata.get("BaseScore"),
                "severity": cve_metadata.get("Severity"),
                "published_date": published_date,
                "patch_age_days": patch_age_days,
                "exploitation": cve_metadata.get("Exploitation"),
                **parse_cvss(cve_metadata.get("Vector")),
            }
        )

    enriched_data = pd.DataFrame(enriched_rows)

    raw_enriched_count = len(enriched_data)

    if not enriched_data.empty:
        enriched_data = enriched_data.drop_duplicates(
            subset=["kb_id", "cve_id", "month"]
        )

    duplicate_rows_removed = raw_enriched_count - len(enriched_data)

    enriched_data.to_csv(output_path, index=False)

    cvss_available = int(enriched_data["cvss_score"].notna().sum())
    vector_available = int(enriched_data["attack_vector"].notna().sum())

    summary = {
        "month_ids_requested": month_ids,
        "metadata_cves_returned": int(len(metadata)),
        "requested_cves": int(len(requested_cves)),
        "matched_cves": int(len(matched_cves)),
        "missing_metadata_cves": int(len(missing_metadata_cves)),
        "first_missing_metadata_cves": missing_metadata_cves[:10],
        "rows_enriched": int(len(enriched_data)),
        "duplicate_rows_removed": int(duplicate_rows_removed),
        "rows_with_cvss_score": cvss_available,
        "rows_with_attack_vector": vector_available,
        "output": relative_path(output_path),
    }

    print_success(f"Rows enriched: {summary['rows_enriched']}")
    print_success(f"Duplicate rows removed: {summary['duplicate_rows_removed']}")
    print_success(f"Rows with CVSS score: {summary['rows_with_cvss_score']}")
    print_success(f"Rows with attack vector: {summary['rows_with_attack_vector']}")
    print_success(f"Output: {relative_path(output_path)}")

    return output_path, summary


# ------------------------------------------------------------
# STEP 3: LABEL
# ------------------------------------------------------------

def label_training_data(input_csv: Path) -> tuple[Path, dict[str, Any]]:
    """Apply shared risk policy labels for supervised model training."""

    print_section("Label")

    enriched_data = pd.read_csv(input_csv)

    labelled_data = apply_risk_policy(enriched_data)

    labelled_data["risk_score"] = labelled_data["policy_risk"]
    labelled_data["priority_label"] = labelled_data["policy_priority"]

    output_path = Path(str(input_csv).replace("enriched", "labelled"))
    labelled_data.to_csv(output_path, index=False)

    label_distribution = {
        str(label): int(count)
        for label, count in labelled_data["priority_label"].value_counts().items()
    }

    policy_risk_min = float(labelled_data["policy_risk"].min()) if not labelled_data.empty else 0.0
    policy_risk_max = float(labelled_data["policy_risk"].max()) if not labelled_data.empty else 0.0
    policy_risk_mean = float(labelled_data["policy_risk"].mean()) if not labelled_data.empty else 0.0

    summary = {
        "rows_labelled": int(len(labelled_data)),
        "label_distribution": label_distribution,
        "policy_risk_min": round(policy_risk_min, 2),
        "policy_risk_max": round(policy_risk_max, 2),
        "policy_risk_mean": round(policy_risk_mean, 2),
        "policy_source": "utils.winshield_risk.apply_risk_policy",
        "output": relative_path(output_path),
    }

    print_step("Applying shared policy risk labels")
    print_info("Policy source: utils.winshield_risk.apply_risk_policy")
    print_success(f"Rows labelled: {summary['rows_labelled']}")
    print_success(f"Policy risk min: {summary['policy_risk_min']:.2f}")
    print_success(f"Policy risk max: {summary['policy_risk_max']:.2f}")
    print_success(f"Policy risk mean: {summary['policy_risk_mean']:.2f}")

    print_info("Priority distribution:")
    for label, count in label_distribution.items():
        print(f"    - {label}: {count}")

    print_success(f"Output: {relative_path(output_path)}")

    return output_path, summary


# ------------------------------------------------------------
# STEP 4: VALIDATE
# ------------------------------------------------------------

def ensure_required_columns(
    dataframe: pd.DataFrame,
    required_columns: list[str],
) -> pd.DataFrame:
    """Ensure required validation columns exist before dropna checks."""

    validated_data = dataframe.copy()

    for column in required_columns:
        if column not in validated_data.columns:
            validated_data[column] = None

    return validated_data


def validate_data(input_csv: Path, mode: str) -> tuple[Path, dict[str, Any]]:
    """Validate pipeline rows and drop incomplete model inputs."""

    print_section("Validate")

    pipeline_data = pd.read_csv(input_csv)

    before_count = len(pipeline_data)

    pipeline_data["cve_id"] = pipeline_data["cve_id"].astype(str).str.strip().str.upper()
    pipeline_data["kb_id"] = pipeline_data["kb_id"].astype(str).str.strip().str.upper()

    non_cve_count = int((~pipeline_data["cve_id"].apply(is_cve_id)).sum())
    pipeline_data = pipeline_data[pipeline_data["cve_id"].apply(is_cve_id)]

    required_columns = [
        "cvss_score",
        "attack_vector",
    ]

    pipeline_data = ensure_required_columns(
        dataframe=pipeline_data,
        required_columns=required_columns,
    )

    missing_required_count = int(pipeline_data[required_columns].isna().any(axis=1).sum())

    pipeline_data = pipeline_data.dropna(subset=required_columns)

    before_deduplication = len(pipeline_data)

    if not pipeline_data.empty:
        pipeline_data = pipeline_data.drop_duplicates(
            subset=["kb_id", "cve_id", "month"]
        )

    duplicate_rows_removed = before_deduplication - len(pipeline_data)
    after_count = len(pipeline_data)
    dropped_count = before_count - after_count

    source_stage = "labelled" if mode == "training" else "enriched"
    output_path = Path(str(input_csv).replace(source_stage, "validated"))

    pipeline_data.to_csv(output_path, index=False)

    summary = {
        "rows_before": int(before_count),
        "rows_after": int(after_count),
        "rows_dropped": int(dropped_count),
        "non_cve_rows_removed": int(non_cve_count),
        "rows_missing_required_fields": int(missing_required_count),
        "duplicate_rows_removed": int(duplicate_rows_removed),
        "required_columns": required_columns,
        "drop_reason": "Rows missing cvss_score or attack_vector are removed.",
        "deduplication": "Rows are deduplicated by kb_id, cve_id, and month.",
        "output": relative_path(output_path),
    }

    print_success(f"Rows before: {summary['rows_before']}")
    print_success(f"Rows after: {summary['rows_after']}")
    print_info(f"Rows dropped: {summary['rows_dropped']}")
    print_info(f"Non-CVE rows removed: {summary['non_cve_rows_removed']}")
    print_info(f"Rows missing required fields: {summary['rows_missing_required_fields']}")
    print_info(f"Duplicate rows removed: {summary['duplicate_rows_removed']}")
    print_info("Required fields: cvss_score, attack_vector")
    print_info("Deduplication: kb_id, cve_id, month")
    print_success(f"Output: {relative_path(output_path)}")

    if after_count == 0:
        print_warning("Validation produced an empty dataset")

    return output_path, summary


# ------------------------------------------------------------
# MAIN PIPELINE
# ------------------------------------------------------------

def run_pipeline(mode: str) -> Path:
    """Run the selected WinShield+ data pipeline mode."""

    prepare_pipeline_directories()
    print_pipeline_header(mode)

    summary: dict[str, Any] = {
        "pipeline": "data_pipeline",
        "mode": mode,
        "timestamp_utc": utc_timestamp(),
        "status": "running",
    }

    output_path, flatten_summary = flatten_scans(mode)
    summary["flatten"] = flatten_summary

    output_path, enrich_summary = enrich_data(output_path)
    summary["enrich"] = enrich_summary

    if mode == "training":
        output_path, label_summary = label_training_data(output_path)
        summary["label"] = label_summary
    else:
        summary["label"] = None
        print_section("Label")
        print_info("Skipped in runtime mode")

    output_path, validate_summary = validate_data(output_path, mode)
    summary["validate"] = validate_summary

    summary["final_output"] = relative_path(output_path)
    summary["status"] = "completed"

    print_section("Summary")
    print_success(f"Final output: {relative_path(output_path)}")

    save_pipeline_summary(mode, summary)

    print()
    print_success(f"Data pipeline ({mode}) completed")

    return output_path


def main() -> int:
    """Run the WinShield+ data pipeline entry point."""

    arguments = parse_args()

    try:
        run_pipeline(arguments.mode)
        return 0

    except KeyboardInterrupt:
        print()
        print_warning("Data pipeline cancelled")
        return 130

    except Exception as exc:
        print_error(f"Data pipeline failed: {exc}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())