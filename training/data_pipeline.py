"""
WinShield+ data pipeline.

Builds training and runtime datasets from WinShield+ scan JSON files.
The pipeline flattens KB/CVE/month relationships, enriches CVEs with MSRC
metadata, optionally labels training data, validates model-ready rows, and
exports a pipeline summary to results/.
"""

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

SCANS_DIR = DATA_DIR / "scans"
RUNTIME_DIR = DATA_DIR / "runtime"
DATASET_DIR = DATA_DIR / "dataset"
RESULTS_DIR = BASE_DIR / "results"

POWERSHELL_SCRIPT = BASE_DIR / "src" / "powershell" / "winshield_metadata.ps1"

RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
DATASET_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


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
# SUMMARY HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a project-relative path for summary output."""

    return str(path.relative_to(BASE_DIR))


def utc_timestamp() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_pipeline_summary(mode: str, summary: dict[str, Any]) -> Path:
    """Save pipeline summary JSON to the results directory."""

    output_path = RESULTS_DIR / f"{mode}_pipeline_summary.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    print(f"[+] Pipeline summary saved to {output_path}")

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
        raise RuntimeError("No runtime scans found. Run winshield_scanner.py first.")

    return scan_files[0]


def find_training_scans() -> list[Path]:
    """Return available training scan JSON files."""

    scan_files = sorted(SCANS_DIR.glob("*.json"))

    if not scan_files:
        raise RuntimeError("No training scans found in data/scans.")

    return scan_files


# ------------------------------------------------------------
# STEP 1: FLATTEN
# ------------------------------------------------------------

def flatten_scans(mode: str) -> tuple[Path, dict[str, Any]]:
    """Flatten scan JSON files into KB/CVE/month rows."""

    if mode == "training":
        scan_files = find_training_scans()
        output_path = DATASET_DIR / "flattened_dataset.csv"
        source_directory = SCANS_DIR
    else:
        scan_files = [find_latest_runtime_scan()]
        output_path = RUNTIME_DIR / "flattened_runtime.csv"
        source_directory = RUNTIME_DIR

    rows: list[dict[str, Any]] = []

    for scan_path in scan_files:
        with scan_path.open("r", encoding="utf-8") as file:
            scan = json.load(file)

        for patch in scan.get("KbEntries", []):
            kb_id = patch.get("KB")
            months = patch.get("Months", [])
            cves = patch.get("Cves", [])

            if not kb_id or not months or not cves:
                continue

            for cve_id in cves:
                for month_id in months:
                    rows.append(
                        {
                            "kb_id": kb_id,
                            "cve_id": str(cve_id).strip().upper(),
                            "month": str(month_id).strip(),
                        }
                    )

    flattened_data = pd.DataFrame(rows)
    flattened_data.to_csv(output_path, index=False)

    summary = {
        "scan_files": len(scan_files),
        "source_directory": relative_path(source_directory),
        "source_files": [relative_path(path) for path in scan_files],
        "rows_created": int(len(flattened_data)),
        "unique_kbs": int(flattened_data["kb_id"].nunique()) if not flattened_data.empty else 0,
        "unique_cves": int(flattened_data["cve_id"].nunique()) if not flattened_data.empty else 0,
        "unique_months": int(flattened_data["month"].nunique()) if not flattened_data.empty else 0,
        "output": relative_path(output_path),
    }

    print(f"[+] Flatten saved to {output_path}")
    print(f"[i] Flatten rows: {summary['rows_created']}")

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

        raise RuntimeError("MSRC metadata collection failed.")

    stdout = result.stdout.strip()

    if not stdout:
        raise RuntimeError("MSRC metadata collection returned no output.")

    try:
        metadata = json.loads(stdout)
    except json.JSONDecodeError as exc:
        print(stdout[:1000])
        raise RuntimeError("MSRC metadata collection returned invalid JSON.") from exc

    if not isinstance(metadata, dict):
        raise RuntimeError("MSRC metadata collection returned unexpected JSON structure.")

    return {
        str(cve_id).strip().upper(): value
        for cve_id, value in metadata.items()
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
    """Enrich flattened rows with MSRC CVE metadata and parsed CVSS fields."""

    output_path = Path(str(input_csv).replace("flattened", "enriched"))

    flattened_data = pd.read_csv(input_csv)

    month_ids = sorted(
        str(month).strip()
        for month in flattened_data["month"].dropna().unique()
        if str(month).strip()
    )

    metadata = fetch_msrc_metadata(month_ids)

    requested_cves = sorted(
        str(cve).strip().upper()
        for cve in flattened_data["cve_id"].dropna().unique()
    )

    matched_cves = [cve for cve in requested_cves if cve in metadata]
    missing_cves = [cve for cve in requested_cves if cve not in metadata]

    print(f"[i] MonthIds requested: {', '.join(month_ids)}")
    print(f"[i] Metadata CVEs returned: {len(metadata)}")
    print(f"[i] Requested CVEs: {len(requested_cves)}")
    print(f"[i] Matched CVEs: {len(matched_cves)}")
    print(f"[i] Missing CVEs: {len(missing_cves)}")

    if missing_cves:
        print("[i] First missing CVEs:")
        for cve_id in missing_cves[:10]:
            print(f"    - {cve_id}")

    today = datetime.now(UTC)
    enriched_rows: list[dict[str, Any]] = []

    for _, row in flattened_data.iterrows():
        cve_id = str(row["cve_id"]).strip().upper()
        cve_metadata = metadata.get(cve_id, {})

        published_date = cve_metadata.get("PublishedDate")
        patch_age_days = calculate_patch_age_days(published_date, today)

        enriched_rows.append(
            {
                **row,
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
    enriched_data.to_csv(output_path, index=False)

    summary = {
        "month_ids_requested": month_ids,
        "metadata_cves_returned": int(len(metadata)),
        "requested_cves": int(len(requested_cves)),
        "matched_cves": int(len(matched_cves)),
        "missing_cves": int(len(missing_cves)),
        "first_missing_cves": missing_cves[:10],
        "output": relative_path(output_path),
    }

    print(f"[+] Enrich saved to {output_path}")

    return output_path, summary


# ------------------------------------------------------------
# STEP 3: LABEL
# ------------------------------------------------------------

def compute_risk_label(row: pd.Series) -> tuple[float, str]:
    """Compute a training risk score and priority label from enriched CVE data."""

    score = float(row.get("cvss_score") or 0)

    if "Exploited:Yes" in str(row.get("exploitation")):
        score += 2

    if row.get("attack_vector") == "N":
        score += 1

    patch_age_days = row.get("patch_age_days")

    if pd.notna(patch_age_days):
        score += float(patch_age_days) / 60

    if score >= 9:
        priority_label = "High"
    elif score >= 6:
        priority_label = "Medium"
    else:
        priority_label = "Low"

    return round(score, 2), priority_label


def label_training_data(input_csv: Path) -> tuple[Path, dict[str, Any]]:
    """Apply synthetic risk labels for supervised model training."""

    enriched_data = pd.read_csv(input_csv)

    enriched_data[["risk_score", "priority_label"]] = enriched_data.apply(
        lambda row: pd.Series(compute_risk_label(row)),
        axis=1,
    )

    output_path = Path(str(input_csv).replace("enriched", "labelled"))
    enriched_data.to_csv(output_path, index=False)

    label_distribution = {
        str(label): int(count)
        for label, count in enriched_data["priority_label"].value_counts().items()
    }

    summary = {
        "rows_labelled": int(len(enriched_data)),
        "label_distribution": label_distribution,
        "output": relative_path(output_path),
    }

    print(f"[+] Label saved to {output_path}")

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

    pipeline_data = pd.read_csv(input_csv)

    before_count = len(pipeline_data)

    pipeline_data["cve_id"] = pipeline_data["cve_id"].astype(str).str.strip().str.upper()
    pipeline_data = pipeline_data[pipeline_data["cve_id"].str.startswith("CVE-")]

    required_columns = [
        "cvss_score",
        "attack_vector",
    ]

    pipeline_data = ensure_required_columns(
        dataframe=pipeline_data,
        required_columns=required_columns,
    )

    pipeline_data = pipeline_data.dropna(subset=required_columns)

    after_count = len(pipeline_data)
    dropped_count = before_count - after_count

    source_stage = "labelled" if mode == "training" else "enriched"
    output_path = Path(str(input_csv).replace(source_stage, "validated"))

    pipeline_data.to_csv(output_path, index=False)

    summary = {
        "rows_before": int(before_count),
        "rows_after": int(after_count),
        "rows_dropped": int(dropped_count),
        "required_columns": required_columns,
        "drop_reason": "Rows missing cvss_score or attack_vector are removed.",
        "output": relative_path(output_path),
    }

    print(f"[+] Validate saved to {output_path}")
    print(f"[i] Validation rows before: {before_count}")
    print(f"[i] Validation rows after:  {after_count}")
    print(f"[i] Validation dropped:     {dropped_count}")

    if after_count == 0:
        print("[!] Warning: validation produced an empty dataset.")

    return output_path, summary


# ------------------------------------------------------------
# MAIN PIPELINE
# ------------------------------------------------------------

def run_pipeline(mode: str) -> Path:
    """Run the selected WinShield+ data pipeline mode."""

    print(f"\n=== Data Pipeline ({mode}) ===\n")

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

    output_path, validate_summary = validate_data(output_path, mode)
    summary["validate"] = validate_summary

    summary["final_output"] = relative_path(output_path)
    summary["status"] = "completed"

    save_pipeline_summary(mode, summary)

    print("\n=== Pipeline Complete ===\n")

    return output_path


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    arguments = parse_args()
    run_pipeline(arguments.mode)