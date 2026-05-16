# WinShield+

**Windows patch-state exposure discovery and risk-based remediation ranking.**

WinShield+ is a Windows security engineering project that turns local patch state into reviewable vulnerability evidence. It scans a host, identifies missing KB updates, maps those missing patches to affected CVEs, enriches the data with Microsoft Security Response Center metadata, and ranks remediation priority at the operational KB level.

The project addresses a practical gap in vulnerability management: Windows remediation is package-driven, while vulnerability analysis is CVE-driven. WinShield+ connects those views so an operator can move from "this KB is missing" to "these CVEs are exposed, this is the supporting context, and this update should be reviewed first."

It is designed for controlled lab and portfolio use. It is not a replacement for Windows Update, WSUS, Intune, SCCM, Defender Vulnerability Management, or enterprise patch management.

## Companion Collector

WinShield+ is supported by a separate portable collection tool: [WinShield+ Collector](https://github.com/erwinmagielda/winshield_collector).

The collector is designed for authorised Windows hosts where the full analysis environment is not required. It collects compatible patch-state JSON using the same baseline, inventory, and MSRC correlation logic, then archives the scan for later analysis inside WinShield+.

```text
Authorised Host -> Portable Collector -> Compatible Scan JSON -> WinShield+ Dataset / Runtime Analysis
```

This separates lightweight host harvesting from heavier processing, enrichment, model training, and prioritisation. In portfolio terms, the collector demonstrates that the project was designed as a small tooling ecosystem rather than a single monolithic script.

## Problem

Windows Update can tell a machine how to stay current. It does not give an analyst a clean explanation of the attack surface left behind by missing patches.

```text
Missing KBs -> Many CVEs -> Mixed Severity -> Unclear Remediation Order
```

WinShield+ focuses on that triage problem. The useful output is not only which patches are missing. The useful output is which CVEs are linked to those missing patches, how those vulnerability records compare, and which KB should be reviewed first.

## Approach

WinShield+ turns local patch state into a structured remediation workflow.

```text
Scan Host -> Map KBs To CVEs -> Enrich CVEs -> Validate Data -> Rank Missing KBs
```

The scanner discovers patch-linked exposure. The data pipeline turns nested scan output into model-ready rows. The prioritiser scores CVEs and aggregates results back to the KB level, because Windows remediation happens through updates, not isolated CVE fixes.

| Stage | Role |
|---|---|
| Baseline Collection | Resolve OS version, build, architecture, LCU context, admin state, and MSRC product hint. |
| Inventory Collection | Gather installed KBs through `Get-HotFix` and elevated Windows package data where available. |
| MSRC Correlation | Query CVRF advisory data and map KB articles to affected CVEs. |
| Supersedence Resolution | Treat superseded KBs as logically present when a newer installed update replaces them. |
| Runtime Export | Save structured scan JSON for enrichment, prioritisation, and review. |
| Data Pipeline | Flatten, enrich, label, and validate vulnerability records. |
| Risk Ranking | Aggregate CVE-level scores back into KB-level remediation order. |

## Capabilities

| Area | Implementation |
|---|---|
| Windows Administration | Collects OS baseline, build, architecture, LCU context, admin state, and installed KB inventory. |
| Vulnerability Analysis | Correlates KB updates with MSRC CVRF advisory data to expose CVEs tied to missing Windows updates. |
| Patch Logic | Handles cumulative update supersedence so replaced KBs are not treated as missing exposure. |
| Data Engineering | Converts nested scan JSON into structured CSV datasets through flattening, enrichment, labelling, and validation. |
| Security Analytics | Scores, labels, groups, and aggregates vulnerability records into KB-level remediation priorities. |
| Operational Control | Uses explicit operator actions, dependency checks, non-destructive defaults, and reviewable output artefacts. |

## Architecture

```text
src/
├── powershell/
│   ├── winshield_baseline.ps1     -> OS baseline, build, architecture, LCU context, MSRC product hint
│   ├── winshield_inventory.ps1    -> installed KBs via Get-HotFix and Get-WindowsPackage
│   ├── winshield_adapter.ps1      -> MSRC CVRF KB-to-CVE mapping and supersedence data
│   └── winshield_metadata.ps1     -> CVSS, severity, vector, publication date, exploitation status
│
└── core/
    ├── winshield_master.py        -> operator menu and workflow control
    ├── winshield_scanner.py       -> scan, correlate, resolve supersedence, export runtime JSON
    ├── winshield_prioritiser.py   -> load models, rank missing KBs, export ranking JSON
    ├── winshield_downloader.py    -> optional Microsoft Update Catalog package download
    └── winshield_installer.py     -> optional WUSA / DISM package installation

training/
├── data_pipeline.py               -> flatten, enrich, label, validate training/runtime data
├── model_pipeline.py              -> run regression, classification, clustering training
├── train_regression.py            -> RandomForestRegressor risk scoring model
├── train_classification.py        -> LogisticRegression priority label model
├── train_clustering.py            -> KMeans vulnerability grouping model
└── clear_run.py                   -> generated artefact cleanup

winshield_plus.bat                 -> Windows launcher with elevation and dependency checks
```

The project is split into collection, processing, modelling, and optional remediation helpers. Each stage writes structured artefacts that can be reviewed independently.

```text
data/scans/*.json
  Source scan JSON files used for training

training/data_pipeline.py --mode training
  data/dataset/flattened_dataset.csv
  data/dataset/enriched_dataset.csv
  data/dataset/labelled_dataset.csv
  data/dataset/validated_dataset.csv

training/model_pipeline.py
  models/regression_model.joblib
  models/classification_model.joblib
  models/clustering_model.joblib

src/core/winshield_scanner.py
  data/runtime/scan_YYYYMMDD_HHMMSS.json

training/data_pipeline.py --mode runtime
  data/runtime/validated_runtime.csv

src/core/winshield_prioritiser.py
  results/ranking_results.json
```

## Workflow Evidence

### Operator Menu

![WinShield+ operator menu](assets/operator_menu.png)

The operator menu keeps the workflow explicit: scan, rank, download, install, clean artefacts, or rebuild models.

### System Scan

![System scan baseline and MSRC collection](assets/system_scan-1.png)

The scan stage collects host context, installed KBs, MSRC MonthIds, mapped KB entries, and missing update counts.

### KB CVE Correlation

![KB and CVE correlation table](assets/system_scan-2.png)

The correlation table links KB status, supersedence, advisory month, and CVE mappings.

### Runtime Export

![Missing KB export summary](assets/system_scan-3.png)

The scanner exports runtime JSON for enrichment and ranking.

### Runtime Pipeline

![Runtime data pipeline output](assets/risk_prioritisation-1.png)

Runtime data is flattened, enriched with MSRC metadata, and validated before ranking.

### Risk Ranking

![Risk prioritisation table](assets/risk_prioritisation-2.png)

The prioritiser ranks missing KBs using trained artefacts and validated runtime rows.

### CVE Breakdown

![CVE-level breakdown](assets/risk_prioritisation-3.png)

The CVE breakdown preserves the evidence behind each KB-level recommendation.

## Risk Model

The current supervised labels are generated from a transparent policy before model training.

```text
risk_score = cvss_score
           + 2 if Exploited:Yes
           + 1 if attack_vector is Network
           + patch_age_days / 60
```

| Risk Score | Priority |
|---:|---|
| `>= 9` | High |
| `>= 6` | Medium |
| `< 6` | Low |

The model layer should be read as an engineering blueprint rather than a claim that machine learning is necessary for a simple deterministic formula. In this version, the labels are rule-derived so the system remains explainable and easy to validate. The value is in the repeatable pipeline: ingest host scan JSON, enrich upstream advisory records, preserve a stable feature schema, train reusable artefacts, run runtime inference, and aggregate CVE-level records back to KB-level decisions.

This structure leaves room for richer future inputs without redesigning the pipeline, such as threat intelligence, exploit maturity, asset criticality, endpoint exposure, compensating controls, or real incident outcomes.

| Model | Purpose |
|---|---|
| `RandomForestRegressor` | Produces a continuous CVE risk score from validated features. |
| `LogisticRegression` | Assigns a Low, Medium, or High triage label. |
| `KMeans` | Groups vulnerability records with similar feature patterns. |

At runtime, CVE-level predictions are aggregated back to KB level. The maximum CVE risk determines the KB ranking because one serious vulnerability can justify urgent review.

Example ranking output:

```text
results/ranking_results.json

KB5083769
  max_risk: 11.12
  classification: Medium
  cluster: 0
  cve_count: 120
  cves: individual CVE predictions retained in JSON
```

## Operation

### Quick Start

Run from the repository root on Windows.

```bat
winshield_plus.bat
```

Manual launch:

```powershell
Install-Module MsrcSecurityUpdates -Scope CurrentUser
python -m pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
python src/core/winshield_master.py
```

Recommended first run:

```text
6) Model Setup
1) Scan System
2) Rank Risk
```

Model setup must run before ranking because the prioritiser loads saved model and preprocessor artefacts from `models/`.

### Controls

| Control | Implementation |
|---|---|
| Operator Control | Download and install actions require explicit menu selection. |
| No Silent Remediation | Scan and ranking do not install updates. |
| No Forced Reboot | Installer helpers use no-restart behaviour. |
| Reviewable Artefacts | Scan, pipeline, model, and ranking outputs are saved as JSON or CSV. |
| Validation Gates | Rows missing required fields such as `cvss_score` or `attack_vector` are dropped before model use. |

### Status

Current status: **complete portfolio implementation**.

WinShield+ is considered complete in this repository. Future work may continue under a new name and repository with a broader practical scope.

Completed areas:

- Windows patch-state and MSRC correlation
- CVE exposure discovery from missing KBs
- Supersedence-aware missing update detection
- Structured training and runtime data pipelines
- CVE enrichment and validation
- Saved model artefacts
- KB-level remediation ranking
- Operator-controlled optional download/install stages

### Limitations

WinShield+ reports patch-linked exposure, not confirmed exploitability. A mapped CVE may require local access, user interaction, specific configuration, or a chained attack path that the tool does not validate.

MSRC advisory data can vary between months. CVSS fields, exploitation text, supersedence, and publication timing are not always perfectly uniform.

The ML layer currently learns from deterministic labels. It is useful for transparent prioritisation and portfolio demonstration, but it should support analyst judgement rather than replace it.

The installer stage is conservative by design. Windows servicing may reject, supersede, defer, or roll back individual packages depending on host state.

## Licence

MIT License. See `LICENSE`.
