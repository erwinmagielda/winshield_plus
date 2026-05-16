# WinShield+

**Windows patch-state exposure discovery and risk-based remediation ranking.**

WinShield+ scans a Windows host, identifies missing KB updates, maps those missing patches to affected CVEs, enriches the vulnerability data with Microsoft Security Response Center metadata, and ranks remediation priority through a transparent machine learning pipeline.

The project addresses a practical security operations gap: Windows remediation is KB-driven, while vulnerability analysis is CVE-driven. WinShield+ connects those two views so a missing update can be reviewed by exposed CVEs, severity context, exploitation indicators, and KB-level remediation priority.

It is designed for controlled lab and portfolio use. It is not a replacement for Windows Update, WSUS, Intune, SCCM, Defender Vulnerability Management, or enterprise patch management. A separate companion repository, [WinShield+ Collector](https://github.com/erwinmagielda/winshield_collector), provides portable authorised-host collection and exports compatible scan JSON for dataset growth and offline analysis.

## 1. Problem

Windows Update can tell a machine how to stay current. It does not give an analyst a clear explanation of the attack surface left behind by missing patches.

That creates a practical triage problem:

```text
Missing KBs -> Many CVEs -> Mixed Severity -> Unclear Remediation Order
```

WinShield+ turns local patch state into a ranked vulnerability management workflow.

```text
Scan Host -> Map KBs To CVEs -> Enrich CVEs -> Validate Data -> Rank Missing KBs
```

The output is not just a list of missing patches. It is a reviewable evidence trail showing which CVEs are linked to those missing patches, how the vulnerability records compare, and which KB should be reviewed first.

## 2. Capabilities

| Area | Implementation |
|---|---|
| Windows Administration | Collects OS baseline, build, architecture, LCU context, admin state, and installed KB inventory. |
| Vulnerability Analysis | Correlates KB updates with MSRC CVRF advisory data to expose CVEs tied to missing Windows updates. |
| Patch Management Logic | Handles cumulative update supersedence so replaced KBs are not treated as missing exposure. |
| Data Engineering | Converts nested scan JSON into structured CSV datasets through flattening, enrichment, labelling, and validation. |
| Machine Learning | Applies regression, classification, and clustering to score, label, and group vulnerability records. |
| Operational Control | Uses explicit operator actions, dependency checks, non-destructive defaults, and reviewable output artefacts. |

## 3. Architecture

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

The workflow is split into collection, processing, modelling, and optional remediation helpers. Each stage writes structured artefacts that can be reviewed independently.

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

## 4. Model Logic

### Operator Workflow

![WinShield+ operator menu](assets/operator_menu.png)

The operator menu keeps the workflow explicit: scan, rank, download, install, clean artefacts, or rebuild models.

### Scan And Correlation

![System scan baseline and MSRC collection](assets/system_scan-1.png)

The scan stage collects host context, installed KBs, MSRC MonthIds, mapped KB entries, and missing update counts.

![KB and CVE correlation table](assets/system_scan-2.png)

The correlation table links KB status, supersedence, advisory month, and CVE mappings.

![Missing KB export summary](assets/system_scan-3.png)

The scanner exports runtime JSON for enrichment and ranking.

### Runtime Pipeline And Ranking

![Runtime data pipeline output](assets/risk_prioritisation-1.png)

Runtime data is flattened, enriched with MSRC metadata, and validated before inference.

![Risk prioritisation table](assets/risk_prioritisation-2.png)

The prioritiser ranks missing KBs using trained model artefacts and validated runtime rows.

![CVE-level breakdown](assets/risk_prioritisation-3.png)

The CVE breakdown preserves the evidence behind each KB-level recommendation.

### Risk Policy

The supervised labels are generated from a transparent rule before model training.

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

| Model | Purpose |
|---|---|
| `RandomForestRegressor` | Continuous CVE risk score. |
| `LogisticRegression` | Low, Medium, or High priority label. |
| `KMeans` | Grouping of similar vulnerability records. |

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

## 5. Operation

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

| Control | Implementation |
|---|---|
| Operator control | Download and install actions require explicit menu selection. |
| No silent remediation | Scan and ranking do not install updates. |
| No forced reboot | Installer helpers use no-restart behaviour. |
| Reviewable artefacts | Scan, pipeline, model, and ranking outputs are saved as JSON or CSV. |
| Validation gates | Rows missing required fields such as `cvss_score` or `attack_vector` are dropped before model use. |

Current status: **working lab implementation**.

Completed areas:

- Windows patch-state and MSRC correlation
- CVE exposure discovery from missing KBs
- Supersedence-aware missing update detection
- Structured training and runtime data pipelines
- CVE enrichment and validation
- Saved model artefacts
- KB-level remediation ranking
- Operator-controlled optional download/install stages

Planned improvements:

- Add pinned `requirements.txt`
- Add pytest coverage for Python pipeline logic
- Add Pester coverage for PowerShell collectors
- Add hash verification for downloaded packages
- Add pre/post scan diffing for remediation evidence
- Add CISA KEV or threat intelligence context

Limitations:

WinShield+ reports patch-linked exposure, not confirmed exploitability. A mapped CVE may require local access, user interaction, specific configuration, or a chained attack path that the tool does not validate.

MSRC advisory data can vary between months. CVSS fields, exploitation text, supersedence, and publication timing are not always perfectly uniform.

The ML layer currently learns from deterministic labels. It is useful for transparent prioritisation and portfolio demonstration, but it should support analyst judgement rather than replace it.

The installer stage is conservative by design. Windows servicing may reject, supersede, defer, or roll back individual packages depending on host state.

## Licence

MIT License. See `LICENSE`.
