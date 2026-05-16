# WinShield+

**Windows patch-state exposure discovery and risk-based remediation ranking.**

WinShield+ is a Windows security engineering project that turns local patch state into reviewable vulnerability evidence. It scans a host, identifies missing KB updates, maps those missing patches to affected CVEs, enriches the vulnerability data with Microsoft Security Response Center metadata, and ranks remediation priority at the operational KB level.

The project addresses a practical vulnerability management gap: Windows remediation is package-driven, while vulnerability analysis is CVE-driven. WinShield+ connects those views so an operator can move from "this KB is missing" to "these CVEs are exposed, this is the supporting context, and this update should be reviewed first."

It is designed for controlled lab and portfolio use. It is not a replacement for Windows Update, WSUS, Intune, SCCM, Defender Vulnerability Management, or enterprise patch management.

## Companion Collector

WinShield+ is supported by a separate portable collection tool: [WinShield+ Collector](https://github.com/erwinmagielda/winshield_collector).

The collector is designed for authorised Windows hosts where the full analysis environment is not required. It collects compatible patch-state JSON using the same baseline, inventory, and MSRC correlation logic, then archives the scan for later analysis inside WinShield+.

```text
Authorised Host -> Portable Collector -> Compatible Scan JSON -> WinShield+ Dataset / Runtime Analysis
```

This separates lightweight host harvesting from heavier processing, enrichment, model training, and prioritisation. The two repositories work as a small tooling ecosystem rather than a single monolithic script.

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
| Baseline Collection | Resolves OS version, build, architecture, LCU context, admin state, and MSRC product hint. |
| Inventory Collection | Gathers installed KBs through `Get-HotFix` and elevated Windows package data where available. |
| MSRC Correlation | Queries CVRF advisory data and maps KB articles to affected CVEs. |
| Supersedence Resolution | Treats superseded KBs as logically present when a newer installed update replaces them. |
| Runtime Export | Saves structured scan JSON for enrichment, prioritisation, and review. |
| Data Pipeline | Flattens, enriches, labels, and validates vulnerability records. |
| Risk Ranking | Aggregates CVE-level scores back into KB-level remediation order. |

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
winshield_plus/
├── winshield_plus.bat
│   Launches WinShield+ from the repository root, checks dependencies, and requests elevation.
│
├── src/
│   ├── powershell/
│   │   ├── winshield_baseline.ps1
│   │   │   Collects OS baseline, build, architecture, LCU context, admin status, and MSRC product hint.
│   │   │
│   │   ├── winshield_inventory.ps1
│   │   │   Enumerates installed KBs using Get-HotFix and Get-WindowsPackage.
│   │   │
│   │   ├── winshield_adapter.ps1
│   │   │   Queries MSRC CVRF data and maps KB updates to affected CVEs and supersedence data.
│   │   │
│   │   └── winshield_metadata.ps1
│   │       Enriches CVEs with CVSS score, severity, vector fields, publication date, and exploitation status.
│   │
│   └── core/
│       ├── winshield_master.py
│       │   Provides the operator menu and controls the main workflow stages.
│       │
│       ├── winshield_scanner.py
│       │   Runs host scanning, KB/CVE correlation, supersedence handling, and runtime JSON export.
│       │
│       ├── winshield_prioritiser.py
│       │   Loads trained artefacts, ranks missing KBs, and exports ranking results.
│       │
│       ├── winshield_downloader.py
│       │   Optionally resolves and downloads selected update packages from Microsoft Update Catalog.
│       │
│       └── winshield_installer.py
│           Optionally installs selected .msu or .cab packages through WUSA or DISM.
│
└── training/
    ├── data_pipeline.py
    │   Builds training and runtime datasets through flattening, enrichment, labelling, and validation.
    │
    ├── model_pipeline.py
    │   Runs the regression, classification, and clustering training stages.
    │
    ├── train_regression.py
    │   Trains the RandomForestRegressor used for continuous CVE risk scoring.
    │
    ├── train_classification.py
    │   Trains the LogisticRegression model used for Low, Medium, and High priority labels.
    │
    ├── train_clustering.py
    │   Trains the KMeans model used to group similar vulnerability records.
    │
    └── clear_run.py
        Removes generated artefacts while preserving source training scans.
```

The project is split into collection, processing, modelling, and optional remediation helpers. Each stage writes structured artefacts that can be reviewed independently.

```text
data/scans/*.json
  Source scan JSON files used for training.

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

## Prioritisation

WinShield+ uses a transparent scoring policy to generate supervised training labels. This keeps the project explainable: the scoring basis can be inspected, challenged, and adjusted instead of hiding the prioritisation logic behind an opaque model.

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

The machine learning layer is not presented as a claim that a simple formula needs prediction. In this version, the formula defines the training target. The value is the surrounding pipeline: consistent feature preparation, reusable preprocessors, runtime inference, CVE-level scoring, clustering, and KB-level aggregation.

That structure is useful because additional inputs can be introduced later without redesigning the workflow. Examples include threat intelligence, asset criticality, exposed services, compensating controls, CISA KEV status, or real incident outcomes.

| Model | Purpose |
|---|---|
| `RandomForestRegressor` | Produces a continuous CVE risk score from validated features. |
| `LogisticRegression` | Assigns a Low, Medium, or High triage label. |
| `KMeans` | Groups vulnerability records with similar feature patterns. |

At runtime, predictions are created at CVE level and aggregated back to KB level. The maximum CVE risk determines the KB ranking because one serious vulnerability can justify urgent review.

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

WinShield+ is launched from a Windows batch file that performs pre-flight checks before opening the Python operator menu. The launcher verifies that it is running on Windows, requests administrator elevation, checks for PowerShell and Python, confirms the required PowerShell scripts are present, checks the `MsrcSecurityUpdates` module, and verifies the required Python packages.

```bat
winshield_plus.bat
```

The normal workflow is:

```text
6) Model Setup
1) Scan System
2) Rank Risk
```

`Model Setup` prepares the training dataset and writes reusable model artefacts into `models/`. `Scan System` collects the current host baseline, inventory, MSRC correlation data, supersedence-aware missing KB list, and runtime scan JSON. `Rank Risk` converts that runtime scan into validated rows, applies the saved models, and writes the ranked output to `results/ranking_results.json`.

Manual launch is also supported:

```powershell
Install-Module MsrcSecurityUpdates -Scope CurrentUser
python -m pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
python src/core/winshield_master.py
```

| Action | Behaviour |
|---|---|
| Model Setup | Runs the training data pipeline and model pipeline, then saves reusable artefacts. |
| Scan System | Collects host patch state, correlates KBs with CVEs, resolves supersedence, and exports runtime JSON. |
| Rank Risk | Builds validated runtime data, applies saved models, and ranks missing KBs. |
| Download Update | Optionally downloads a selected missing package from Microsoft Update Catalog. |
| Install Update | Optionally installs a selected `.msu` or `.cab` package through WUSA or DISM. |
| Clear Artefacts | Removes generated runtime, dataset, model, result, and download artefacts while preserving source scans. |

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
