# WinShield+

**Windows patch-state exposure discovery, MSRC enrichment, and remediation prioritisation.**

[Companion Project: WinShield+ Collector](https://github.com/erwinmagielda/winshield_collector)

WinShield+ is a Windows security engineering project that transforms local patch state into structured vulnerability evidence. It scans a Windows host, identifies missing or superseded KB updates, maps those packages to exposed CVEs using Microsoft Security Response Center (MSRC) data, enriches the vulnerability records, and ranks remediation priority at the operational KB level.

The project addresses a practical gap in vulnerability management:

> Windows patching is package-driven through KB updates, while vulnerability analysis is CVE-driven. WinShield+ connects those views so an analyst can move from missing patch state to evidence-backed remediation order.

WinShield+ is designed for controlled lab and portfolio environments. It is not a replacement for WSUS, Intune, SCCM, Defender Vulnerability Management, or enterprise patch management.

---

## Overview

WinShield+ combines PowerShell-based Windows collection with Python-based data processing, enrichment, model execution, and reporting.

The project demonstrates:

- Windows patch-state collection and baseline extraction
- MSRC KB-to-CVE correlation
- Supersedence-aware missing update detection
- Structured JSON and CSV artefact generation
- Runtime and training data pipelines
- CVSS and vulnerability metadata enrichment
- Regression, classification, and clustering workflows
- KB-level remediation prioritisation
- Optional download and installation support
- Companion collector support for portable scan harvesting

---

## Screenshots

### Operator Menu

![WinShield+ operator menu](assets/operator_menu.png)

### System Scan

![System scan](assets/system_scan-1.png)

### KB And CVE Correlation

![KB and CVE correlation](assets/system_scan-2.png)

### Runtime Export

![Runtime export](assets/system_scan-3.png)

### Model Setup

![Model setup](assets/model_setup.png)

### Runtime Pipeline

![Runtime pipeline](assets/risk_prioritisation-1.png)

### Risk Prioritisation

![Risk prioritisation](assets/risk_prioritisation-2.png)

### CVE Breakdown

![CVE breakdown](assets/risk_prioritisation-3.png)

---

## Technical Capabilities

| Area | Implementation |
|---|---|
| Core Stack | Python, PowerShell, Pandas, Scikit-Learn, Joblib, BeautifulSoup, MSRC PowerShell module |
| Windows Security | Collects OS baseline, build, architecture, LCU context, elevation state, and installed KB inventory |
| Vulnerability Analysis | Maps KB updates to CVEs using MSRC CVRF advisory data |
| Patch Logic | Resolves supersedence so newer cumulative updates can logically satisfy older KBs |
| Data Engineering | Converts nested host scan JSON into validated training and runtime datasets |
| Model Layer | Applies regression, classification, and clustering to support risk ranking and analysis |
| Operational Control | Uses explicit menu actions, dependency checks, no silent remediation, and reviewable artefacts |

---

## Architecture

```text
src/
├── powershell/
│   ├── winshield_baseline.ps1
│   │   Collects OS build, architecture, LCU context, admin state, and MSRC product hint.
│   │
│   ├── winshield_inventory.ps1
│   │   Enumerates installed KBs through Get-HotFix and Get-WindowsPackage.
│   │
│   ├── winshield_adapter.ps1
│   │   Queries MSRC CVRF data and maps KB updates to affected CVEs and supersedence data.
│   │
│   └── winshield_metadata.ps1
│       Enriches CVEs with CVSS score, vector fields, severity, publication date, and exploitation status.
│
├── core/
│   ├── winshield_master.py
│   │   Provides the interactive operator menu and workflow orchestration.
│   │
│   ├── winshield_scanner.py
│   │   Runs host scanning, KB/CVE correlation, supersedence handling, and runtime JSON export.
│   │
│   ├── winshield_prioritiser.py
│   │   Loads saved model artefacts, ranks missing KBs, and exports prioritisation results.
│   │
│   ├── winshield_downloader.py
│   │   Optionally resolves and downloads selected update packages from Microsoft Update Catalog.
│   │
│   └── winshield_installer.py
│       Optionally installs selected .msu or .cab packages through WUSA or DISM.
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
    │   Trains the LogisticRegression model used for priority labels.
    │
    └── train_clustering.py
        Trains the KMeans model used for exploratory vulnerability grouping.
```

The project separates host collection, data preparation, model execution, and optional remediation support into independent stages. Each stage communicates through structured JSON or CSV artefacts so output can be reviewed, reused, or debugged independently.

---

## Data Pipeline

Runtime data is not sent directly to the models. It passes through the same preparation path used during training so feature structure remains consistent.

```text
Training Scans
    -> data_pipeline.py --mode training
    -> validated_dataset.csv
    -> model_pipeline.py
    -> saved .joblib artefacts

Live Host Scan
    -> winshield_scanner.py
    -> runtime scan JSON
    -> data_pipeline.py --mode runtime
    -> validated_runtime.csv
    -> winshield_prioritiser.py
    -> ranking_results.json
```

This design prevents common machine learning workflow issues such as schema drift, mismatched feature columns, or dirty runtime inputs reaching the inference stage.

---

## Prioritisation

WinShield+ analyses vulnerability evidence at CVE level, then aggregates the result back to KB level because Windows remediation is applied through update packages.

The model layer uses three views:

- `RandomForestRegressor` produces a continuous CVE risk score for sorting.
- `LogisticRegression` provides readable priority labels for triage.
- `KMeans` groups similar vulnerability records for exploratory analysis.

The supervised labels are rule-derived, so the model layer should be understood as a transparent security analytics workflow rather than a claim of real-world exploit prediction. The value is in the repeatable pipeline: enrichment, validation, reusable artefacts, runtime inference, and KB-level aggregation.

---

## Operation

Run the main launcher from the repository root:

```bat
winshield_plus.bat
```

The launcher performs pre-flight checks before opening the operator menu. It verifies Windows execution, requests administrator elevation, checks PowerShell and Python availability, confirms required source files, checks the MSRC PowerShell module, and verifies Python package dependencies.

Recommended first run:

```text
6) Model Setup
1) Scan System
2) Rank Risk
```

### Model Setup

Builds the training dataset, trains regression, classification, and clustering models, and saves reusable artefacts into `models/`.

### Scan System

Collects host baseline, installed KB inventory, MSRC KB/CVE mappings, supersedence relationships, and missing KB results. The scan is exported as runtime JSON.

### Rank Risk

Converts the latest runtime scan into validated model-ready rows, applies saved model artefacts, and writes ranked remediation output to `results/ranking_results.json`.

### Optional Actions

`Download Update` can retrieve a selected missing package from Microsoft Update Catalog.

`Install Update` can install a selected `.msu` or `.cab` package through WUSA or DISM. It does not force a restart.

`Clear Artefacts` removes generated runtime, dataset, model, result, and download artefacts while preserving source scans.

---

## Companion Collector

WinShield+ is supported by a separate repository: [WinShield+ Collector](https://github.com/erwinmagielda/winshield_collector).

The collector is a portable host-scanning tool that exports the same scan JSON contract used by WinShield+. It allows authorised endpoint scan data to be collected separately and later used for dataset growth or offline analysis.

```text
Authorised Host
    -> WinShield+ Collector
    -> Compatible Scan JSON
    -> WinShield+ Dataset Or Runtime Pipeline
```

---

## Project Status

Current status: **complete portfolio implementation**.

Completed areas include:

- Windows patch-state collection
- MSRC advisory correlation
- Missing KB exposure discovery
- Supersedence-aware scan logic
- Runtime and training data pipelines
- CVE enrichment and validation
- Reusable model artefacts
- KB-level prioritisation workflow
- Optional download and installation support
- Portable companion collector workflow

Future development under a new repository could focus on:

- pre-patch and post-patch verification
- practical CVE targeting for testing relevance
- richer threat intelligence and exploit trend features
- improved class balance and model evaluation
- clearer cluster interpretation
- package hash verification and artefact integrity checks
- stronger support for legacy Windows servicing behaviour

---

## Limitations

WinShield+ reports patch-linked exposure, not confirmed exploitability. A mapped CVE may require local access, user interaction, specific configuration, or a chained attack path that the tool does not validate.

MSRC advisory structure, Microsoft Update Catalog layout, and Windows servicing behaviour can change over time. These upstream dependencies may affect parsing, package resolution, or update applicability.

The machine learning layer currently learns from rule-derived labels. It supports transparent prioritisation and portfolio demonstration, but it does not replace analyst judgement or enterprise patch governance.

---

## Licence

MIT License. See `LICENSE`.
