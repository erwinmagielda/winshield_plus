# WinShield+

**Windows patch-state exposure discovery, MSRC enrichment, and remediation prioritisation.**

[Companion Project: WinShield+ Collector](https://github.com/erwinmagielda/winshield_collector)

WinShield+ is a Windows security engineering project that transforms local patch state into structured vulnerability evidence. It scans a Windows host, identifies missing or superseded KB updates, maps those packages to exposed CVEs using Microsoft Security Response Center (MSRC) data, enriches the vulnerability records, and ranks remediation priority at the operational KB level.

The project addresses a practical vulnerability management gap:

> Windows patching is package-driven through KB updates, while vulnerability analysis is CVE-driven. WinShield+ connects those views so an analyst can move from missing patch state to evidence-backed remediation order.

WinShield+ is designed for controlled lab and portfolio environments. It is not a replacement for WSUS, Intune, SCCM, Defender Vulnerability Management, or enterprise patch management.

---

## Overview

WinShield+ combines PowerShell-based Windows collection with Python-based data processing, enrichment, model execution, and reporting. The project demonstrates how patch telemetry can be converted into actionable security evidence while preserving transparency across each stage of the workflow.

The project demonstrates:

- Windows patch-state collection is performed through dedicated PowerShell modules that gather baseline, inventory, and servicing context.
- Missing KB exposure is identified by correlating local update state with MSRC advisory data and CVE mappings.
- Supersedence-aware scan logic reduces false missing-patch findings by recognising when newer cumulative updates satisfy older KBs.
- Structured JSON and CSV artefacts preserve a repeatable evidence trail for review, troubleshooting, and security assessment.
- Runtime and training pipelines keep feature preparation consistent between model training and live inference.
- CVSS enrichment and metadata parsing convert raw advisory data into usable security analytics features.
- Regression, classification, and clustering provide different analytical views over the same vulnerability dataset.
- KB-level prioritisation translates CVE-level evidence back into the package-based language used by Windows remediation.
- Optional download and installation stages demonstrate controlled remediation support without silent system modification.
- The companion collector supports portable scan harvesting from authorised hosts for dataset growth and offline analysis.

---

## Screenshots

### Operator Menu

![WinShield+ operator menu](assets/operator_menu.png)

The operator menu provides a single entry point for scanning, ranking, downloading, installing, clearing generated artefacts, and rebuilding model artefacts.

### System Scan

![System scan](assets/system_scan-1.png)

The scan stage collects host baseline data, installed KB inventory, MSRC MonthIds, mapped KB entries, and missing update counts.

### KB CVE Correlation

![KB and CVE correlation](assets/system_scan-2.png)

The correlation table links KB status, supersedence state, advisory month, and associated CVEs so the operator can inspect patch-linked exposure.

### Runtime Export

![Runtime export](assets/system_scan-3.png)

The scanner exports a runtime JSON snapshot that becomes the input for enrichment, validation, and prioritisation.

### Model Setup

![Model setup](assets/model_setup.png)

Model setup runs the training data pipeline, trains the model pipeline, and saves reusable artefacts for later runtime ranking.

### Runtime Pipeline

![Runtime pipeline](assets/risk_prioritisation-1.png)

The runtime pipeline flattens scan data, enriches CVEs with MSRC metadata, validates required fields, and exports model-ready rows.

### Risk Prioritisation

![Risk prioritisation](assets/risk_prioritisation-2.png)

The prioritiser loads validated runtime data, applies trained artefacts, and ranks missing KBs by predicted CVE risk.

### CVE Breakdown

![CVE breakdown](assets/risk_prioritisation-3.png)

The CVE breakdown preserves the vulnerability-level evidence behind each KB-level recommendation.

---

## Technical Capabilities

WinShield+ is built around modular security tooling rather than a single script. Each capability supports visibility, evidence quality, or operational control during patch-state assessment.

| Area | Implementation |
|---|---|
| Core Stack | The project uses Python, PowerShell, Pandas, Scikit-Learn, Joblib, BeautifulSoup, and the MSRC PowerShell module. |
| Windows Security | The collectors gather OS baseline, build, architecture, LCU context, elevation state, and installed KB inventory from the host. |
| Vulnerability Analysis | The scanner maps KB updates to CVEs using MSRC CVRF advisory data, allowing missing updates to be reviewed through vulnerability exposure. |
| Patch Logic | Supersedence handling allows newer cumulative updates to logically satisfy older KBs, improving assessment accuracy. |
| Data Engineering | Nested host scan JSON is transformed into validated training and runtime datasets with consistent feature structure. |
| Security Analytics | Regression, classification, and clustering support ranking, triage labels, and exploratory grouping of vulnerability records. |
| Operational Control | The workflow uses explicit menu actions, dependency checks, no silent remediation, and reviewable artefacts. |
| Assessment Value | The tool improves patch-state detection and vulnerability assessment by turning raw servicing data into auditable remediation evidence. |

---

## Architecture

The architecture separates collection, correlation, enrichment, model execution, and remediation support. This code modularity makes the prototype easier to inspect, test, scale, and adapt for wider vulnerability assessment workflows.

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

Each layer communicates through structured JSON or CSV artefacts. This preserves evidence integrity, supports repeatable analysis, and allows individual stages to be reviewed without re-running the entire workflow.

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

This design reduces schema drift, dirty input risk, and feature mismatch between training and runtime execution. From a cybersecurity assessment perspective, it improves data prevalence by preserving consistent evidence across scan, enrichment, validation, and ranking stages.

---

## Prioritisation

WinShield+ analyses vulnerability evidence at CVE level, then aggregates the result back to KB level because Windows remediation is applied through update packages.

| Model | Approach | Purpose |
|---|---|---|
| `RandomForestRegressor` | Learns from validated vulnerability features and outputs a continuous CVE-level score. | It provides a sortable risk signal so missing KBs can be ranked beyond a flat severity bucket. |
| `LogisticRegression` | Uses scaled and encoded features to assign a readable priority category. | It gives the operator a quick triage label that is easier to interpret during review. |
| `KMeans` | Groups vulnerability records by feature similarity without using priority labels. | It supports exploratory analysis by showing which CVEs or KBs share similar risk characteristics. |

The supervised targets are rule-derived, so the model layer should be understood as a transparent security analytics workflow rather than a claim of real-world exploit prediction. The value is in enrichment, validation, reusable artefacts, runtime inference, and KB-level aggregation.

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

Model Setup builds the training dataset, trains regression, classification, and clustering models, and saves reusable artefacts into `models/`.

### Scan System

Scan System collects the host baseline, installed KB inventory, MSRC KB/CVE mappings, supersedence relationships, and missing KB results. The scan is exported as runtime JSON.

### Rank Risk

Rank Risk converts the latest runtime scan into validated model-ready rows, applies saved model artefacts, and writes ranked remediation output to `results/ranking_results.json`.

### Clear Artefacts

Clear Artefacts removes generated runtime files, datasets, models, results, and downloads while preserving source training scans. This allows the workflow to be rebuilt cleanly from known input data.

### Download Update

Download Update is an optional testing-stage helper that attempts to resolve a selected missing KB through Microsoft Update Catalog. It uses host baseline constraints such as Windows generation, build, and architecture to reduce incorrect package selection.

### Install Update

Install Update is an optional testing-stage helper that applies a selected `.msu` or `.cab` package through WUSA or DISM. It uses no-restart behaviour, but Windows servicing may still reject, supersede, roll back, or defer an update depending on package applicability, reboot state, and cumulative update rules.

Manual launch is also supported:

```powershell
python -m pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
python training\data_pipeline.py --mode training
python training\model_pipeline.py
python src\core\winshield_scanner.py
python training\data_pipeline.py --mode runtime
python src\core\winshield_prioritiser.py
```

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

Implemented functionality includes:

- Windows patch-state collection is complete through PowerShell baseline, inventory, and adapter scripts.
- MSRC advisory correlation is implemented for KB-to-CVE mapping and vulnerability enrichment.
- Missing KB exposure discovery is supported through installed state, expected state, and supersedence-aware logic.
- Runtime and training data pipelines produce structured JSON and CSV artefacts.
- CVE enrichment and validation support model-ready feature preparation.
- Saved model artefacts are produced for regression, classification, and clustering workflows.
- KB-level prioritisation translates vulnerability evidence into remediation order.
- Optional download and installation helpers demonstrate controlled remediation support.
- The companion collector provides portable scan harvesting for authorised hosts.

Future development under a new repository could focus on:

- Pre-patch and post-patch verification could compare scan snapshots to confirm which KBs and CVEs changed after remediation.
- CVE targeting could highlight vulnerabilities that are practically relevant for testing rather than only theoretically exposed.
- Threat intelligence and exploit trend features could improve prioritisation beyond CVSS and patch age.
- Class balancing and external evaluation could improve confidence in model behaviour beyond internal consistency.
- Cluster interpretation could make unsupervised groupings easier to explain during security review.
- Package hash verification and artefact signing could strengthen evidence integrity.
- Legacy Windows handling could improve assessment coverage across older servicing models.

---

## Limitations

WinShield+ reports patch-linked exposure, not confirmed exploitability. A mapped CVE may require local access, user interaction, specific configuration, or a chained attack path that the tool does not validate.

MSRC advisory structure, Microsoft Update Catalog layout, and Windows servicing behaviour can change over time. These upstream dependencies may affect parsing, package resolution, or update applicability.

The machine learning layer currently learns from rule-derived labels. It supports transparent prioritisation and portfolio demonstration, but it does not replace analyst judgement or enterprise patch governance.

The download and install helpers demonstrate controlled servicing workflows, but direct update installation is constrained by Windows package applicability, supersedence, and rollback behaviour.

---

## Licence

MIT License. See `LICENSE`.
