# WinShield+

WinShield+ is a Windows patch-state analysis and vulnerability prioritisation pipeline. It scans local Windows update state, correlates installed and missing KBs with Microsoft Security Response Center data, enriches related CVEs, builds training/runtime datasets, trains machine learning models, and ranks missing updates by predicted risk.

The project is designed as a practical vulnerability management workflow rather than a simple patch checker. It combines PowerShell collection, MSRC CVRF correlation, Python data processing, and machine learning-based prioritisation.

---

## Overview

WinShield+ helps answer a practical operational question:

> If a Windows system is missing updates, which missing KBs should be prioritised first based on the vulnerabilities they address?

The workflow collects Windows baseline and update inventory data, maps KBs to MSRC vulnerability information, enriches CVEs with CVSS and exploitation metadata, and applies trained models to rank missing patches by risk.

The project includes:

- Windows baseline and installed update collection
- MSRC CVRF advisory correlation
- KB-to-CVE mapping
- CVE metadata enrichment
- Dataset generation for training and runtime use
- Regression, classification, and clustering models
- Runtime prioritisation output
- Manual Microsoft Update Catalog downloader
- Best-effort installer helper for downloaded packages
- Pipeline summary outputs for traceability

---

## Key Features

- Collects Windows OS, build, architecture, LCU, and product metadata
- Inventories installed KBs using `Get-HotFix` and `Get-WindowsPackage`
- Resolves matching MSRC product names for Windows 10/11 systems
- Builds MonthId ranges for MSRC CVRF retrieval
- Correlates KBs with CVEs and supersedence relationships
- Exports runtime scan JSON files
- Builds training and runtime CSV datasets
- Enriches CVEs with:
  - CVSS base score
  - CVSS vector components
  - severity
  - publication date
  - exploitation status
  - patch age
- Trains:
  - Random Forest regression model
  - Logistic Regression classification model
  - KMeans clustering model
- Ranks missing KBs by maximum predicted risk across related CVEs
- Produces structured JSON reports in `results/`
- Includes cleanup utility to remove generated artefacts while preserving training scans

---

## Pipeline

### Training Pipeline

```text
data/scans/*.json
        ↓
training/data_pipeline.py --mode training
        ↓
flattened_dataset.csv
        ↓
enriched_dataset.csv
        ↓
labelled_dataset.csv
        ↓
validated_dataset.csv
        ↓
training/model_pipeline.py
        ↓
regression_model.joblib
classification_model.joblib
clustering_model.joblib
```

### Runtime Pipeline

```text
src/core/winshield_scanner.py
        ↓
data/runtime/scan_YYYYMMDD_HHMMSS.json
        ↓
training/data_pipeline.py --mode runtime
        ↓
validated_runtime.csv
        ↓
src/core/winshield_prioritiser.py
        ↓
results/ranking_results.json
results/prioritisation_summary.json
results/downloader_summary.json
results/installer_summary.json
```

---

## Repository Structure

```text
winshield_plus/
├── data/
│   ├── scans/              # Authorised training scan JSON files
│   ├── dataset/            # Generated training CSVs
│   └── runtime/            # Generated runtime scans and CSVs
├── downloads/              # Downloaded update packages
├── models/                 # Generated trained model artefacts
├── results/                # Generated pipeline summaries and rankings
├── src/
│   ├── core/
│   │   ├── winshield_master.py
│   │   ├── winshield_scanner.py
│   │   ├── winshield_prioritiser.py
│   │   ├── winshield_downloader.py
│   │   └── winshield_installer.py
│   └── powershell/
│       ├── winshield_baseline.ps1
│       ├── winshield_inventory.ps1
│       ├── winshield_adapter.ps1
│       └── winshield_metadata.ps1
├── training/
│   ├── data_pipeline.py
│   ├── model_pipeline.py
│   ├── train_regression.py
│   ├── train_classification.py
│   └── train_clustering.py
├── remove_run.py
├── README.md
├── LICENSE
└── .gitignore
```

---

## Setup

### Requirements

WinShield+ requires Windows with PowerShell and Python.

Python dependencies:

```powershell
pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
```

PowerShell dependency:

```powershell
Install-Module MsrcSecurityUpdates -Scope CurrentUser
```

If PowerShell blocks script execution, run commands through:

```powershell
-ExecutionPolicy Bypass
```

The project scripts already use this flag when calling PowerShell internally.

---

## Usage

### 1. Clean generated artefacts

This removes generated datasets, runtime files, model artefacts, results, and downloads while preserving `data/scans/`.

```powershell
python remove_run.py
```

---

### 2. Build training dataset

```powershell
python training\data_pipeline.py --mode training
```

This creates:

```text
data/dataset/flattened_dataset.csv
data/dataset/enriched_dataset.csv
data/dataset/labelled_dataset.csv
data/dataset/validated_dataset.csv
results/training_pipeline_summary.json
```

---

### 3. Train all models

```powershell
python training\model_pipeline.py
```

This runs:

```text
training/data_pipeline.py --mode training
training/train_regression.py
training/train_classification.py
training/train_clustering.py
```

Generated model artefacts:

```text
models/regression_model.joblib
models/regression_preprocessor.joblib
models/classification_model.joblib
models/classification_preprocessor.joblib
models/clustering_model.joblib
models/clustering_preprocessor.joblib
models/clustering_features.joblib
```

Generated summary:

```text
results/model_pipeline_summary.json
```

---

### 4. Scan current system

Run:

```powershell
python src\core\winshield_scanner.py
```

This collects system baseline information, installed KBs, MSRC correlation data, and missing KBs.

Generated output:

```text
data/runtime/scan_YYYYMMDD_HHMMSS.json
```

---

### 5. Build runtime dataset

```powershell
python training\data_pipeline.py --mode runtime
```

Generated output:

```text
data/runtime/flattened_runtime.csv
data/runtime/enriched_runtime.csv
data/runtime/validated_runtime.csv
results/runtime_pipeline_summary.json
```

---

### 6. Prioritise missing KBs

```powershell
python src\core\winshield_prioritiser.py
```

Generated output:

```text
results/ranking_results.json
results/prioritisation_summary.json
```

---

### 7. Run through the master menu

```powershell
python src\core\winshield_master.py
```

Menu options:

```text
1) Scan System
2) Rank Risk
3) Download Update
4) Install Update
5) Clean Artefacts
6) Exit
```

The cleanup option runs `remove_run.py`, which removes generated datasets, runtime files, model artefacts, results, and downloads while preserving `data/scans/`.

---

## Outputs

### `ranking_results.json`

Contains KB-level prioritisation output.

Example structure:

```json
[
  {
    "kb_id": "KB5074109",
    "max_risk": 9.84,
    "classification": "High",
    "cluster": 2,
    "cves": [
      {
        "cve_id": "CVE-2025-6965",
        "risk": 9.84,
        "classification": "High",
        "cluster": 2
      }
    ]
  }
]
```

### Pipeline summaries

WinShield+ writes JSON summaries for traceability:

```text
results/training_pipeline_summary.json
results/runtime_pipeline_summary.json
results/model_pipeline_summary.json
results/prioritisation_summary.json
results/downloader_summary.json
results/installer_summary.json
```

These summaries record counts such as:

- scan files processed
- rows created
- unique KBs
- unique CVEs
- MonthIds requested
- metadata CVEs returned
- matched and missing CVEs
- rows validated
- rows dropped
- generated outputs
- model artefacts created
- prioritisation results produced
- downloader package retrieval attempts
- installer execution attempts

---

## Data and Artefact Handling

The repository is intended to keep source training scans while ignoring generated artefacts.

Tracked:

```text
data/scans/
```

Ignored:

```text
data/dataset/
data/runtime/
results/
models/
downloads/
```

This allows the project to rebuild the training dataset and models from authorised scan inputs without storing generated output files in Git.

---

## Optional Downloader and Installer Modules

WinShield+ includes two manual operator modules:

```text
src/core/winshield_downloader.py
src/core/winshield_installer.py
```

The downloader searches the Microsoft Update Catalog for a selected missing KB and downloads a matching `.msu` or `.cab` package. It writes `results/downloader_summary.json` when run.

The installer writes `results/installer_summary.json` and attempts to install a selected downloaded package using:

```text
wusa.exe
dism.exe
```

These modules are intentionally operator-controlled. The downloader is useful for package retrieval, while the installer is best-effort because Windows servicing can reject or revert packages depending on applicability, supersedence, servicing stack state, pending reboot state, and system configuration.

They are included to show the wider remediation workflow, but the core supported pipeline is:

```text
scan → enrich → validate → prioritise
```

---

## Limitations

- The project depends on the `MsrcSecurityUpdates` PowerShell module.
- MSRC product names and Update Catalog entries can change over time.
- Microsoft Update Catalog parsing relies on HTML structure and may require updates if the site changes.
- Installer behaviour depends on Windows servicing rules and cannot guarantee successful update installation.
- The ML labels are generated using a rule-based scoring function for training purposes.
- The prioritisation output supports decision-making but does not replace formal vulnerability management tooling.

---

## Skills Demonstrated

- Windows administration and patch-state analysis
- PowerShell scripting
- Python automation
- Data pipeline design
- JSON and CSV processing
- MSRC CVRF data handling
- Vulnerability enrichment
- CVSS vector parsing
- Machine learning model training
- Regression, classification, and clustering
- Runtime inference
- Repository hygiene and artefact separation
- Operational reporting and pipeline traceability

---

## Disclaimer

WinShield+ is an educational and portfolio project built for authorised Windows systems and lab environments. It should only be used on systems where scanning, update analysis, package download, and installation attempts are permitted.
