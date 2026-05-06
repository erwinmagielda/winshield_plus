# WinShield+

**Windows patch-state analysis, CVE enrichment, and ML-assisted vulnerability prioritisation.**

WinShield+ is a portfolio security engineering project that turns local Windows update state into a risk-ranked patch remediation view. It collects host and update inventory data, correlates installed and missing KBs with Microsoft Security Response Center advisory data, enriches related CVEs, builds training and runtime datasets, trains machine learning models, and ranks missing updates by predicted risk.

The project is designed as a practical vulnerability management workflow rather than a simple patch checker. Its core question is:

> If a Windows system is missing updates, which missing KBs should be prioritised first based on the vulnerabilities they address?

---

## Why It Matters

Traditional patch checks can tell an operator that updates are missing, but they do not always explain which missing update should be handled first. In a real support or SOC environment, this creates triage fatigue: multiple KBs, many CVEs, different severities, supersedence relationships, and unclear remediation order.

WinShield+ addresses that problem by automating the flow from Windows inventory to vulnerability prioritisation:

```text
Scan → Correlate → Enrich → Validate → Model → Prioritise
```

The result is an operator-readable ranking of missing KBs, supported by CVE-level evidence and structured JSON outputs for traceability.

---

## Engineering Highlights

- **Hybrid Windows/Python architecture**: PowerShell handles Windows inventory and MSRC collection, while Python handles orchestration, data processing, model training, and runtime inference.
- **Windows patch-state correlation**: Installed KBs are collected through `Get-HotFix` and `Get-WindowsPackage`, then correlated with MSRC CVRF advisory data.
- **Supersedence-aware logic**: The scanner treats superseded KBs as logically present when a newer installed KB replaces them.
- **CVE enrichment pipeline**: Runtime and training records are enriched with CVSS score, CVSS vector fields, severity, publication date, exploitation status, and patch age.
- **Training/runtime separation**: Historical scan data builds the training dataset, while current system scans flow through a separate runtime path.
- **Three-model prioritisation layer**: Random Forest regression predicts risk score, Logistic Regression predicts priority label, and KMeans groups vulnerabilities into behavioural clusters.
- **Operational traceability**: Each major stage writes structured JSON summaries that record inputs, row counts, matched CVEs, dropped rows, output paths, and model artefacts.
- **Manual remediation support**: Optional downloader and installer helpers demonstrate the wider remediation lifecycle while keeping execution operator-controlled.

---

## Demonstration Screenshots

### Master menu

The master runner provides a single operator entry point for scanning, ranking, downloading, installing, and cleaning generated artefacts.

![WinShield+ master menu](assets/winshield_menu.png)

### Runtime pipeline

A runtime scan collects the local Windows baseline, installed KB inventory, MSRC data, missing KBs, and exports a runtime JSON scan for downstream analysis.

![Runtime pipeline output](assets/runtime_pipeline.png)

### KB correlation table

The scanner correlates expected KBs, installed KBs, superseded KBs, MonthIds, and CVEs into an operator-readable table.

![Correlation table](assets/correlation_table.png)

### Training pipeline

The training pipeline flattens authorised scan JSON files, enriches CVE metadata, labels training rows, validates required model fields, and writes pipeline summaries.

![Training data pipeline](assets/data_pipeline.png)

### Model training

The model pipeline trains regression, classification, and clustering models, then writes model artefacts and a model pipeline summary.

![Model training output](assets/model_training.png)

### Update collection

The scanner collects Windows baseline and inventory data, builds the MSRC MonthId range, queries MSRC, and reports expected versus missing KBs.

![Update collection output](assets/update_collection.png)

### Prioritisation output

The prioritiser ranks missing KBs by the highest predicted CVE risk for each KB and prints CVE-level model outputs.

![Prioritisation table](assets/prioritisation_table.png)

### Remediation recommendation

The final recommendation gives the operator a patch order based on predicted risk.

![Prioritisation summary](assets/prioritisation_summary.png)

---

## System Overview

WinShield+ is split into four main layers:

```text
PowerShell collection layer
    winshield_baseline.ps1
    winshield_inventory.ps1
    winshield_adapter.ps1
    winshield_metadata.ps1

Python orchestration layer
    winshield_scanner.py
    winshield_master.py

Data and model layer
    data_pipeline.py
    model_pipeline.py
    train_regression.py
    train_classification.py
    train_clustering.py

Operator remediation layer
    winshield_prioritiser.py
    winshield_downloader.py
    winshield_installer.py
```

The core supported workflow is:

```text
scan → enrich → validate → prioritise
```

The downloader and installer modules are intentionally manual because Windows servicing behaviour depends on applicability, supersedence, servicing stack state, pending reboot state, and local configuration.

---

## Pipeline Design

### 1. Host baseline collection

`winshield_baseline.ps1` collects host metadata required for Windows/MSRC correlation:

- OS name and edition
- DisplayVersion
- build and UBR
- architecture
- administrator context
- latest cumulative update anchor
- latest MSRC MonthId
- resolved MSRC product name hint

This gives the Python scanner enough context to query the correct Windows product data from MSRC.

### 2. Installed update inventory

`winshield_inventory.ps1` collects installed update identifiers from:

- `Get-HotFix`
- `Get-WindowsPackage -Online`, when running with administrator privileges

The result is a normalised installed KB list used to compare local state against expected MSRC KB entries.

### 3. MSRC correlation

`winshield_adapter.ps1` aggregates MSRC CVRF data across selected MonthIds and builds KB entries containing:

- KB ID
- associated MonthIds
- related CVEs
- supersedence relationships

The scanner then resolves missing KBs while accounting for logical presence through supersedence.

### 4. CVE metadata enrichment

`winshield_metadata.ps1` retrieves vulnerability metadata for requested MonthIds. The Python enrichment stage attaches:

- CVSS base score
- CVSS vector
- parsed CVSS components
- severity
- published date
- exploitation status
- patch age in days

Rows missing required model fields, such as `cvss_score` or `attack_vector`, are removed during validation.

### 5. Machine learning prioritisation

The training pipeline creates supervised labels using a rule-based training score. The score starts from CVSS base score and increases for exploitation status, network attack vector, and patch age.

The trained models are then used at runtime:

| Model | Purpose |
| --- | --- |
| Random Forest Regressor | Predicts CVE-level risk score |
| Logistic Regression | Predicts priority label |
| KMeans | Groups vulnerabilities into behavioural clusters |

Runtime ranking is performed at KB level by taking the maximum predicted CVE risk for each missing KB. This means a KB with one highly risky CVE can be prioritised above a KB with many lower-risk CVEs.

---

## Current Demonstration Run

The current demo run shows the system working end to end.

### Training dataset summary

```text
Training scan files: 9
Flattened rows: 3094
Validated rows: 3075
Unique KBs: 38
Unique CVEs requested: 1578
Matched CVEs: 1575
MSRC metadata CVEs returned: 9717
Rows dropped during validation: 19
```

### Runtime summary

```text
Runtime scan files: 1
Runtime rows: 121
Runtime unique KBs: 2
Runtime unique CVEs: 121
Matched CVEs: 121
Missing CVEs: 0
Validation rows dropped: 0
```

### Runtime prioritisation result

```text
1. KB5083769 | Cluster: 0 | Classification: Medium | Risk: 11.08 | CVEs: 120
2. KB5074109 | Cluster: 1 | Classification: High   | Risk: 10.88 | CVEs: 1
```

This demonstrates why risk-based ordering is useful. KB5083769 contains many related CVEs and receives the highest predicted risk score, while KB5074109 is still prioritised as high despite only mapping to one CVE.

---

## Example `ranking_results.json`

`results/ranking_results.json` contains KB-level ranking output with nested CVE-level model results.

```json
[
  {
    "kb_id": "KB5083769",
    "max_risk": 11.08,
    "classification": "Medium",
    "cluster": 0,
    "cves": [
      {
        "cve_id": "CVE-2026-26178",
        "risk": 11.08,
        "classification": "High",
        "cluster": 1
      }
    ]
  },
  {
    "kb_id": "KB5074109",
    "max_risk": 10.88,
    "classification": "High",
    "cluster": 1,
    "cves": [
      {
        "cve_id": "CVE-2025-6965",
        "risk": 10.88,
        "classification": "High",
        "cluster": 1
      }
    ]
  }
]
```

---

## Repository Structure

```text
winshield_plus/
├── assets/                 # README screenshots
├── data/
│   ├── scans/              # Authorised source scan JSON files
│   ├── dataset/            # Generated training CSVs, ignored by Git
│   └── runtime/            # Generated runtime scans and CSVs, ignored by Git
├── downloads/              # Downloaded update packages, ignored by Git
├── models/                 # Generated model artefacts, ignored by Git
├── results/                # Generated summaries and rankings, ignored by Git
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

WinShield+ requires:

- Windows 10 or Windows 11
- PowerShell
- Python 3.10 or later
- Microsoft `MsrcSecurityUpdates` PowerShell module

Install Python dependencies:

```powershell
pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
```

Install the PowerShell dependency:

```powershell
Install-Module MsrcSecurityUpdates -Scope CurrentUser
```

If script execution is blocked, run PowerShell through:

```powershell
-ExecutionPolicy Bypass
```

The project uses this internally when launching PowerShell scripts from Python.

---

## Usage

### Option A: Run from the master menu

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

### Option B: Run stages manually

Clean generated artefacts:

```powershell
python remove_run.py
```

Build the training dataset:

```powershell
python training\data_pipeline.py --mode training
```

Train all models:

```powershell
python training\model_pipeline.py
```

Scan the current system:

```powershell
python src\core\winshield_scanner.py
```

Build the runtime dataset:

```powershell
python training\data_pipeline.py --mode runtime
```

Prioritise missing KBs:

```powershell
python src\core\winshield_prioritiser.py
```

Optional package retrieval:

```powershell
python src\core\winshield_downloader.py
```

Optional package installation helper:

```powershell
python src\core\winshield_installer.py
```

---

## Generated Outputs

WinShield+ writes structured outputs to support traceability and review.

```text
results/training_pipeline_summary.json
results/runtime_pipeline_summary.json
results/model_pipeline_summary.json
results/prioritisation_summary.json
results/ranking_results.json
results/downloader_summary.json
results/installer_summary.json
```

These outputs record evidence such as:

- scan files processed
- rows created
- unique KBs and CVEs
- MonthIds requested
- MSRC metadata CVEs returned
- matched and missing CVEs
- rows validated and dropped
- model artefacts created
- prioritisation results produced
- downloader and installer attempts

---

## Data and Artefact Handling

The repository separates source inputs from generated artefacts.

Tracked or suitable for tracking:

```text
assets/
data/scans/
src/
training/
README.md
LICENSE
.gitignore
```

Ignored generated artefacts:

```text
data/dataset/
data/runtime/
results/
models/
downloads/
collector/
```

The separate `collector/` concept was used as an authorised scanner-only utility for collecting JSON scan inputs. It is intentionally split out of the main WinShield+ repository to keep this project focused on patch analysis, enrichment, modelling, and prioritisation.

---

## Limitations

- WinShield+ depends on the `MsrcSecurityUpdates` PowerShell module.
- MSRC product names and CVRF structures can change over time.
- Microsoft Update Catalog HTML parsing may require maintenance if Microsoft changes the site structure.
- Installer behaviour depends on Windows servicing rules and cannot guarantee successful installation.
- The supervised training labels are generated from a rule-based scoring function, not from real incident outcomes.
- The prioritisation output supports operator decision-making, but it does not replace enterprise vulnerability management tooling.

---

## Skills Demonstrated

- Windows administration and patch-state analysis
- PowerShell scripting and Windows inventory collection
- Python automation and subprocess orchestration
- MSRC CVRF advisory handling
- KB-to-CVE correlation
- Supersedence-aware patch reasoning
- CVSS vector parsing and vulnerability enrichment
- Data pipeline design with training/runtime separation
- Regression, classification, and clustering workflows
- JSON and CSV processing
- Runtime model inference
- Operational reporting and traceability
- Repository hygiene and generated artefact separation

---

## Disclaimer

WinShield+ is an educational and portfolio project built for authorised Windows systems and lab environments. It should only be used on systems where scanning, update analysis, package download, and installation attempts are permitted.
