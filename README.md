# WinShield+

**Windows patch risk prioritisation workflow using PowerShell, Python, MSRC CVE data, and machine learning.**

WinShield+ scans a Windows host, maps installed and missing KBs against Microsoft Security Response Centre advisory data, enriches related CVEs, and ranks patch remediation targets by predicted operational risk.

The project is designed as a controlled lab and portfolio workflow for Windows patch-state analysis, vulnerability triage, and remediation planning. It is not intended to replace enterprise patch management platforms. Its purpose is to show how raw Windows update data can be turned into structured, ranked security intelligence.

## Problem

A missing Windows update is not just an inventory gap. Once a missing KB is mapped to the CVEs it addresses, then enriched with severity, exploitation, attack vector, and patch age data, it becomes a measurable part of the host's exposed attack surface.

Raw patch lists are difficult to interpret because KBs, CVEs, supersedence, advisory metadata, and installation state all need to be correlated before the risk is clear. WinShield+ addresses that problem by turning a clean Windows scan into a prioritised view of missing remediation targets.

## Solution

WinShield+ follows a structured workflow: collect patch state, correlate KBs with MSRC CVE data, enrich the CVEs, prepare model-ready data, train risk models, and rank missing updates. The result is a KB-level remediation order backed by CVE-level detail.

| Layer | Purpose |
|---|---|
| PowerShell collectors | Collect Windows baseline, installed KB inventory, MSRC advisory data, and CVE metadata |
| Python data pipeline | Flatten, enrich, label, and validate KB/CVE/month relationships |
| Model pipeline | Train regression, classification, and clustering models |
| Runtime prioritiser | Apply trained models to runtime scan data and rank KB remediation targets |
| Downloader and installer | Support controlled package resolution, download, and installation workflow |

## Demo Workflow

The screenshots below show the intended operator flow from setup to scan and risk-ranked output.

### Operator Menu

![WinShield+ operator menu](assets/operator_menu.png)

### Model Setup

The Model Setup stage prepares training data and trains the model artefacts used by the runtime prioritiser. Detailed execution output is written to `results/model_setup_run.json` so the main terminal remains clean.

![WinShield+ model setup](assets/model_setup.png)

### System Scan

The Scan System stage clears runtime artefacts, collects the host baseline, inventories installed KBs, queries MSRC CVRF data, and exports a fresh runtime scan.

![WinShield+ system scan summary](assets/system_scan-1.png)

The scanner also prints KB correlation details, including installed, superseded, and missing update states.

![WinShield+ KB correlation](assets/system_scan-2.png)

Missing KBs are exported into a runtime scan JSON file for downstream ranking.

![WinShield+ missing KB export](assets/system_scan-3.png)

### Risk Prioritisation

The Rank Risk stage runs the runtime data pipeline, enriches CVEs, validates model-ready rows, and passes them into the prioritiser.

![WinShield+ runtime data pipeline](assets/risk_prioritisation-1.png)

The prioritiser applies trained models and produces a KB-level remediation table.

![WinShield+ ranked remediation](assets/risk_prioritisation-2.png)

CVE-level predictions remain visible under each KB so the ranking can be reviewed rather than treated as a black box.

![WinShield+ CVE breakdown](assets/risk_prioritisation-3.png)

## Operator Workflow

WinShield+ is controlled through a single master runner.

```bash
python src/core/winshield_master.py
```

| Menu option | Stage | Purpose |
|---:|---|---|
| 1 | Scan System | Collects a fresh runtime scan from the current Windows host |
| 2 | Rank Risk | Builds runtime data and ranks KBs using trained models |
| 3 | Download Update | Resolves and downloads an operator-selected missing update |
| 4 | Install Update | Installs a selected `.msu` or `.cab` package without automatic restart |
| 5 | Clear Artefacts | Removes generated artefacts while preserving source training scans |
| 6 | Model Setup | Runs the training data pipeline and model pipeline |
| 7 | Exit | Exits the operator menu |

The normal run order is:

```text
6) Model Setup
1) Scan System
2) Rank Risk
```

Model Setup is required before ranking because the runtime prioritiser depends on trained regression, classification, and clustering artefacts. Scan System is required before Rank Risk because runtime ranking depends on a fresh `data/runtime/scan_TIMESTAMP.json` file.

## Companion Collector Repository

WinShield+ is designed to work alongside a separate collector repository used to harvest scan results from permitted Windows environments:

[github.com/erwinmagielda/winshield_colletor](https://github.com/erwinmagielda/winshield_colletor)

The collector repository focuses on gathering scan material. This repository focuses on correlation, enrichment, modelling, ranking, and the remediation workflow.

## Technical Method

### Collection

PowerShell scripts collect the Windows baseline, installed KB inventory, and MSRC advisory data. The scanner uses this information to identify expected KBs, installed KBs, superseded KBs, and missing KBs.

### KB to CVE Mapping

The scanner maps KB entries to CVEs from MSRC CVRF data. Non-CVE advisory identifiers are filtered out before model-ready data is produced, which keeps the vulnerability pipeline focused on CVE records.

### Runtime Scan Export

Each scan exports a timestamped JSON file in `data/runtime/`. The runtime directory is cleared at the start of each scan so Rank Risk always works from a fresh runtime state.

### Data Pipeline

The data pipeline has training and runtime modes.

| Step | Training mode | Runtime mode |
|---|---|---|
| Flatten | Reads source scans from `data/scans/` | Reads latest runtime scan from `data/runtime/` |
| Enrich | Adds MSRC metadata and CVSS fields | Adds MSRC metadata and CVSS fields |
| Label | Creates rule-derived risk scores and priority labels | Skipped |
| Validate | Removes rows missing required model inputs | Removes rows missing required model inputs |

### Risk Labelling

Training labels are derived from CVSS score, exploitation status, network attack vector, and patch age. This creates a repeatable supervised training target for the models while keeping the scoring logic transparent.

### Machine Learning

| Model | Purpose |
|---|---|
| RandomForestRegressor | Predicts a numerical risk score for each CVE row |
| LogisticRegression | Predicts priority labels such as Low, Medium, or High |
| KMeans | Groups similar vulnerability profiles into clusters |

The models operate at CVE level. Runtime results are then aggregated back to KB level so missing updates can be ranked as remediation targets.

### Runtime Ranking

The prioritiser loads `data/runtime/validated_runtime.csv`, applies the trained models, then ranks KBs by maximum predicted CVE risk. The console output shows a KB-level remediation table and an aligned CVE-level breakdown for each KB. The full result is also saved as structured JSON.

## Output Artefacts

| Artefact | Purpose |
|---|---|
| `data/runtime/scan_TIMESTAMP.json` | Fresh runtime scan exported by Scan System |
| `data/runtime/flattened_runtime.csv` | Runtime KB/CVE/month rows |
| `data/runtime/enriched_runtime.csv` | Runtime rows enriched with MSRC metadata |
| `data/runtime/validated_runtime.csv` | Runtime model-ready rows |
| `data/dataset/validated_dataset.csv` | Training dataset used by the model pipeline |
| `models/*.joblib` | Trained model and preprocessor artefacts |
| `results/model_setup_run.json` | Structured Model Setup execution details |
| `results/model_pipeline_summary.json` | Model training summary and artefact status |
| `results/runtime_pipeline_summary.json` | Runtime data pipeline summary |
| `results/ranking_results.json` | KB-level and CVE-level prioritisation output |
| `results/clustering_elbow_curve.png` | Saved clustering elbow chart |
| `results/clustering_scatter.png` | Saved clustering scatter chart |

## Project Structure

```text
winshield_plus/
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
│   ├── train_clustering.py
│   └── clear_run.py
├── data/
│   ├── scans/
│   ├── dataset/
│   └── runtime/
├── models/
├── results/
├── downloads/
└── assets/
```

## Requirements

WinShield+ is designed for Windows lab environments.

| Requirement | Notes |
|---|---|
| Windows 10 or Windows 11 | Required for patch inventory and update tooling |
| PowerShell | Used by the collectors and MSRC adapter scripts |
| Python 3.10 or later | Used by the data pipeline, model pipeline, and CLI workflow |
| MsrcSecurityUpdates PowerShell module | Used to query Microsoft security update data |
| Python packages | `pandas`, `numpy`, `scikit-learn`, `joblib`, `requests`, `beautifulsoup4`, `matplotlib` |

Install the MSRC PowerShell module if required:

```powershell
Install-Module MsrcSecurityUpdates -Scope CurrentUser
```

Install Python dependencies from your environment or requirements file:

```bash
pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
```

Run the master menu:

```bash
python src/core/winshield_master.py
```

## Limitations

WinShield+ is a lab and portfolio tool, not a production patch management platform. The installer stage relies on Windows servicing behaviour and may fail, roll back, or require a restart depending on package state and host configuration.

The machine learning labels are rule-derived rather than business-ground-truth risk labels. They are useful for demonstrating repeatable prioritisation logic, but they should support operator judgement rather than replace it.

MSRC data structures can vary by month, product, and advisory format. The project includes filtering and validation steps, but Microsoft advisory data should still be reviewed when making real remediation decisions.

## Skills Demonstrated

| Area | Evidence in project |
|---|---|
| Windows support | Baseline collection, KB inventory, update state handling, WUSA and DISM workflow |
| PowerShell automation | Windows collectors, MSRC CVRF retrieval, metadata extraction |
| Python engineering | CLI workflow, file handling, structured JSON output, pipeline orchestration |
| Vulnerability management | KB to CVE mapping, CVSS parsing, exploitation context, patch age handling |
| Data pipelines | Flatten, enrich, label, validate, train, rank workflow |
| Machine learning | Regression, classification, clustering, preprocessing, saved model artefacts |
| Operational thinking | Setup gating, runtime clearing, repo-relative output, structured artefacts, reproducible execution |

## Future Improvements

Future work could include signed package verification, richer update install validation, HTML reporting, clearer supersedence visualisation, and a dashboard view for ranked remediation results.

The next practical improvement would be an exportable report that turns `results/ranking_results.json` into a concise HTML or PDF remediation summary.
