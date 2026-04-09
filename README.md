````markdown
# WinShield+

## Requirements

Install Python dependencies:

```bash
pip install pandas numpy scikit-learn joblib matplotlib seaborn requests beautifulsoup4
```

Run in PowerShell (Administrator):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -Force
}

if (-not (Get-Module -ListAvailable -Name MsrcSecurityUpdates)) {
    Install-Module -Name MsrcSecurityUpdates -Scope CurrentUser -Force -AllowClobber
}
```

---

## Run

Run terminal as **Administrator**:

```bash
python winshield_plus/src/core/winshield_master.py
```

Select:

```
2. Rank Risk
```

(Runtime scan already provided.)

---

## Full Pipeline (Optional)

Delete contents of:

```
winshield_plus/models/
winshield_plus/data/dataset/
winshield_plus/data/runtime/
```

Run:

```bash
python winshield_plus/training/data_pipeline.py
python winshield_plus/training/train_classification.py
python winshield_plus/training/train_regression.py
python winshield_plus/training/train_clustering.py
```

Then:

```bash
python winshield_plus/src/core/winshield_master.py
```

Select:

```
1. Scan System
2. Rank Risk
```
````
