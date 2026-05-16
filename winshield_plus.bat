@echo off
setlocal

title WinShield+

REM ------------------------------------------------------------
REM WinShield+ Launcher
REM ------------------------------------------------------------
REM Runs the main WinShield+ operator menu from the repository root.
REM ------------------------------------------------------------

cd /d "%~dp0"

set "APP_NAME=WinShield+"
set "MASTER_SCRIPT=src\core\winshield_master.py"
set "POWERSHELL_DIR=src\powershell"

echo.
echo ============================================================
echo  WinShield+
echo ============================================================
echo.

REM ------------------------------------------------------------
REM WINDOWS CHECK
REM ------------------------------------------------------------

if /i not "%OS%"=="Windows_NT" (
    echo [X] WinShield+ must be run on Windows.
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM ADMIN ELEVATION
REM ------------------------------------------------------------

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges are required.
    echo [*] Requesting elevation...
    echo.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"

    exit /b
)

REM ------------------------------------------------------------
REM POWERSHELL CHECK
REM ------------------------------------------------------------

where powershell.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] PowerShell was not found on this system.
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM PYTHON CHECK
REM ------------------------------------------------------------

where python.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python was not found on this system.
    echo.
    echo Install Python, then rerun:
    echo winshield_plus.bat
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM MSRC POWERSHELL MODULE CHECK
REM ------------------------------------------------------------

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (Get-Module -ListAvailable -Name MsrcSecurityUpdates) { exit 0 } else { exit 1 }" >nul 2>&1

if %errorlevel% neq 0 (
    echo [!] Required PowerShell module is missing:
    echo     MsrcSecurityUpdates
    echo.
    echo This module is required for MSRC advisory collection.
    echo.
    choice /C YN /M "Install MsrcSecurityUpdates for the current user now?"

    if errorlevel 2 (
        echo.
        echo [X] Dependency installation declined.
        echo.
        echo Install it manually with:
        echo powershell -NoProfile -Command "Install-Module MsrcSecurityUpdates -Scope CurrentUser"
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [*] Installing MsrcSecurityUpdates...
    echo.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue; Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force; Install-Module MsrcSecurityUpdates -Scope CurrentUser -Force -AllowClobber"

    if %errorlevel% neq 0 (
        echo.
        echo [X] Failed to install MsrcSecurityUpdates.
        echo.
        echo Install it manually with:
        echo powershell -NoProfile -Command "Install-Module MsrcSecurityUpdates -Scope CurrentUser"
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [+] MsrcSecurityUpdates installed successfully.
    echo.
)

REM ------------------------------------------------------------
REM REQUIRED FILE CHECKS
REM ------------------------------------------------------------

if not exist "%MASTER_SCRIPT%" (
    echo [X] Master script missing:
    echo %MASTER_SCRIPT%
    echo.
    pause
    exit /b 1
)

if not exist "%POWERSHELL_DIR%\winshield_baseline.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_baseline.ps1
    echo.
    pause
    exit /b 1
)

if not exist "%POWERSHELL_DIR%\winshield_inventory.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_inventory.ps1
    echo.
    pause
    exit /b 1
)

if not exist "%POWERSHELL_DIR%\winshield_adapter.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_adapter.ps1
    echo.
    pause
    exit /b 1
)

if not exist "%POWERSHELL_DIR%\winshield_metadata.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_metadata.ps1
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM PYTHON PACKAGE CHECKS
REM ------------------------------------------------------------

echo [*] Checking Python package dependencies...
echo.

python -c "import pandas, numpy, sklearn, joblib, requests, bs4, matplotlib" >nul 2>&1

if %errorlevel% neq 0 (
    echo [!] One or more Python packages are missing.
    echo.
    choice /C YN /M "Install required Python packages now?"

    if errorlevel 2 (
        echo.
        echo [X] Python dependency installation declined.
        echo.
        echo Install manually with:
        echo python -m pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [*] Installing Python dependencies...
    echo.

    python -m pip install pandas numpy scikit-learn joblib requests beautifulsoup4 matplotlib

    if %errorlevel% neq 0 (
        echo.
        echo [X] Failed to install Python dependencies.
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [+] Python dependencies installed successfully.
    echo.
)

REM ------------------------------------------------------------
REM LAUNCH WINSHIELD+
REM ------------------------------------------------------------

echo [*] Launching WinShield+ master runner...
echo.

python "%MASTER_SCRIPT%"

if %errorlevel% neq 0 (
    echo.
    echo [X] WinShield+ exited with an error.
    echo Exit code: %errorlevel%
    echo.
    pause
    exit /b 1
)

echo.
echo [+] WinShield+ closed.
echo.
pause
exit /b 0