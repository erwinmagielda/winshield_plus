@echo off
:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo =====================================
echo WinShield Collector Setup (Admin)
echo =====================================

echo Setting execution policy...
powershell -Command "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force"

echo Checking NuGet provider...
powershell -Command "if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -Force }"

echo Checking MSRC module...
powershell -Command "if (-not (Get-Module -ListAvailable -Name MsrcSecurityUpdates)) { Install-Module -Name MsrcSecurityUpdates -Scope CurrentUser -Force -AllowClobber }"

echo Running WinShield Collector...
start "" "%~dp0winshield_collector.exe"

pause