@echo off
echo =====================================
echo WinShield Collector Setup
echo =====================================

echo Checking PowerShell execution policy...
powershell -Command "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force"

echo Checking for NuGet provider...
powershell -Command "if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -Force }"

echo Checking for MsrcSecurityUpdates module...
powershell -Command "if (-not (Get-Module -ListAvailable -Name MsrcSecurityUpdates)) { Install-Module -Name MsrcSecurityUpdates -Scope CurrentUser -Force -AllowClobber }"

echo Running WinShield Collector...
start "" "winshield_collector.exe"

pause