<#
.SYNOPSIS
    WinShield+ inventory collector.

.DESCRIPTION
    Collects installed Windows update identifiers using Get-HotFix and
    Get-WindowsPackage.

    Get-HotFix provides user-level hotfix visibility. Get-WindowsPackage
    provides deeper Windows package visibility when the script is running with
    administrative privileges.

    Emits a stable JSON object consumed by winshield_scanner.py.

.OUTPUTS
    JSON object written to stdout.
#>


# ------------------------------------------------------------
# PRIVILEGE CONTEXT
# ------------------------------------------------------------

function Test-WinShieldAdministrator {
    <#
    .SYNOPSIS
        Return True when the current PowerShell session is elevated.
    #>

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


# ------------------------------------------------------------
# KB NORMALISATION
# ------------------------------------------------------------

function ConvertTo-WinShieldKbId {
    <#
    .SYNOPSIS
        Normalise a KB value to uppercase KB format.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if (-not $Value) {
        return $null
    }

    $text = [string]$Value

    if ($text -match '(KB\d{4,8})') {
        return $Matches[1].ToUpper()
    }

    return $null
}


# ------------------------------------------------------------
# HOTFIX COLLECTION
# ------------------------------------------------------------

function Get-WinShieldHotFixKbs {
    <#
    .SYNOPSIS
        Collect KB identifiers from Get-HotFix.
    #>

    try {
        return @(
            Get-HotFix |
                ForEach-Object { ConvertTo-WinShieldKbId -Value $_.HotFixID } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
    }
    catch {
        return @()
    }
}


# ------------------------------------------------------------
# PACKAGE COLLECTION
# ------------------------------------------------------------

function Get-WinShieldPackageKbs {
    <#
    .SYNOPSIS
        Collect KB identifiers from Get-WindowsPackage when elevated.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [bool]$IsAdmin
    )

    if (-not $IsAdmin) {
        return @()
    }

    try {
        return @(
            Get-WindowsPackage -Online |
                ForEach-Object {
                    $packageKb = ConvertTo-WinShieldKbId -Value $_.PackageName

                    if ($packageKb) {
                        $packageKb
                        return
                    }

                    ConvertTo-WinShieldKbId -Value $_.Description
                } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
    }
    catch {
        return @()
    }
}


# ------------------------------------------------------------
# INVENTORY COLLECTION
# ------------------------------------------------------------

function Get-WinShieldInventory {
    <#
    .SYNOPSIS
        Build the WinShield+ installed update inventory object.
    #>

    $isAdmin = Test-WinShieldAdministrator

    $hotFixKbs = @(Get-WinShieldHotFixKbs)
    $packageKbs = @(Get-WinShieldPackageKbs -IsAdmin $isAdmin)

    $allInstalledKbs = @(
        $hotFixKbs
        $packageKbs
    ) |
        Where-Object { $_ } |
        Sort-Object -Unique

    [pscustomobject]@{
        IsAdmin         = $isAdmin
        HotFixKbs       = @($hotFixKbs)
        PackageKbs      = @($packageKbs)
        AllInstalledKbs = @($allInstalledKbs)
    }
}


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    Get-WinShieldInventory | ConvertTo-Json -Depth 4
}