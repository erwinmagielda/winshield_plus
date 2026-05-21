<#
.SYNOPSIS
    WinShield+ MSRC adapter.

.DESCRIPTION
    Aggregates MSRC CVRF data for a specific Windows product across one or more
    MonthIds.

    Builds KB-to-CVE mappings and supersedence data used by winshield_scanner.py.

.OUTPUTS
    JSON object written to stdout.
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds,

    [Parameter(Mandatory = $true)]
    [string]$ProductNameHint
)


# ------------------------------------------------------------
# INPUT NORMALISATION
# ------------------------------------------------------------

function ConvertTo-WinShieldMonthIdList {
    <#
    .SYNOPSIS
        Normalise MonthId input into a unique sorted list.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputMonthIds
    )

    return @(
        $InputMonthIds |
            ForEach-Object { $_ -split '[,\s]+' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    ) | Sort-Object -Unique
}


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

    if ($text -match '(KB)?(\d{4,8})') {
        return "KB$($Matches[2])"
    }

    return $null
}


function ConvertTo-WinShieldCveId {
    <#
    .SYNOPSIS
        Normalise a CVE value to uppercase CVE format.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if (-not $Value) {
        return $null
    }

    $text = ([string]$Value).Trim().ToUpper()

    if ($text -match '^CVE-\d{4}-\d{4,}$') {
        return $text
    }

    return $null
}


# ------------------------------------------------------------
# ERROR OUTPUT
# ------------------------------------------------------------

function Write-WinShieldJsonError {
    <#
    .SYNOPSIS
        Emit a stable JSON error object.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Details = $null
    )

    [pscustomobject]@{
        Error   = $Message
        Details = $Details
    } | ConvertTo-Json -Depth 5
}


# ------------------------------------------------------------
# MODULE DEPENDENCY
# ------------------------------------------------------------

function Import-WinShieldMsrcModule {
    <#
    .SYNOPSIS
        Import MsrcSecurityUpdates if available.
    #>

    try {
        Import-Module MsrcSecurityUpdates -ErrorAction Stop
        return $true
    }
    catch {
        Write-WinShieldJsonError `
            -Message 'Failed to load MsrcSecurityUpdates' `
            -Details $_.Exception.Message

        return $false
    }
}


# ------------------------------------------------------------
# MSRC DOCUMENT COLLECTION
# ------------------------------------------------------------

function Get-WinShieldAffectedSoftware {
    <#
    .SYNOPSIS
        Return affected software rows for a MonthId.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$MonthId
    )

    try {
        $document = Get-MsrcCvrfDocument -ID $MonthId -ErrorAction Stop

        return Get-MsrcCvrfAffectedSoftware `
            -Vulnerability $document.Vulnerability `
            -ProductTree $document.ProductTree
    }
    catch {
        return @()
    }
}


# ------------------------------------------------------------
# KB ENTRY MERGING
# ------------------------------------------------------------

function New-WinShieldKbEntry {
    <#
    .SYNOPSIS
        Create an empty KB mapping object.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$KbId
    )

    [pscustomobject]@{
        KB         = $KbId
        Months     = @()
        Cves       = @()
        Supersedes = @()
    }
}


function Add-WinShieldUniqueValue {
    <#
    .SYNOPSIS
        Append a value to an object array property if it is not already present.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Target,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )

    if (-not $Value) {
        return
    }

    if ($Target.$PropertyName -notcontains $Value) {
        $Target.$PropertyName += $Value
    }
}


function Get-WinShieldCveList {
    <#
    .SYNOPSIS
        Extract normalised CVEs from an affected product row.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [object]$ProductRow
    )

    if (-not $ProductRow.CVE) {
        return @()
    }

    return @(
        @($ProductRow.CVE) |
            ForEach-Object { ConvertTo-WinShieldCveId -Value $_ } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}


function Get-WinShieldSupersededKbs {
    <#
    .SYNOPSIS
        Extract superseded KB identifiers from an affected product row.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [object]$ProductRow
    )

    if (-not $ProductRow.Supercedence) {
        return @()
    }

    return @(
        @($ProductRow.Supercedence) |
            ForEach-Object { ConvertTo-WinShieldKbId -Value $_ } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}


function Add-WinShieldProductRowToKbMap {
    <#
    .SYNOPSIS
        Merge one affected product row into the KB map.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$KbMap,

        [Parameter(Mandatory = $true)]
        [string]$MonthId,

        [Parameter(Mandatory = $true)]
        [object]$ProductRow
    )

    $cveList = @(Get-WinShieldCveList -ProductRow $ProductRow)
    $supersededKbs = @(Get-WinShieldSupersededKbs -ProductRow $ProductRow)

    foreach ($kbArticle in @($ProductRow.KBArticle)) {
        if (-not $kbArticle -or -not $kbArticle.ID) {
            continue
        }

        $kbId = ConvertTo-WinShieldKbId -Value $kbArticle.ID

        if (-not $kbId) {
            continue
        }

        if (-not $KbMap.ContainsKey($kbId)) {
            $KbMap[$kbId] = New-WinShieldKbEntry -KbId $kbId
        }

        Add-WinShieldUniqueValue -Target $KbMap[$kbId] -PropertyName 'Months' -Value $MonthId

        foreach ($cve in $cveList) {
            Add-WinShieldUniqueValue -Target $KbMap[$kbId] -PropertyName 'Cves' -Value $cve
        }

        foreach ($supersededKb in $supersededKbs) {
            Add-WinShieldUniqueValue -Target $KbMap[$kbId] -PropertyName 'Supersedes' -Value $supersededKb
        }
    }
}


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

$normalisedMonthIds = ConvertTo-WinShieldMonthIdList -InputMonthIds $MonthIds
$productName = $ProductNameHint.Trim()

if (-not $normalisedMonthIds -or -not $productName) {
    Write-WinShieldJsonError `
        -Message 'Invalid arguments' `
        -Details 'MonthIds and ProductNameHint are required.'

    exit 1
}

if (-not (Import-WinShieldMsrcModule)) {
    exit 1
}

$kbMap = @{}
$monthsProcessed = @()
$monthsWithProductRows = @()

foreach ($monthId in $normalisedMonthIds) {
    $affectedSoftware = @(Get-WinShieldAffectedSoftware -MonthId $monthId)

    if (-not $affectedSoftware) {
        continue
    }

    $monthsProcessed += $monthId

    $productRows = @(
        $affectedSoftware |
            Where-Object { $_.FullProductName -eq $productName }
    )

    if (-not $productRows) {
        continue
    }

    $monthsWithProductRows += $monthId

    foreach ($productRow in $productRows) {
        Add-WinShieldProductRowToKbMap `
            -KbMap $kbMap `
            -MonthId $monthId `
            -ProductRow $productRow
    }
}


# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

[pscustomobject]@{
    ProductNameHint       = $productName
    MonthIds              = @($normalisedMonthIds)
    MonthsProcessed       = @($monthsProcessed | Sort-Object -Unique)
    MonthsWithProductRows = @($monthsWithProductRows | Sort-Object -Unique)
    KbEntries             = @(
        $kbMap.GetEnumerator() |
            ForEach-Object { $_.Value } |
            Sort-Object KB
    )
} | ConvertTo-Json -Depth 10