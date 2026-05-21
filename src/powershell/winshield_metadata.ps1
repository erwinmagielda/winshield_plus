<#
.SYNOPSIS
    WinShield+ vulnerability metadata collector.

.DESCRIPTION
    Retrieves vulnerability metadata from Microsoft Security Response Center
    CVRF documents for the specified MonthIds.

    Extracts CVE severity, CVSS base score, CVSS vector, publication date, and
    exploitation status.

    Emits a JSON object consumed by the WinShield+ enrichment pipeline.

.OUTPUTS
    JSON object written to stdout.
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds
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
        foreach ($item in $InputMonthIds) {
            if (-not $item) {
                continue
            }

            $item -split '[,\s]+' |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }
        }
    ) | Sort-Object -Unique
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

    if ($text.StartsWith('CVE-')) {
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
# METADATA EXTRACTION
# ------------------------------------------------------------

function Get-WinShieldThreatDescription {
    <#
    .SYNOPSIS
        Return a vulnerability threat description by MSRC threat type.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$Threats,

        [Parameter(Mandatory = $true)]
        [int]$Type
    )

    return (
        $Threats |
            Where-Object { $_.Type -eq $Type } |
            Select-Object -First 1
    ).Description.Value
}


function Get-WinShieldCvssData {
    <#
    .SYNOPSIS
        Return CVSS base score and vector from a vulnerability row.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [object]$Vulnerability
    )

    $cvss = $Vulnerability.CVSSScoreSets |
        Select-Object -First 1

    if (-not $cvss) {
        return [pscustomobject]@{
            BaseScore = $null
            Vector    = $null
        }
    }

    return [pscustomobject]@{
        BaseScore = $cvss.BaseScore
        Vector    = $cvss.Vector
    }
}


function Get-WinShieldPublishedDate {
    <#
    .SYNOPSIS
        Return the first revision history date for a vulnerability.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [object]$Vulnerability
    )

    return (
        $Vulnerability.RevisionHistory |
            Select-Object -First 1
    ).Date
}


function ConvertTo-WinShieldVulnerabilityMetadata {
    <#
    .SYNOPSIS
        Convert an MSRC vulnerability row into WinShield+ metadata.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [object]$Vulnerability
    )

    $cvss = Get-WinShieldCvssData -Vulnerability $Vulnerability

    return @{
        Severity      = Get-WinShieldThreatDescription -Threats $Vulnerability.Threats -Type 3
        BaseScore     = $cvss.BaseScore
        Vector        = $cvss.Vector
        PublishedDate = Get-WinShieldPublishedDate -Vulnerability $Vulnerability
        Exploitation  = Get-WinShieldThreatDescription -Threats $Vulnerability.Threats -Type 1
    }
}


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

$normalisedMonthIds = ConvertTo-WinShieldMonthIdList -InputMonthIds $MonthIds

if (-not $normalisedMonthIds) {
    Write-WinShieldJsonError `
        -Message 'Invalid arguments' `
        -Details 'No MonthIds were supplied.'

    exit 1
}

if (-not (Import-WinShieldMsrcModule)) {
    exit 1
}

$results = @{}

foreach ($monthId in $normalisedMonthIds) {
    try {
        $document = Get-MsrcCvrfDocument -ID $monthId -ErrorAction Stop
    }
    catch {
        Write-WinShieldJsonError `
            -Message "Failed to retrieve MSRC CVRF document for $monthId" `
            -Details $_.Exception.Message

        exit 1
    }

    if (-not $document -or -not $document.Vulnerability) {
        continue
    }

    foreach ($vulnerability in $document.Vulnerability) {
        $cveId = ConvertTo-WinShieldCveId -Value $vulnerability.CVE

        if (-not $cveId) {
            continue
        }

        $results[$cveId] = ConvertTo-WinShieldVulnerabilityMetadata `
            -Vulnerability $vulnerability
    }
}


# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

$results | ConvertTo-Json -Depth 5