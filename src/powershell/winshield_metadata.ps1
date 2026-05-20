<#
.SYNOPSIS
    WinShield+ vulnerability metadata.

.DESCRIPTION
    Retrieves vulnerability metadata from Microsoft Security Response Center (MSRC)
    CVRF documents for the specified MonthIds.

    Extracts CVE severity, CVSS base score, CVSS vector, publication date,
    and exploitation status.

    Emits a JSON object consumed by the WinShield+ enrichment pipeline.

.OUTPUTS
    JSON object written to stdout.
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds
)

# ------------------------------------------------------------
# MODULE DEPENDENCY
# ------------------------------------------------------------

try {
    Import-Module MsrcSecurityUpdates -ErrorAction Stop
}
catch {
    Write-Error "Failed to load MsrcSecurityUpdates: $($_.Exception.Message)"
    exit 1
}

# ------------------------------------------------------------
# INPUT NORMALISATION
# ------------------------------------------------------------

$monthIds = @(
    foreach ($item in $MonthIds) {

        if (-not $item) {
            continue
        }

        $item -split "[,\s]+" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    }
) | Sort-Object -Unique

if (-not $monthIds) {
    Write-Error "No MonthIds were supplied."
    exit 1
}

# ------------------------------------------------------------
# AGGREGATION CONTAINER
# ------------------------------------------------------------

$results = @{}

# ------------------------------------------------------------
# PER-MONTH PROCESSING
# ------------------------------------------------------------

foreach ($monthId in $monthIds) {

    try {
        $document = Get-MsrcCvrfDocument -ID $monthId
    }
    catch {
        Write-Error "Failed to retrieve MSRC CVRF document for $monthId`: $($_.Exception.Message)"
        exit 1
    }

    if (-not $document -or -not $document.Vulnerability) {
        continue
    }

    foreach ($vulnerability in $document.Vulnerability) {

        $cve = $vulnerability.CVE

        if (-not $cve) {
            continue
        }

        $cve = ([string]$cve).Trim().ToUpper()

        if (-not $cve.StartsWith("CVE-")) {
            continue
        }

        $severity = ($vulnerability.Threats |
            Where-Object { $_.Type -eq 3 } |
            Select-Object -First 1).Description.Value

        $exploitation = ($vulnerability.Threats |
            Where-Object { $_.Type -eq 1 } |
            Select-Object -First 1).Description.Value

        $cvss = $vulnerability.CVSSScoreSets |
            Select-Object -First 1

        $baseScore = $null
        $vector = $null

        if ($cvss) {
            $baseScore = $cvss.BaseScore
            $vector = $cvss.Vector
        }

        $publishedDate = ($vulnerability.RevisionHistory |
            Select-Object -First 1).Date

        $results[$cve] = @{
            Severity      = $severity
            BaseScore     = $baseScore
            Vector        = $vector
            PublishedDate = $publishedDate
            Exploitation  = $exploitation
        }
    }
}

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

$results | ConvertTo-Json -Depth 5