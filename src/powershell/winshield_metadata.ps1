<#
.SYNOPSIS
    WinShield Metadata

.DESCRIPTION
    Retrieves vulnerability metadata from Microsoft Security Response Center (MSRC)
    CVRF documents for the specified MonthIds.

    Extracts CVE severity, CVSS base score, CVSS vector, publication date,
    and exploitation status.

    Emits a JSON object consumed by enrich.py in the WinShield pipeline.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$MonthIds
)

# ------------------------------------------------------------
# MODULE DEPENDENCY
# ------------------------------------------------------------

Import-Module MsrcSecurityUpdates -ErrorAction Stop

# ------------------------------------------------------------
# INPUT NORMALISATION
# ------------------------------------------------------------

$months = $MonthIds -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

# ------------------------------------------------------------
# AGGREGATION CONTAINER
# ------------------------------------------------------------

$results = @{}

# ------------------------------------------------------------
# PER-MONTH PROCESSING
# ------------------------------------------------------------

foreach ($month in $months) {

    $doc = Get-MsrcCvrfDocument -ID $month

    foreach ($v in $doc.Vulnerability) {

        $cve = $v.CVE

        $severity = ($v.Threats |
            Where-Object { $_.Type -eq 3 } |
            Select-Object -First 1).Description.Value

        $exploit = ($v.Threats |
            Where-Object { $_.Type -eq 1 } |
            Select-Object -First 1).Description.Value

        $cvss = $v.CVSSScoreSets | Select-Object -First 1

        $baseScore = $cvss.BaseScore
        $vector = $cvss.Vector

        $published = ($v.RevisionHistory | Select-Object -First 1).Date

        $results[$cve] = @{
            Severity      = $severity
            BaseScore     = $baseScore
            Vector        = $vector
            PublishedDate = $published
            Exploitation  = $exploit
        }
    }
}

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

$results | ConvertTo-Json -Depth 5