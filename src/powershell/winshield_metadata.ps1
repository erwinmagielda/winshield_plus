param(
    [Parameter(Mandatory = $true)]
    [string[]]$MonthIds
)

Import-Module MsrcSecurityUpdates

$metadata = @{}

foreach ($month in $MonthIds) {

    $doc = Get-MsrcCvrfDocument -ID $month

    foreach ($vuln in $doc.Vulnerability) {

        $cve = $vuln.CVE
        if (-not $cve) { continue }

        # --- CVSS (first unique entry only)
        $cvssEntry = $vuln.CVSSScoreSets | Select-Object -First 1

        $baseScore = $null
        $vector = $null

        if ($cvssEntry) {
            $baseScore = $cvssEntry.BaseScore
            $vector = $cvssEntry.Vector
        }

        # --- Severity (Threat Type 3)
        $severity = $vuln.Threats |
            Where-Object { $_.Type -eq 3 } |
            Select-Object -First 1 |
            ForEach-Object { $_.Description.Value }

        # --- Exploitation info (Threat Type 1)
        $exploitation = $vuln.Threats |
            Where-Object { $_.Type -eq 1 } |
            Select-Object -First 1 |
            ForEach-Object { $_.Description.Value }

        # --- Published date
        $published = $vuln.RevisionHistory |
            Select-Object -First 1 |
            ForEach-Object { $_.Date }

        $metadata[$cve] = @{
            BaseScore = $baseScore
            Vector = $vector
            Severity = $severity
            PublishedDate = $published
            Exploitation = $exploitation
        }
    }
}

$metadata | ConvertTo-Json -Depth 6
