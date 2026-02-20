param(
    [Parameter(Mandatory=$true)]
    [string]$MonthIds
)

$months = $MonthIds -split ","

$results = @{}

foreach ($month in $months) {

    $doc = Get-MsrcCvrfDocument -ID $month

    foreach ($v in $doc.Vulnerability) {

        $cve = $v.CVE

        # Severity
        $severity = ($v.Threats | Where-Object { $_.Type -eq 3 } |
                     Select-Object -First 1).Description.Value

        # Exploitation
        $exploit = ($v.Threats | Where-Object { $_.Type -eq 1 } |
                    Select-Object -First 1).Description.Value

        # CVSS
        $cvss = $v.CVSSScoreSets | Select-Object -First 1

        $baseScore = $cvss.BaseScore
        $vector = $cvss.Vector

        # Published date
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

$results | ConvertTo-Json -Depth 5