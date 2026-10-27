param(
    [switch]$Json,
    [string]$Html,
    [string[]]$Area,
    [switch]$Quiet
)

Import-Module (Join-Path $PSScriptRoot 'WinHarden.psm1') -Force
if ($Area) {
    $bad = @($Area | Where-Object { $_ -notin (Get-WinHardenAreas) })
    if ($bad) {
        [Console]::Error.WriteLine("winharden: unknown area '$($bad -join "', '")'. Valid areas: $((Get-WinHardenAreas) -join ', ')")
        exit 2
    }
}
$report = Invoke-WinHardenAudit -Area $Area

if ($Html) {
    $dir = Split-Path -Parent ([IO.Path]::GetFullPath($Html))
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    ConvertTo-WinHardenHtml $report | Set-Content -LiteralPath $Html -Encoding UTF8 -ErrorAction Stop
    if (-not $Json) { Write-Host "wrote $Html" }
}

if ($Json) {
    ConvertTo-WinHardenJson $report
    return
}

if (-not $Quiet) {
    $colors = @{ pass = 'Green'; warn = 'Yellow'; fail = 'Red'; unknown = 'DarkGray' }
    foreach ($a in (Get-WinHardenAreas)) {
        $rows = @($report.Results | Where-Object Area -eq $a)
        if (-not $rows) { continue }
        Write-Host "`n$a"
        foreach ($r in $rows) {
            Write-Host ('  [{0,-7}] ' -f $r.Status.ToUpper()) -ForegroundColor $colors[$r.Status] -NoNewline
            Write-Host "$($r.Title): $($r.Evidence)"
            if ($r.Status -in 'warn', 'fail') {
                Write-Host "      why: $($r.Why)" -ForegroundColor DarkGray
                foreach ($line in ($r.Fix -split "`n")) { Write-Host "      fix: $line" -ForegroundColor DarkGray }
            }
        }
    }
    $c = $report.Counts
    Write-Host "`n$($c.fail) fail, $($c.warn) warn, $($c.unknown) unknown, $($c.pass) pass"
    if (-not $report.IsAdmin) { Write-Host 'Not elevated: admin-only checks are reported as unknown. Fix commands are printed only, never run.' -ForegroundColor DarkGray }
}
