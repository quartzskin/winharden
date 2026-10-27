param(
    [switch]$SelfTest,
    [switch]$Png,
    [string]$PngPath = (Join-Path $PSScriptRoot 'docs\screenshot.png')
)

if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    $a = @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($SelfTest) { $a += '-SelfTest' }
    if ($Png) { $a += '-Png' }
    $a += @('-PngPath', $PngPath)
    & powershell.exe @a
    exit $LASTEXITCODE
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Import-Module (Join-Path $PSScriptRoot 'WinHarden.psm1') -Force

$script:reader = $null
$script:report = $null
if ($SelfTest) {
    . (Join-Path $PSScriptRoot 'tests\FakeReaders.ps1')
    $script:reader = New-MessyFakeReader
}

function New-Control {
    param([string]$Type, [hashtable]$Props = @{})
    $c = New-Object "Windows.Controls.$Type"
    foreach ($k in $Props.Keys) { $c.$k = $Props[$k] }
    $c
}

function New-Column {
    param($Header, $Path, $Width)
    $col = New-Object Windows.Controls.DataGridTextColumn
    $col.Header = $Header
    $col.Binding = New-Object Windows.Data.Binding $Path
    $col.Width = $Width; $col.MinWidth = 60
    $col
}

$bar = New-Control StackPanel @{ Orientation = 'Horizontal'; Margin = '8' }
$statusBox = New-Control ComboBox @{ Width = 90; Margin = '4,0,12,0' }
$areaBox = New-Control ComboBox @{ Width = 130; Margin = '4,0,12,0' }
$rescan = New-Control Button @{ Content = 'Rescan'; Padding = '12,2,12,2' }
$summary = New-Control TextBlock @{ Margin = '16,0,0,0'; VerticalAlignment = 'Center' }
$statusBox.ItemsSource = @('all', 'fail', 'warn', 'unknown', 'pass')
$areaBox.ItemsSource = @('all') + @(Get-WinHardenAreas)
$statusBox.SelectedIndex = 0; $areaBox.SelectedIndex = 0
foreach ($c in @(
        (New-Control Label @{ Content = 'Status' }), $statusBox,
        (New-Control Label @{ Content = 'Area' }), $areaBox, $rescan, $summary)) { [void]$bar.Children.Add($c) }

$grid = New-Control DataGrid @{
    AutoGenerateColumns = $false; IsReadOnly = $true; SelectionMode = 'Single'
    HeadersVisibility = 'Column'; GridLinesVisibility = 'Horizontal'; Margin = '8,0,8,8'
}
$star = New-Object Windows.Controls.DataGridLength 1, ([Windows.Controls.DataGridLengthUnitType]::Star)
[void]$grid.Columns.Add((New-Column 'Area' 'Area' 100))
[void]$grid.Columns.Add((New-Column 'Check' 'Title' 230))
[void]$grid.Columns.Add((New-Column 'Status' 'Status' 70))
[void]$grid.Columns.Add((New-Column 'Evidence' 'Evidence' $star))
$wrap = New-Object Windows.Style ([Windows.Controls.TextBlock])
$wrap.Setters.Add((New-Object Windows.Setter ([Windows.Controls.TextBlock]::TextWrappingProperty), ([Windows.TextWrapping]::Wrap)))
$grid.Columns[3].ElementStyle = $wrap
$grid.Columns[3].MinWidth = 300

$dTitle = New-Control TextBlock @{ FontWeight = 'Bold'; Margin = '0,0,0,4' }
$dEvidence = New-Control TextBlock @{ TextWrapping = 'Wrap'; Margin = '0,0,0,4' }
$dWhy = New-Control TextBlock @{ TextWrapping = 'Wrap'; Margin = '0,0,0,6' }
$dFix = New-Control TextBox @{ IsReadOnly = $true; TextWrapping = 'Wrap'; FontFamily = 'Consolas'; MinHeight = 48; MaxHeight = 80; VerticalScrollBarVisibility = 'Auto' }
$copy = New-Control Button @{ Content = 'Copy fix'; Padding = '12,2,12,2'; Margin = '0,6,0,0'; HorizontalAlignment = 'Left' }
$details = New-Control StackPanel @{ Margin = '8' }
$fixLabel = New-Control TextBlock @{ Text = 'Fix (shown only, never run):'; Margin = '0,0,0,2' }
foreach ($c in $dTitle, $dEvidence, $dWhy, $fixLabel, $dFix, $copy) { [void]$details.Children.Add($c) }
$box = New-Control GroupBox @{ Header = 'Details'; Margin = '8,0,8,8'; Content = $details }

$root = New-Object Windows.Controls.Grid
$root.Background = [Windows.SystemColors]::ControlBrush
foreach ($h in 'Auto', '*', 'Auto') {
    $rd = New-Object Windows.Controls.RowDefinition
    $rd.Height = $h
    [void]$root.RowDefinitions.Add($rd)
}
[Windows.Controls.Grid]::SetRow($grid, 1); [Windows.Controls.Grid]::SetRow($box, 2)
foreach ($c in $bar, $grid, $box) { [void]$root.Children.Add($c) }

function Show-Details {
    $r = $grid.SelectedItem
    $copy.Content = 'Copy fix'
    if (-not $r) {
        $dTitle.Text = ''; $dEvidence.Text = ''; $dWhy.Text = ''; $dFix.Text = ''
        $copy.IsEnabled = $false
        return
    }
    $dTitle.Text = "$($r.Title) [$($r.Status)]"
    $dEvidence.Text = $r.Evidence
    $dWhy.Text = $r.Why
    $dFix.Text = $r.Fix
    $copy.IsEnabled = $true
}

function Update-List {
    $rows = @($script:report.Results)
    if ($statusBox.SelectedItem -and $statusBox.SelectedItem -ne 'all') { $rows = @($rows | Where-Object Status -eq $statusBox.SelectedItem) }
    if ($areaBox.SelectedItem -and $areaBox.SelectedItem -ne 'all') { $rows = @($rows | Where-Object Area -eq $areaBox.SelectedItem) }
    $grid.ItemsSource = $rows
    if ($rows.Count) { $grid.SelectedIndex = 0 }
    Show-Details
}

function Update-Audit {
    $script:report = Invoke-WinHardenAudit -Reader $script:reader
    $c = $script:report.Counts
    $note = ''
    if (-not $script:report.IsAdmin) { $note = '   (not elevated: admin-only checks are unknown)' }
    $summary.Text = "$($c.fail) fail, $($c.warn) warn, $($c.unknown) unknown, $($c.pass) pass$note"
    Update-List
}

$grid.Add_SelectionChanged({ Show-Details })
$statusBox.Add_SelectionChanged({ if ($script:report) { Update-List } })
$areaBox.Add_SelectionChanged({ if ($script:report) { Update-List } })
$copy.Add_Click({ if ($grid.SelectedItem) { [Windows.Clipboard]::SetText($grid.SelectedItem.Fix); $copy.Content = 'Copied' } })
$rescan.Add_Click({ $rescan.IsEnabled = $false; try { Update-Audit } finally { $rescan.IsEnabled = $true } })

Update-Audit

if ($SelfTest) {
    $w = 1000; $h = 680
    $root.Measure((New-Object Windows.Size $w, $h)); $root.Arrange((New-Object Windows.Rect 0, 0, $w, $h)); $root.UpdateLayout()
    $problems = @()
    $res = $script:report.Results
    if ($res.Count -ne 24) { $problems += "expected 24 results, got $($res.Count)" }
    if ($grid.Items.Count -ne 24) { $problems += "grid shows $($grid.Items.Count) rows" }
    if ($dFix.Text -notmatch '\S') { $problems += 'detail panel empty' }
    $statusBox.SelectedItem = 'fail'
    if ($grid.Items.Count -ne $script:report.Counts.fail) { $problems += "status filter shows $($grid.Items.Count) rows" }
    $areaBox.SelectedItem = 'Disk'
    $want = @($res | Where-Object { $_.Status -eq 'fail' -and $_.Area -eq 'Disk' }).Count
    if ($grid.Items.Count -ne $want) { $problems += "status+area filter shows $($grid.Items.Count) rows, want $want" }
    $statusBox.SelectedItem = 'pass'; $areaBox.SelectedItem = 'Remote Access'
    if ($grid.Items.Count -and $copy.IsEnabled -ne $true) { $problems += 'copy disabled with a row selected' }
    $statusBox.SelectedIndex = 0; $areaBox.SelectedIndex = 0
    if ($grid.Items.Count -ne 24) { $problems += 'reset filter did not restore rows' }
    if ($problems) { $problems | ForEach-Object { Write-Host "FAIL: $_" -ForegroundColor Red }; exit 1 }
    $root.UpdateLayout()
    if ($Png) {
        $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap $w, $h, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
        $bmp.Render($root)
        $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
        $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
        $dir = Split-Path $PngPath -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $fs = [IO.File]::Create($PngPath)
        try { $enc.Save($fs) } finally { $fs.Dispose() }
        Write-Host "wrote $PngPath ($w x $h)"
    }
    $c = $script:report.Counts
    Write-Host "selftest ok: $($res.Count) checks, $($c.fail) fail, $($c.warn) warn"
    exit 0
}

$win = New-Object Windows.Window
$win.Title = 'winharden'; $win.Content = $root; $win.Width = 1000; $win.Height = 680
$win.WindowStartupLocation = 'CenterScreen'
[void]$win.ShowDialog()
