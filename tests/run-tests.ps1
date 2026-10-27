$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'WinHarden.psm1') -Force
. (Join-Path $PSScriptRoot 'FakeReaders.ps1')

$script:pass = 0
$script:failed = @()

function Check {
    param([string]$Name, [bool]$Cond)
    if ($Cond) { $script:pass++ } else { $script:failed += $Name; Write-Host "FAIL: $Name" -ForegroundColor Red }
}

function Run {
    param($Reader)
    $rep = Invoke-WinHardenAudit -Reader $Reader
    $h = @{}
    foreach ($r in $rep.Results) { $h[$r.Id] = $r }
    $h
}

function Status {
    param([string]$Id, [string]$Want, $Reader, [string]$Name)
    $h = Run $Reader
    Check "$Id -> $Want ($Name; got $($h[$Id].Status): $($h[$Id].Evidence))" ($h[$Id].Status -eq $Want)
}

$K = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$UAC = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

$healthy = Run (New-FakeReader)
foreach ($id in $healthy.Keys) {
    Check "healthy: $id passes ($($healthy[$id].Evidence))" ($healthy[$id].Status -eq 'pass')
    $r = $healthy[$id]
    Check "$id has why/fix/evidence/area" ($r.Why -and $r.Fix -and $r.Evidence -and $r.Area -and $r.Label)
}
Check 'check count' ($healthy.Count -eq 24)
$adminRep = Invoke-WinHardenAudit -Reader (New-FakeReader)
Check 'report.IsAdmin follows the reader' ($adminRep.IsAdmin -eq $true -and (Invoke-WinHardenAudit -Reader (New-FakeReader -Override @{ IsAdmin = { $false } })).IsAdmin -eq $false)
Check 'every area has a check' ((Get-WinHardenAreas | Where-Object { $a = $_; -not ($healthy.Values | Where-Object Area -eq $a) }).Count -eq 0)

Status defender-realtime fail (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $false } } }) 'rt off'
Status defender-realtime warn (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ AMServiceEnabled = $false; RealTimeProtectionEnabled = $false } } }) 'service off'
Status defender-realtime unknown (New-FakeReader -Override @{ MpStatus = { throw 'no defender' } }) 'cmdlet throws'
Status defender-signatures warn (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ AntivirusSignatureAge = 5 } } }) 'age 5'
Status defender-signatures fail (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ AntivirusSignatureAge = 30 } } }) 'age 30'
Status defender-signatures unknown (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ } } }) 'no age'
Status defender-tamper warn (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ IsTamperProtected = $false } } }) 'tamper off'
Status defender-exclusions pass (New-FakeReader) 'none'
Status defender-exclusions warn (New-FakeReader -Override @{ MpPref = { [pscustomobject]@{ ExclusionPath = @('C:\Tools') } } }) 'one path'
Status defender-exclusions fail (New-FakeReader -Override @{ MpPref = { [pscustomobject]@{ ExclusionPath = @('C:\') } } }) 'drive root'
Status defender-exclusions fail (New-FakeReader -Override @{ MpPref = { [pscustomobject]@{ ExclusionExtension = @('.exe') } } }) 'exe ext'
$na = { [pscustomobject]@{ ExclusionPath = @('N/A: Must be an administrator to view exclusions') } }
Status defender-exclusions unknown (New-FakeReader -Override @{ IsAdmin = { $false }; MpPref = $na }) 'hidden for non-admin'
$h = Run (New-FakeReader -Override @{ IsAdmin = { $false }; MpPref = $na })
Check 'exclusions evidence says needs admin' ($h['defender-exclusions'].Evidence -eq 'unknown (needs admin)' -and $h['defender-exclusions'].NeedsAdmin)

$fw = { param($pub) { [pscustomobject]@{ Items = @([pscustomobject]@{ Name = 'Public'; Enabled = $pub[0]; DefaultInbound = $pub[1] }) } }.GetNewClosure() }
Status firewall-public fail (New-FakeReader -Override @{ Firewall = (& $fw @('False', 'Block')) }) 'disabled'
Status firewall-public warn (New-FakeReader -Override @{ Firewall = (& $fw @('True', 'Allow')) }) 'allow inbound'
Status firewall-private unknown (New-FakeReader -Override @{ Firewall = (& $fw @('True', 'Block')) }) 'profile missing'
Status firewall-domain unknown (New-FakeReader -Override @{ Firewall = { throw 'denied' } }) 'cmdlet throws'

Status smb1 fail (New-FakeReader -Override @{ Smb1Config = { $true } }) 'cfg on'
Status smb1 fail (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = 1 } -Override @{ Smb1Config = { throw 'admin' } }) 'registry fallback on'
Status smb1 pass (New-FakeReader -Override @{ Smb1Config = { throw 'admin' } }) 'registry fallback off'
Status smb1 unknown (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = $null } -Override @{ IsAdmin = { $false }; Smb1Config = { throw 'admin' } }) 'nothing readable'
$h = Run (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = $null } -Override @{ IsAdmin = { $false }; Smb1Config = { throw 'admin' } })
Check 'smb1 needs admin text' ($h['smb1'].Evidence -eq 'unknown (needs admin)')
Status smb-signing warn (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature' = 0 }) 'not required'
Status smb-signing warn (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature' = $null }) 'unset'

$ls = { param($ports) { [pscustomobject]@{ Items = @($ports | ForEach-Object { [pscustomobject]@{ Port = $_; Process = 'x' } }) } }.GetNewClosure() }
Status listening pass (New-FakeReader -Override @{ Listeners = (& $ls @()) }) 'empty'
Status listening pass (New-FakeReader -Override @{ Listeners = (& $ls @(135, 445, 49664)) }) 'normal windows ports'
Status listening warn (New-FakeReader -Override @{ Listeners = (& $ls @(3389)) }) 'rdp'
Status listening fail (New-FakeReader -Override @{ Listeners = (& $ls @(3389, 23)) }) 'telnet'
Status listening unknown (New-FakeReader -Override @{ Listeners = { throw 'x' } }) 'cmdlet throws'

Status bitlocker fail (New-FakeReader -Override @{ BitLocker = { 0 } }) 'off'
Status bitlocker warn (New-FakeReader -Override @{ BitLocker = { 5 } }) 'suspended'
Status bitlocker unknown (New-FakeReader -Override @{ BitLocker = { 99 } }) 'odd code'
Status bitlocker unknown (New-FakeReader -Override @{ BitLocker = { $null } }) 'no value'
Status secureboot fail (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State|UEFISecureBootEnabled' = 0 }) 'off'
Status secureboot unknown (New-FakeReader -Reg @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State|UEFISecureBootEnabled' = $null }) 'bios'
Status tpm warn (New-FakeReader -Override @{ Tpm = { [pscustomobject]@{ Items = @() } } }) 'none'
Status tpm unknown (New-FakeReader -Override @{ Tpm = { throw 'x' } }) 'throws'
Status autorun warn (New-FakeReader -Reg @{ 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun' = 0 }) 'enabled'
Status autorun pass (New-FakeReader -Reg @{ 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun' = $null }) 'default'

Status guest fail (New-FakeReader -Override @{ GuestEnabled = { $true } }) 'enabled'
Status guest unknown (New-FakeReader -Override @{ GuestEnabled = { throw 'x' } }) 'throws'
$na1 = { param($l) { [pscustomobject]@{ Items = $l } }.GetNewClosure() }
Status password-length fail (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Minimum password length:    0')) }) 'zero'
Status password-length warn (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Minimum password length:    8')) }) 'eight'
Status password-length unknown (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Mindestlaenge des Kennworts:   8')) }) 'german output'
Status password-length unknown (New-FakeReader -Override @{ NetAccounts = (& $na1 @()) }) 'empty output'
Status password-length unknown (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Minimum password length:    ??')) }) 'garbage value'
Status lockout fail (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Lockout threshold:     Never')) }) 'never'
Status lockout warn (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Lockout threshold:     50')) }) '50'
Status lockout unknown (New-FakeReader -Override @{ NetAccounts = (& $na1 @('Lockout threshold:     soon')) }) 'junk'
Status uac fail (New-FakeReader -Reg @{ "$UAC|EnableLUA" = 0 }) 'lua off'
Status uac fail (New-FakeReader -Reg @{ "$UAC|ConsentPromptBehaviorAdmin" = 0 }) 'no prompt'
Status uac warn (New-FakeReader -Reg @{ "$UAC|PromptOnSecureDesktop" = 0 }) 'no secure desktop'
Status uac unknown (New-FakeReader -Reg @{ "$UAC|EnableLUA" = $null }) 'unreadable'

Status rdp warn (New-FakeReader -Reg @{ "$K|fDenyTSConnections" = 0 }) 'enabled'
Status rdp-nla fail (New-FakeReader -Reg @{ "$K|fDenyTSConnections" = 0; "$K\WinStations\RDP-Tcp|UserAuthentication" = 0 }) 'enabled without nla'
Status rdp-nla pass (New-FakeReader -Reg @{ "$K|fDenyTSConnections" = 1; "$K\WinStations\RDP-Tcp|UserAuthentication" = 0 }) 'rdp off'
Status ps-execpolicy warn (New-FakeReader -Override @{ ExecPolicy = { @{ LocalMachine = 'Unrestricted'; CurrentUser = 'Undefined' } } }) 'unrestricted'
Status ps-execpolicy pass (New-FakeReader -Override @{ ExecPolicy = { @{ LocalMachine = 'Unrestricted'; CurrentUser = 'AllSigned' } } }) 'user scope wins'
Status ps-execpolicy pass (New-FakeReader -Override @{ ExecPolicy = { @{ Process = 'Bypass'; LocalMachine = 'RemoteSigned' } } }) 'process scope ignored'
Status ps-logging warn (New-FakeReader -Reg @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging' = $null }) 'unset'

Status auto-updates fail (New-FakeReader -Reg @{ 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU|NoAutoUpdate' = 1 }) 'policy off'
Status auto-updates fail (New-FakeReader -Override @{ ServiceStart = { 'Disabled' } }) 'service disabled'
Status auto-updates unknown (New-FakeReader -Override @{ ServiceStart = { throw 'x' } }) 'svc unreadable'
$lk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install|LastSuccessTime'
Status last-update warn (New-FakeReader -Reg @{ $lk = (Get-Date).ToUniversalTime().AddDays(-60).ToString('yyyy-MM-dd HH:mm:ss') }) '60 days'
Status last-update fail (New-FakeReader -Reg @{ $lk = '2001-01-01 00:00:00' }) 'ancient'
Status last-update unknown (New-FakeReader -Reg @{ $lk = 'not a date' }) 'garbage'
Status last-update unknown (New-FakeReader -Reg @{ $lk = $null }) 'missing'

# a reader that throws everywhere must not break the audit
$boom = @{}
foreach ($k in (New-FakeReader).Keys) { $boom[$k] = { throw 'boom' } }
$rep = Invoke-WinHardenAudit -Reader $boom
Check 'all-throwing reader still returns every check' ($rep.Results.Count -eq 24)
Check 'all-throwing reader: nothing is pass' (-not ($rep.Results | Where-Object Status -eq 'pass' | Where-Object Id -notin 'autorun', 'ps-execpolicy'))
Check 'statuses are in the allowed set' (-not ($rep.Results | Where-Object { $_.Status -notin 'pass', 'warn', 'fail', 'unknown' }))

# a check that itself throws becomes unknown with the message
$odd = Invoke-WinHardenAudit -Reader (New-FakeReader -Override @{ MpStatus = { [pscustomobject]@{ AntivirusSignatureAge = 'abc' } } })
$sig = $odd.Results | Where-Object Id -eq 'defender-signatures'
Check 'non-numeric age -> unknown with message' ($sig.Status -eq 'unknown' -and $sig.Evidence -like 'check failed*')

$only = Invoke-WinHardenAudit -Reader (New-FakeReader) -Area 'Updates'
Check 'area filter' ($only.Results.Count -eq 2 -and ($only.Results | Where-Object Area -ne 'Updates').Count -eq 0)

# unknown area is a usage error, not an empty pass
$ErrorActionPreference = 'Continue'
$out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'winharden.ps1') -Area Bogus 2>&1 | Out-String
$ErrorActionPreference = 'Stop'
Check 'bogus area exits 2' ($LASTEXITCODE -eq 2)
Check 'bogus area names the area' ($out -match "unknown area 'Bogus'")

$rep = Invoke-WinHardenAudit -Reader (New-MessyFakeReader)
Check 'messy: has fails' ($rep.Counts.fail -ge 5)
$json = ConvertTo-WinHardenJson $rep
$back = $json | ConvertFrom-Json
Check 'json round trip' ($back.Results.Count -eq 24 -and $back.Counts.fail -eq $rep.Counts.fail)
$bad = Invoke-WinHardenAudit -Reader (New-FakeReader -Override @{ MpPref = { [pscustomobject]@{ ExclusionPath = @('C:\<script>alert(1)</script>') } } })
$html = ConvertTo-WinHardenHtml $bad
Check 'html has no raw injected tag' ($html -notmatch '<script>alert')
Check 'html encodes it' ($html -match '&lt;script&gt;' -or $html -notmatch 'alert')
$html = ConvertTo-WinHardenHtml $rep
Check 'html lists fix text of a failing check' ($html -match 'Set-NetFirewallProfile -Profile Public')
Check 'html is a document' ($html.StartsWith('<!DOCTYPE html>') -and $html.TrimEnd().EndsWith('</html>'))

# the module only prints fixes
$src = Get-Content (Join-Path $root 'WinHarden.psm1') -Raw
Check 'module never evaluates fix text' ($src -notmatch 'Invoke-Expression|\biex\b|Start-Process')

$ErrorActionPreference = 'Continue'
$gui = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'winharden-gui.ps1') -SelfTest 2>&1 | Out-String
$guiExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Check "gui selftest (exit $guiExit): $gui" ($guiExit -eq 0 -and $gui -match 'selftest ok: 24 checks, 11 fail, 7 warn')

Write-Host "$script:pass passed, $($script:failed.Count) failed"
if ($script:failed.Count) { exit 1 }
