$script:Areas = 'Defender', 'Network', 'Disk', 'Accounts', 'Remote Access', 'Updates'

function New-WinHardenReader {
    @{
        IsAdmin = {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        Reg = {
            param($Path, $Name)
            try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
        }
        MpStatus = { Get-MpComputerStatus -ErrorAction Stop }
        MpPref = { Get-MpPreference -ErrorAction Stop }
        Firewall = {
            $items = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = "$($_.Name)"; Enabled = "$($_.Enabled)"; DefaultInbound = "$($_.DefaultInboundAction)" }
            })
            [pscustomobject]@{ Items = $items }
        }
        # Explorer shell property works without elevation, unlike Get-BitLockerVolume
        BitLocker = {
            $sh = New-Object -ComObject Shell.Application
            $v = $sh.NameSpace("$($env:SystemDrive)\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
            if ($null -ne $v) { [int]$v }
        }
        Tpm = {
            $items = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
                Where-Object { $_.FriendlyName -like 'Trusted Platform Module*' } | ForEach-Object { $_.FriendlyName })
            [pscustomobject]@{ Items = $items }
        }
        Smb1Config = { (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol }
        NetAccounts = { [pscustomobject]@{ Items = @(net accounts 2>$null) } }
        GuestEnabled = {
            $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' }
            if ($g) { [bool]$g.Enabled }
        }
        Listeners = {
            $names = @{}
            Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
            $seen = @{}
            $items = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } | ForEach-Object {
                    if (-not $seen.ContainsKey($_.LocalPort)) {
                        $seen[$_.LocalPort] = 1
                        $p = $names[[int]$_.OwningProcess]
                        if (-not $p) { $p = '?' }
                        [pscustomobject]@{ Port = [int]$_.LocalPort; Process = $p }
                    }
                } | Sort-Object Port)
            [pscustomobject]@{ Items = $items }
        }
        ExecPolicy = {
            $h = @{}
            Get-ExecutionPolicy -List | ForEach-Object { $h["$($_.Scope)"] = "$($_.ExecutionPolicy)" }
            $h
        }
        ServiceStart = { (Get-Service -Name $args[0] -ErrorAction Stop).StartType.ToString() }
    }
}

function Invoke-Reader {
    param($R, $Name)
    try { & $R[$Name] @args } catch { $null }
}

function Cant {
    param($R, $what)
    if (-not (Invoke-Reader $R 'IsAdmin')) { return @('unknown', 'unknown (needs admin)', $true) }
    @('unknown', "could not read $what")
}

function Get-AcctValue {
    param($Lines, $Label)
    foreach ($l in $Lines) {
        if ($l -match "^\s*$Label[^:]*:\s*(.*?)\s*$") { return $Matches[1] }
    }
    $null
}

$script:RiskyPorts = @{
    21 = 'FTP'; 23 = 'Telnet'; 69 = 'TFTP'; 512 = 'rexec'; 513 = 'rlogin'; 514 = 'rsh'
    1433 = 'SQL Server'; 3306 = 'MySQL'; 3389 = 'RDP'; 5432 = 'PostgreSQL'; 5900 = 'VNC'
    5985 = 'WinRM'; 5986 = 'WinRM TLS'; 6379 = 'Redis'; 9200 = 'Elasticsearch'; 27017 = 'MongoDB'
}

function New-FirewallCheck {
    param($Prof)
    @{
        Prof = $Prof; Id = "firewall-$($Prof.ToLower())"; Area = 'Network'; Label = "FW $Prof"
        Title = "Firewall: $Prof profile"
        Why = 'The firewall is what stops other machines on the network from reaching services on this one.'
        Fix = "Set-NetFirewallProfile -Profile $Prof -Enabled True -DefaultInboundAction Block"
        Run = {
            param($R, $C)
            $fw = Invoke-Reader $R 'Firewall'
            if (-not $fw) { return (Cant $R 'firewall profiles') }
            $p = @($fw.Items) | Where-Object { $_.Name -eq $C.Prof }
            if (-not $p) { return @('unknown', "profile $($C.Prof) not reported") }
            $ev = "enabled=$($p.Enabled), default inbound=$($p.DefaultInbound)"
            if ($p.Enabled -ne 'True') { return @('fail', $ev) }
            if ($p.DefaultInbound -eq 'Allow') { return @('warn', $ev) }
            @('pass', $ev)
        }
    }
}

function Get-WinHardenChecks {
    $c = New-Object System.Collections.ArrayList

    [void]$c.Add(@{
        Id = 'defender-realtime'; Area = 'Defender'; Label = 'Real-time'
        Title = 'Defender real-time protection'
        Why = 'Real-time scanning is what catches malware as it is written or run.'
        Fix = 'Set-MpPreference -DisableRealtimeMonitoring $false'
        Run = {
            param($R)
            $st = Invoke-Reader $R 'MpStatus'
            if (-not $st) { return @('unknown', 'Get-MpComputerStatus failed (another antivirus may be in charge)') }
            if ($st.AMServiceEnabled -eq $false) { return @('warn', 'Defender service is not running (another antivirus may be active)') }
            if ($st.RealTimeProtectionEnabled) { return @('pass', 'RealTimeProtectionEnabled=True') }
            @('fail', 'RealTimeProtectionEnabled=False')
        }
    })
    [void]$c.Add(@{
        Id = 'defender-signatures'; Area = 'Defender'; Label = 'Signatures'
        Title = 'Defender signature age'
        Why = 'Old signatures miss recent malware, so the scanner is only as good as its last update.'
        Fix = 'Update-MpSignature'
        Run = {
            param($R)
            $st = Invoke-Reader $R 'MpStatus'
            if (-not $st -or $null -eq $st.AntivirusSignatureAge) { return @('unknown', 'signature age not reported') }
            $d = [int]$st.AntivirusSignatureAge
            $ev = "signatures are $d day(s) old"
            if ($d -le 3) { return @('pass', $ev) }
            if ($d -le 7) { return @('warn', $ev) }
            @('fail', $ev)
        }
    })
    [void]$c.Add(@{
        Id = 'defender-tamper'; Area = 'Defender'; Label = 'Tamper'
        Title = 'Defender tamper protection'
        Why = 'Tamper protection stops malware from simply switching Defender off.'
        Fix = 'Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On (no supported PowerShell switch)'
        Run = {
            param($R)
            $st = Invoke-Reader $R 'MpStatus'
            if (-not $st -or $null -eq $st.IsTamperProtected) { return @('unknown', 'tamper state not reported') }
            if ($st.IsTamperProtected) { return @('pass', 'IsTamperProtected=True') }
            @('warn', 'IsTamperProtected=False')
        }
    })
    [void]$c.Add(@{
        Id = 'defender-exclusions'; Area = 'Defender'; Label = 'Exclusions'
        Title = 'Defender exclusions'
        Why = 'Anything excluded from scanning is a place malware can sit unseen, and broad exclusions defeat the scanner.'
        Fix = "Get-MpPreference | Select ExclusionPath, ExclusionExtension, ExclusionProcess`nRemove-MpPreference -ExclusionPath '<path>'"
        Run = {
            param($R)
            $p = Invoke-Reader $R 'MpPref'
            if (-not $p) { return (Cant $R 'Defender preferences') }
            $all = @($p.ExclusionPath) + @($p.ExclusionExtension) + @($p.ExclusionProcess) | Where-Object { $_ }
            if ($all | Where-Object { "$_" -like 'N/A: Must be an administrator*' }) { return @('unknown', 'unknown (needs admin)', $true) }
            if (-not $all) { return @('pass', 'no exclusions configured') }
            $broad = @($p.ExclusionPath) | Where-Object { $_ -match '^[A-Za-z]:\\?\*?$' }
            $badExt = @($p.ExclusionExtension) | Where-Object { $_ -match '^\.?(exe|dll|ps1|bat|cmd|js|vbs|scr)$' }
            $ev = "$(@($all).Count) exclusion(s)"
            if ($broad -or $badExt) { return @('fail', "$ev, including drive-wide or executable-type exclusions") }
            @('warn', $ev)
        }
    })

    foreach ($pr in 'Domain', 'Private', 'Public') { [void]$c.Add((New-FirewallCheck $pr)) }

    [void]$c.Add(@{
        Id = 'smb1'; Area = 'Network'; Label = 'SMBv1'
        Title = 'SMBv1 server protocol'
        Why = 'SMBv1 is the old file-sharing protocol exploited by EternalBlue and WannaCry; nothing modern needs it.'
        Fix = "Set-SmbServerConfiguration -EnableSMB1Protocol `$false`nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
        Run = {
            param($R)
            $cfg = Invoke-Reader $R 'Smb1Config'
            if ($null -ne $cfg) {
                if ($cfg) { return @('fail', 'EnableSMB1Protocol=True') }
                return @('pass', 'EnableSMB1Protocol=False')
            }
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
            if ($null -eq $v) { return (Cant $R 'SMB1 state (registry value not set)') }
            if ([int]$v -eq 0) { return @('pass', 'LanmanServer SMB1=0') }
            @('fail', "LanmanServer SMB1=$v")
        }
    })
    [void]$c.Add(@{
        Id = 'smb-signing'; Area = 'Network'; Label = 'SMB sign'
        Title = 'SMB signing required'
        Why = 'Without required signing, someone on the network can tamper with or relay SMB traffic.'
        Fix = 'Set-SmbServerConfiguration -RequireSecuritySignature $true'
        Run = {
            param($R)
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
            if ($null -eq $v) { return @('warn', 'RequireSecuritySignature not set (server does not require signing by default)') }
            if ([int]$v -eq 1) { return @('pass', 'RequireSecuritySignature=1') }
            @('warn', "RequireSecuritySignature=$v")
        }
    })
    [void]$c.Add(@{
        Id = 'listening'; Area = 'Network'; Label = 'Listeners'
        Title = 'Services listening on all interfaces'
        Why = 'A service bound to 0.0.0.0 is reachable from every network the machine is on, not just localhost.'
        Fix = "Get-NetTCPConnection -State Listen | ? LocalAddress -in '0.0.0.0','::' | Sort LocalPort`nNew-NetFirewallRule -DisplayName 'Block <port>' -Direction Inbound -Protocol TCP -LocalPort <port> -Action Block"
        Run = {
            param($R)
            $l = Invoke-Reader $R 'Listeners'
            if (-not $l) { return @('unknown', 'could not list listening sockets') }
            $items = @($l.Items)
            $risky = @($items | Where-Object { $script:RiskyPorts.ContainsKey([int]$_.Port) })
            $desc = { param($x) ($x | ForEach-Object { "$($_.Port)/$($script:RiskyPorts[[int]$_.Port]) ($($_.Process))" }) -join ', ' }
            $ev = "$($items.Count) port(s) on all interfaces"
            if (-not $risky) { return @('pass', "$ev, none from the risky-service list (a listener may still be blocked by the firewall)") }
            $status = 'warn'
            if ($risky | Where-Object { $_.Port -in 21, 23, 69, 512, 513, 514, 5900 }) { $status = 'fail' }
            @($status, "$ev; risky: $(& $desc $risky)")
        }
    })

    [void]$c.Add(@{
        Id = 'bitlocker'; Area = 'Disk'; Label = 'BitLocker'
        Title = 'BitLocker on the system drive'
        Why = 'Without disk encryption anyone holding a lost or stolen machine can read the drive.'
        Fix = 'Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -RecoveryPasswordProtector'
        Run = {
            param($R)
            $v = Invoke-Reader $R 'BitLocker'
            if ($null -eq $v) { return @('unknown', 'BitLocker state not reported (unsupported edition or no access)') }
            switch ([int]$v) {
                1 { return @('pass', 'system drive protection is on') }
                3 { return @('warn', 'system drive is mid-encryption or mid-decryption') }
                5 { return @('warn', 'protection is suspended') }
                { $_ -in 0, 2 } { return @('fail', 'system drive is not protected') }
            }
            @('unknown', "unrecognised protection code $v")
        }
    })
    [void]$c.Add(@{
        Id = 'secureboot'; Area = 'Disk'; Label = 'Secure Boot'
        Title = 'Secure Boot'
        Why = 'Secure Boot refuses unsigned boot loaders, which blocks most bootkits.'
        Fix = 'Enable Secure Boot in the UEFI firmware setup; check with Confirm-SecureBootUEFI (admin)'
        Run = {
            param($R)
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
            if ($null -eq $v) { return @('unknown', 'state key absent (legacy BIOS boot or unsupported firmware)') }
            if ([int]$v -eq 1) { return @('pass', 'UEFISecureBootEnabled=1') }
            @('fail', "UEFISecureBootEnabled=$v")
        }
    })
    [void]$c.Add(@{
        Id = 'tpm'; Area = 'Disk'; Label = 'TPM'
        Title = 'TPM present'
        Why = 'A TPM holds disk-encryption keys and sign-in secrets in hardware instead of on disk.'
        Fix = 'Enable fTPM / Intel PTT in the firmware setup; details with Get-Tpm (admin)'
        Run = {
            param($R)
            $t = Invoke-Reader $R 'Tpm'
            if (-not $t) { return @('unknown', 'could not enumerate devices') }
            $items = @($t.Items)
            if ($items.Count) { return @('pass', "$($items[0])") }
            @('warn', 'no Trusted Platform Module device found')
        }
    })
    [void]$c.Add(@{
        Id = 'autorun'; Area = 'Disk'; Label = 'AutoRun'
        Title = 'AutoRun on removable drives'
        Why = 'AutoRun lets a USB stick or disc start code the moment it is plugged in.'
        Fix = "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord"
        Run = {
            param($R)
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
            if ($null -eq $v) { return @('pass', 'no policy set; Windows default does not run autorun.inf from removable media') }
            if (([int]$v -band 0x34) -eq 0x34) { return @('pass', "NoDriveTypeAutoRun=$v") }
            @('warn', "NoDriveTypeAutoRun=$v leaves some drive types enabled")
        }
    })

    [void]$c.Add(@{
        Id = 'guest'; Area = 'Accounts'; Label = 'Guest'
        Title = 'Guest account'
        Why = 'An enabled guest account is a sign-in that needs no real identity.'
        Fix = 'net user guest /active:no'
        Run = {
            param($R)
            $g = Invoke-Reader $R 'GuestEnabled'
            if ($null -eq $g) { return @('unknown', 'guest account not found or not readable') }
            if ($g) { return @('fail', 'Guest is enabled') }
            @('pass', 'Guest is disabled')
        }
    })
    [void]$c.Add(@{
        Id = 'password-length'; Area = 'Accounts'; Label = 'Pwd length'
        Title = 'Minimum password length'
        Why = 'Short passwords fall quickly to guessing, and a minimum of zero allows blank ones.'
        Fix = 'net accounts /minpwlen:12'
        Run = {
            param($R)
            $a = Invoke-Reader $R 'NetAccounts'
            if (-not $a) { return @('unknown', '"net accounts" failed') }
            $v = Get-AcctValue $a.Items 'Minimum password length'
            if ($v -notmatch '^\d+$') { return @('unknown', 'could not parse "net accounts" (non-English Windows?)') }
            $n = [int]$v
            if ($n -ge 12) { return @('pass', "minimum length $n") }
            if ($n -ge 8) { return @('warn', "minimum length $n") }
            @('fail', "minimum length $n")
        }
    })
    [void]$c.Add(@{
        Id = 'lockout'; Area = 'Accounts'; Label = 'Lockout'
        Title = 'Account lockout threshold'
        Why = 'Without lockout, a password can be guessed at unlimited speed.'
        Fix = 'net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15'
        Run = {
            param($R)
            $a = Invoke-Reader $R 'NetAccounts'
            if (-not $a) { return @('unknown', '"net accounts" failed') }
            $v = Get-AcctValue $a.Items 'Lockout threshold'
            if ($null -eq $v) { return @('unknown', 'could not parse "net accounts" (non-English Windows?)') }
            if ($v -eq 'Never' -or $v -eq '0') { return @('fail', 'no lockout threshold') }
            if ($v -notmatch '^\d+$') { return @('unknown', "unrecognised value '$v'") }
            if ([int]$v -le 10) { return @('pass', "locks after $v failed attempts") }
            @('warn', "locks only after $v failed attempts")
        }
    })
    [void]$c.Add(@{
        Id = 'uac'; Area = 'Accounts'; Label = 'UAC'
        Title = 'User Account Control'
        Why = 'UAC is the prompt between a program and administrator rights; turned down, malware gets them silently.'
        Fix = "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1`nSet-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5"
        Run = {
            param($R)
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            $lua = Invoke-Reader $R 'Reg' $k 'EnableLUA'
            $cp = Invoke-Reader $R 'Reg' $k 'ConsentPromptBehaviorAdmin'
            $sd = Invoke-Reader $R 'Reg' $k 'PromptOnSecureDesktop'
            if ($null -eq $lua) { return @('unknown', 'EnableLUA not readable') }
            $ev = "EnableLUA=$lua, ConsentPromptBehaviorAdmin=$cp, PromptOnSecureDesktop=$sd"
            if ([int]$lua -eq 0) { return @('fail', $ev) }
            if ($null -ne $cp -and [int]$cp -eq 0) { return @('fail', $ev) }
            if (($null -ne $sd -and [int]$sd -eq 0) -or ($null -ne $cp -and [int]$cp -in 3, 4)) { return @('warn', $ev) }
            @('pass', $ev)
        }
    })

    [void]$c.Add(@{
        Id = 'rdp'; Area = 'Remote Access'; Label = 'RDP'
        Title = 'Remote Desktop'
        Why = 'Remote Desktop is a favourite brute-force target; leave it off unless you use it.'
        Fix = "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1"
        Run = {
            param($R)
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
            if ($null -eq $v) { return @('unknown', 'fDenyTSConnections not readable') }
            if ([int]$v -eq 1) { return @('pass', 'Remote Desktop connections are denied') }
            @('warn', 'Remote Desktop is enabled')
        }
    })
    [void]$c.Add(@{
        Id = 'rdp-nla'; Area = 'Remote Access'; Label = 'RDP NLA'
        Title = 'RDP Network Level Authentication'
        Why = 'NLA makes a client authenticate before a session is created, which blunts pre-login attacks.'
        Fix = "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        Run = {
            param($R)
            $deny = Invoke-Reader $R 'Reg' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
            if ($null -ne $deny -and [int]$deny -eq 1) { return @('pass', 'RDP is off, NLA not relevant') }
            if ($null -eq $v) { return @('unknown', 'UserAuthentication not readable') }
            if ([int]$v -eq 1) { return @('pass', 'UserAuthentication=1') }
            @('fail', "UserAuthentication=$v while RDP is enabled")
        }
    })
    [void]$c.Add(@{
        Id = 'ps-execpolicy'; Area = 'Remote Access'; Label = 'PS policy'
        Title = 'PowerShell execution policy'
        Why = 'It is a guard rail, not a security boundary, but Unrestricted/Bypass removes even the speed bump.'
        Fix = 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine'
        Run = {
            param($R)
            $e = Invoke-Reader $R 'ExecPolicy'
            if (-not $e) { return @('unknown', 'Get-ExecutionPolicy failed') }
            $eff = 'Restricted'
            foreach ($s in 'MachinePolicy', 'UserPolicy', 'CurrentUser', 'LocalMachine') {
                if ($e[$s] -and $e[$s] -ne 'Undefined') { $eff = $e[$s]; break }
            }
            if ($eff -in 'Unrestricted', 'Bypass') { return @('warn', "effective policy $eff") }
            @('pass', "effective policy $eff")
        }
    })
    [void]$c.Add(@{
        Id = 'ps-logging'; Area = 'Remote Access'; Label = 'PS logging'
        Title = 'PowerShell script block logging'
        Why = 'Script block logging records what PowerShell actually ran, which is often the only trace of a fileless attack.'
        Fix = "New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force`nSet-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
        Run = {
            param($R)
            $v = Invoke-Reader $R 'Reg' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
            if ($null -ne $v -and [int]$v -eq 1) { return @('pass', 'EnableScriptBlockLogging=1') }
            @('warn', 'script block logging policy is not enabled')
        }
    })

    [void]$c.Add(@{
        Id = 'auto-updates'; Area = 'Updates'; Label = 'Auto update'
        Title = 'Automatic updates'
        Why = 'Updates are how known holes get closed; turning them off leaves the machine exposed to old exploits.'
        Fix = "Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate`nSet-Service wuauserv -StartupType Manual"
        Run = {
            param($R)
            $no = Invoke-Reader $R 'Reg' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
            $svc = Invoke-Reader $R 'ServiceStart' 'wuauserv'
            if ($null -ne $no -and [int]$no -eq 1) { return @('fail', 'policy NoAutoUpdate=1') }
            if ($svc -eq 'Disabled') { return @('fail', 'Windows Update service (wuauserv) is disabled') }
            if (-not $svc) { return @('unknown', 'wuauserv state not readable') }
            @('pass', "no policy disabling updates, wuauserv start type $svc")
        }
    })
    [void]$c.Add(@{
        Id = 'last-update'; Area = 'Updates'; Label = 'Last install'
        Title = 'Most recent update install'
        Why = 'Even with updates switched on, a machine that has not installed anything lately is not actually patched.'
        Fix = 'Settings > Windows Update > Check for updates (or: UsoClient StartScan)'
        Run = {
            param($R)
            $s = Invoke-Reader $R 'Reg' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' 'LastSuccessTime'
            $dt = [datetime]::MinValue
            $styles = [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal'
            if (-not $s -or -not [datetime]::TryParse("$s", [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) {
                return @('unknown', 'no install timestamp recorded')
            }
            $days = [int]([datetime]::UtcNow - $dt).TotalDays
            $ev = "last successful install $days day(s) ago"
            if ($days -le 35) { return @('pass', $ev) }
            if ($days -le 90) { return @('warn', $ev) }
            @('fail', $ev)
        }
    })

    ,$c.ToArray()
}

function Invoke-WinHardenAudit {
    param([hashtable]$Reader, [string[]]$Area)
    $R = New-WinHardenReader
    if ($Reader) { foreach ($k in $Reader.Keys) { $R[$k] = $Reader[$k] } }
    $results = foreach ($c in (Get-WinHardenChecks)) {
        if ($Area -and $c.Area -notin $Area) { continue }
        $status = 'unknown'; $ev = 'check did not return a result'; $needs = $false
        try {
            $out = @(& $c.Run $R $c)
            if ($out.Count -ge 2 -and $out[0] -in 'pass', 'warn', 'fail', 'unknown') {
                $status = $out[0]; $ev = "$($out[1])"
                if ($out.Count -ge 3) { $needs = [bool]$out[2] }
            }
        } catch {
            $ev = "check failed: $($_.Exception.Message)"
        }
        [pscustomobject]@{
            Id = $c.Id; Area = $c.Area; Label = $c.Label; Title = $c.Title; Status = $status
            Evidence = $ev; Why = $c.Why; Fix = $c.Fix; NeedsAdmin = $needs
        }
    }
    $results = @($results)
    $counts = [ordered]@{ pass = 0; warn = 0; fail = 0; unknown = 0 }
    foreach ($res in $results) { $counts[$res.Status]++ }
    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('s')
        IsAdmin = [bool](Invoke-Reader $R 'IsAdmin')
        Counts = [pscustomobject]$counts
        Results = $results
    }
}

function Get-WinHardenAreas { $script:Areas }

function ConvertTo-WinHardenJson {
    param($Report)
    $Report | ConvertTo-Json -Depth 5
}

function ConvertTo-WinHardenHtml {
    param($Report)
    $e = { param($t) [Net.WebUtility]::HtmlEncode("$t") }
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>winharden report</title><style>')
    [void]$sb.AppendLine('body{font:14px Segoe UI,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;color:#1b2733}')
    [void]$sb.AppendLine('h2{border-bottom:1px solid #bbb;margin-top:1.6em}.c{border-left:6px solid #888;padding:.3em .8em;margin:.6em 0;background:#f6f8fa}')
    [void]$sb.AppendLine('.pass{border-color:#1a9c7b}.warn{border-color:#d99a00}.fail{border-color:#d63a3f}code{display:block;white-space:pre-wrap;background:#e9edf1;padding:.3em .5em;margin-top:.3em}</style></head><body>')
    $c = $Report.Counts
    [void]$sb.AppendLine("<h1>winharden</h1><p>$(& $e $Report.GeneratedAt) | admin: $($Report.IsAdmin) | $($c.fail) fail, $($c.warn) warn, $($c.unknown) unknown, $($c.pass) pass</p>")
    foreach ($a in $script:Areas) {
        $rows = @($Report.Results | Where-Object { $_.Area -eq $a })
        if (-not $rows) { continue }
        [void]$sb.AppendLine("<h2>$(& $e $a)</h2>")
        foreach ($r in $rows) {
            [void]$sb.AppendLine("<div class=`"c $($r.Status)`"><b>$(& $e $r.Title)</b> [$($r.Status)]<br>$(& $e $r.Evidence)")
            if ($r.Status -ne 'pass') {
                [void]$sb.AppendLine("<br><i>$(& $e $r.Why)</i><code>$(& $e $r.Fix)</code>")
            }
            [void]$sb.AppendLine('</div>')
        }
    }
    [void]$sb.AppendLine('</body></html>')
    $sb.ToString()
}

Export-ModuleMember -Function New-WinHardenReader, Invoke-WinHardenAudit, Get-WinHardenAreas, Get-WinHardenChecks, ConvertTo-WinHardenJson, ConvertTo-WinHardenHtml
