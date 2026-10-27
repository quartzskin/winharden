function New-FakeReader {
    param([hashtable]$Reg = @{}, [hashtable]$Override = @{})

    $recent = (Get-Date).ToUniversalTime().AddDays(-5).ToString('yyyy-MM-dd HH:mm:ss')
    $table = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections' = 1
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication' = 1
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA' = 1
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorAdmin' = 5
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|PromptOnSecureDesktop' = 1
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State|UEFISecureBootEnabled' = 1
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = 0
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature' = 1
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun' = 255
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging' = 1
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install|LastSuccessTime' = $recent
    }
    foreach ($k in $Reg.Keys) {
        if ($null -eq $Reg[$k]) { $table.Remove($k) } else { $table[$k] = $Reg[$k] }
    }

    $acct = @(
        'Force user logoff how long after time expires?:       Never'
        'Minimum password age (days):                          0'
        'Maximum password age (days):                          42'
        'Minimum password length:                              14'
        'Length of password history maintained:                24'
        'Lockout threshold:                                    5'
        'Lockout duration (minutes):                           30'
        'Lockout observation window (minutes):                 30'
        'Computer role:                                        WORKSTATION'
    )

    $r = @{
        IsAdmin = { $true }
        Reg = { param($Path, $Name) $table["$Path|$Name"] }.GetNewClosure()
        MpStatus = { [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 1; IsTamperProtected = $true } }
        MpPref = { [pscustomobject]@{ ExclusionPath = $null; ExclusionExtension = $null; ExclusionProcess = $null } }
        Firewall = { [pscustomobject]@{ Items = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInbound = 'Block' }
            [pscustomobject]@{ Name = 'Private'; Enabled = 'True'; DefaultInbound = 'Block' }
            [pscustomobject]@{ Name = 'Public'; Enabled = 'True'; DefaultInbound = 'Block' }) } }
        BitLocker = { 1 }
        Tpm = { [pscustomobject]@{ Items = @('Trusted Platform Module 2.0') } }
        Smb1Config = { $false }
        NetAccounts = { [pscustomobject]@{ Items = $acct } }.GetNewClosure()
        GuestEnabled = { $false }
        Listeners = { [pscustomobject]@{ Items = @([pscustomobject]@{ Port = 135; Process = 'svchost' }) } }
        ExecPolicy = { @{ MachinePolicy = 'Undefined'; UserPolicy = 'Undefined'; Process = 'Undefined'; CurrentUser = 'Undefined'; LocalMachine = 'RemoteSigned' } }
        ServiceStart = { 'Manual' }
    }
    foreach ($k in $Override.Keys) { $r[$k] = $Override[$k] }
    $r
}

# Invented machine in poor shape, used for the README screenshot
function New-MessyFakeReader {
    $old = (Get-Date).ToUniversalTime().AddDays(-140).ToString('yyyy-MM-dd HH:mm:ss')
    New-FakeReader -Reg @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections' = 0
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication' = 0
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature' = $null
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1' = 1
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|PromptOnSecureDesktop' = 0
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun' = $null
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging' = $null
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install|LastSuccessTime' = $old
    } -Override @{
        MpStatus = { [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 9; IsTamperProtected = $false } }
        MpPref = { [pscustomobject]@{ ExclusionPath = @('C:\Tools', 'D:\'); ExclusionExtension = $null; ExclusionProcess = $null } }
        Firewall = { [pscustomobject]@{ Items = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInbound = 'Block' }
            [pscustomobject]@{ Name = 'Private'; Enabled = 'True'; DefaultInbound = 'Allow' }
            [pscustomobject]@{ Name = 'Public'; Enabled = 'False'; DefaultInbound = 'Block' }) } }
        BitLocker = { 0 }
        Smb1Config = { $null }
        GuestEnabled = { $true }
        NetAccounts = { [pscustomobject]@{ Items = @('Minimum password length:                              6', 'Lockout threshold:                                    Never') } }
        Listeners = { [pscustomobject]@{ Items = @(
            [pscustomobject]@{ Port = 23; Process = 'telnetd' }
            [pscustomobject]@{ Port = 3389; Process = 'svchost' }
            [pscustomobject]@{ Port = 5985; Process = 'System' }) } }
        ExecPolicy = { @{ MachinePolicy = 'Undefined'; UserPolicy = 'Undefined'; Process = 'Undefined'; CurrentUser = 'Undefined'; LocalMachine = 'Unrestricted' } }
    }
}
