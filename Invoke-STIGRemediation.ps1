<#
.SYNOPSIS
    Audits, and optionally remediates, Windows 11 DISA STIG controls, then exports a CSV report.

.DESCRIPTION
    Checks 12 DISA Windows 11 STIG rules covering the controls in the companion
    windows11-stig-hardening-lab. For each rule the script:

      1. Reads the current setting.
      2. If non-compliant and remediation is allowed, applies the fix.
      3. Re-reads the setting and reports REMEDIATED only if the new value is compliant.

    Status values:
      COMPLIANT           Setting met the requirement before any change.
      REMEDIATED          Setting was changed and re-verified as compliant.
      REMEDIATION FAILED  A change was attempted but failed or did not verify.
      OPEN FINDING        Non-compliant and not changed (audit-only mode, or manual-only rule).
      MANUAL REVIEW       The script cannot decide compliance; an assessor must check.
      ERROR               The current setting could not be read.

    Rules that are never changed automatically, even without -AuditOnly:
      WN11-00-000030 (BitLocker encryption), WN11-00-000035 (application allowlisting),
      WN11-00-000055 (alternate operating systems). Changing these safely needs
      decisions (recovery keys, allowlist rules, boot entries) that a script should not make.

.PARAMETER AuditOnly
    Report compliance without changing any setting.

.PARAMETER ReportPath
    CSV output path. Defaults to STIG_Report_<timestamp>.csv in the current directory.

.PARAMETER AdminAccountName
    New name for the built-in Administrator account (SID ending -500). Default: LocalAdmin.

.PARAMETER GuestAccountName
    New name for the built-in Guest account (SID ending -501). Default: LocalGuest.

.EXAMPLE
    .\Invoke-STIGRemediation.ps1 -AuditOnly

.EXAMPLE
    .\Invoke-STIGRemediation.ps1 -ReportPath C:\Reports\stig.csv

.NOTES
    Author:    Derrick Lattimore Jr.
    Version:   2.0
    Framework: DISA Microsoft Windows 11 STIG; NIST SP 800-53 Rev 5 (via CCI mappings)
    Requires:  Windows PowerShell 5.1 or PowerShell 7 on Windows, run as Administrator.
    Exit code: 0 = all compliant or remediated; 1 = findings remain; 2 = at least one ERROR.
    Locale:    Audit policy and boot-entry checks parse English-language tool output.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [string]$ReportPath = (Join-Path -Path (Get-Location) -ChildPath ("STIG_Report_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [ValidateNotNullOrEmpty()][string]$AdminAccountName = 'LocalAdmin',
    [ValidateNotNullOrEmpty()][string]$GuestAccountName = 'LocalGuest'
)

Set-StrictMode -Version 2.0

$script:FvePath       = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$script:LsaPath       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:LogonAuditGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'   # Logon/Logoff > Logon

#region System access wrappers (each is mocked in the tests)

function Get-RegistryDword {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function Set-RegistryDword {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$Value)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
}

function Invoke-SeceditExport {
    # Returns the lines of a secedit security-policy export (locale independent keys).
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        $output = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed (exit $LASTEXITCODE): $output" }
        return Get-Content -Path $tmp -ErrorAction Stop
    }
    finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

function ConvertFrom-SeceditLockoutLine {
    param([AllowEmptyCollection()][string[]]$Lines)
    $line = $Lines | Where-Object { $_ -match '^\s*LockoutBadCount\s*=' } | Select-Object -First 1
    if (-not $line) { throw 'LockoutBadCount not found in secedit export.' }
    return [int](($line -split '=', 2)[1].Trim())
}

function Get-LockoutThreshold {
    return ConvertFrom-SeceditLockoutLine -Lines (Invoke-SeceditExport)
}

function Set-LockoutThreshold {
    param([Parameter(Mandatory)][int]$Value)
    $output = & net.exe accounts "/lockoutthreshold:$Value" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "net accounts failed (exit $LASTEXITCODE): $output" }
}

function Get-BuiltinAccount {
    param([Parameter(Mandatory)][ValidateSet('500', '501')][string]$Rid)
    $account = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match "-$Rid$" } | Select-Object -First 1
    if ($null -eq $account) { throw "Built-in account with RID $Rid not found." }
    return $account
}

function Rename-BuiltinAccount {
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$NewName)
    Rename-LocalUser -SID $Sid -NewName $NewName -ErrorAction Stop
}

function Disable-BuiltinAccount {
    param([Parameter(Mandatory)][string]$Sid)
    Disable-LocalUser -SID $Sid -ErrorAction Stop
}

function ConvertFrom-AuditpolCsv {
    param([AllowEmptyCollection()][string[]]$Lines)
    $row = $Lines | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv | Select-Object -First 1
    if ($null -eq $row -or -not ($row.PSObject.Properties.Name -contains 'Inclusion Setting')) {
        throw 'Unexpected auditpol output.'
    }
    return [string]$row.'Inclusion Setting'
}

function Get-AuditSubcategorySetting {
    param([Parameter(Mandatory)][string]$Guid)
    $output = & auditpol.exe /get "/subcategory:$Guid" /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /get failed (exit $LASTEXITCODE): $output" }
    return ConvertFrom-AuditpolCsv -Lines ([string[]]$output)
}

function Set-AuditSubcategorySuccessFailure {
    param([Parameter(Mandatory)][string]$Guid)
    $output = & auditpol.exe /set "/subcategory:$Guid" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed (exit $LASTEXITCODE): $output" }
}

function Get-OsLoaderEntryCount {
    $output = & bcdedit.exe /enum osloader 2>&1
    if ($LASTEXITCODE -ne 0) { throw "bcdedit failed (exit $LASTEXITCODE): $output" }
    return @($output | Where-Object { $_ -match '^identifier\s' }).Count
}

function Get-UnencryptedFixedVolumes {
    $volumes = Get-BitLockerVolume -ErrorAction Stop |
        Where-Object { [string]$_.VolumeType -in @('OperatingSystem', 'FixedData') }
    return @($volumes | Where-Object { [string]$_.VolumeStatus -ne 'FullyEncrypted' } | ForEach-Object { [string]$_.MountPoint })
}

function Get-AppLockerRuleCount {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $count = 0
    foreach ($collection in $policy.RuleCollections) { $count += @($collection).Count }
    return $count
}

#endregion

#region Control definitions

function New-CheckResult {
    param($Value, [bool]$Compliant, [bool]$ManualReview = $false)
    return [pscustomobject]@{ Value = $Value; Compliant = $Compliant; ManualReview = $ManualReview }
}

function Get-StigControlDefinitions {
    param([string]$AdminName = 'LocalAdmin', [string]$GuestName = 'LocalGuest')

    # Control scriptblocks read these script-scoped values when they run.
    $script:TargetAdminName = $AdminName
    $script:TargetGuestName = $GuestName

    $controls = @(
        @{ StigId = 'WN11-00-000030'; VulnId = 'V-253259'; Cat = 'I'; Title = 'BitLocker encrypts all fixed drives'
           Test = { $unencrypted = @(Get-UnencryptedFixedVolumes)
                    if ($unencrypted.Count -eq 0) { New-CheckResult 'All fixed volumes FullyEncrypted' $true }
                    else { New-CheckResult ('Not fully encrypted: ' + ($unencrypted -join ', ')) $false } }
           Remediate = $null
           ManualNote = 'Enable BitLocker manually and escrow the recovery key.' }

        @{ StigId = 'WN11-00-000031'; VulnId = 'V-253260'; Cat = 'I'; Title = 'BitLocker pre-boot PIN required'
           Test = { $adv = Get-RegistryDword $script:FvePath 'UseAdvancedStartup'
                    $pin = Get-RegistryDword $script:FvePath 'UseTPMPIN'
                    $keyPin = Get-RegistryDword $script:FvePath 'UseTPMKeyPIN'
                    New-CheckResult ("UseAdvancedStartup=$adv; UseTPMPIN=$pin; UseTPMKeyPIN=$keyPin") (($adv -eq 1) -and (($pin -eq 1) -or ($keyPin -eq 1))) }
           Remediate = { Set-RegistryDword $script:FvePath 'UseAdvancedStartup' 1
                         Set-RegistryDword $script:FvePath 'UseTPMPIN' 1
                         Set-RegistryDword $script:FvePath 'UseTPMKeyPIN' 1 } }

        @{ StigId = 'WN11-00-000032'; VulnId = 'V-253261'; Cat = 'II'; Title = 'BitLocker minimum PIN length of 6'
           Test = { $min = Get-RegistryDword $script:FvePath 'MinimumPIN'
                    New-CheckResult ("MinimumPIN=$min") (($null -ne $min) -and ($min -ge 6)) }
           Remediate = { Set-RegistryDword $script:FvePath 'MinimumPIN' 6 } }

        @{ StigId = 'WN11-00-000035'; VulnId = 'V-253262'; Cat = 'II'; Title = 'Application allowlisting (deny-all, permit-by-exception)'
           Test = { $rules = Get-AppLockerRuleCount
                    if ($rules -eq 0) { New-CheckResult 'No effective AppLocker rules' $false }
                    else { New-CheckResult ("$rules effective AppLocker rules") $false $true } }
           Remediate = $null
           ManualNote = 'Deploy AppLocker or App Control for Business allowlisting; confirm deny-by-default including packaged apps.' }

        @{ StigId = 'WN11-00-000055'; VulnId = 'V-253266'; Cat = 'II'; Title = 'No alternate operating systems on the boot menu'
           Test = { $count = Get-OsLoaderEntryCount
                    New-CheckResult ("$count OS loader entries") ($count -le 1) }
           Remediate = $null
           ManualNote = 'Remove extra boot entries manually; automatic removal can make the system unbootable.' }

        @{ StigId = 'WN11-AC-000010'; VulnId = 'V-253298'; Cat = 'II'; Title = 'Account lockout threshold of 3 or less (not 0)'
           Test = { $threshold = Get-LockoutThreshold
                    New-CheckResult ("LockoutBadCount=$threshold") (($threshold -ge 1) -and ($threshold -le 3)) }
           Remediate = { Set-LockoutThreshold -Value 3 } }

        @{ StigId = 'WN11-SO-000145'; VulnId = 'V-253453'; Cat = 'I'; Title = 'Anonymous enumeration of SAM accounts not allowed'
           Test = { $value = Get-RegistryDword $script:LsaPath 'RestrictAnonymousSAM'
                    New-CheckResult ("RestrictAnonymousSAM=$value") ($value -eq 1) }
           Remediate = { Set-RegistryDword $script:LsaPath 'RestrictAnonymousSAM' 1 } }

        @{ StigId = 'WN11-SO-000020'; VulnId = 'V-253435'; Cat = 'II'; Title = 'Built-in Administrator account renamed'
           Test = { $account = Get-BuiltinAccount -Rid '500'
                    New-CheckResult $account.Name ($account.Name -ne 'Administrator') }
           Remediate = { $account = Get-BuiltinAccount -Rid '500'
                         Rename-BuiltinAccount -Sid $account.SID.Value -NewName $script:TargetAdminName } }

        @{ StigId = 'WN11-SO-000010'; VulnId = 'V-253433'; Cat = 'II'; Title = 'Built-in Guest account disabled'
           Test = { $account = Get-BuiltinAccount -Rid '501'
                    New-CheckResult ("Enabled=$($account.Enabled)") (-not $account.Enabled) }
           Remediate = { $account = Get-BuiltinAccount -Rid '501'
                         Disable-BuiltinAccount -Sid $account.SID.Value } }

        @{ StigId = 'WN11-SO-000025'; VulnId = 'V-253436'; Cat = 'II'; Title = 'Built-in Guest account renamed'
           Test = { $account = Get-BuiltinAccount -Rid '501'
                    New-CheckResult $account.Name ($account.Name -ne 'Guest') }
           Remediate = { $account = Get-BuiltinAccount -Rid '501'
                         Rename-BuiltinAccount -Sid $account.SID.Value -NewName $script:TargetGuestName } }

        @{ StigId = 'WN11-AU-000070'; VulnId = 'V-253316'; Cat = 'II'; Title = 'Audit Logon failures'
           Test = { $setting = Get-AuditSubcategorySetting -Guid $script:LogonAuditGuid
                    New-CheckResult $setting ($setting -match 'Failure') }
           Remediate = { Set-AuditSubcategorySuccessFailure -Guid $script:LogonAuditGuid } }

        @{ StigId = 'WN11-AU-000075'; VulnId = 'V-253317'; Cat = 'II'; Title = 'Audit Logon successes'
           Test = { $setting = Get-AuditSubcategorySetting -Guid $script:LogonAuditGuid
                    New-CheckResult $setting ($setting -match 'Success') }
           Remediate = { Set-AuditSubcategorySuccessFailure -Guid $script:LogonAuditGuid } }
    )

    foreach ($control in $controls) {
        if (-not $control.ContainsKey('ManualNote')) { $control.ManualNote = '' }
    }
    return $controls
}

#endregion

#region Engine

function Invoke-StigControl {
    param([Parameter(Mandatory)][hashtable]$Control, [switch]$AuditOnly)

    $row = [ordered]@{
        StigId = $Control.StigId; VulnId = $Control.VulnId; Severity = "CAT $($Control.Cat)"; Control = $Control.Title
        Before = ''; After = ''; Status = ''; Notes = ''; Timestamp = (Get-Date -Format 's')
    }

    try {
        $before = & $Control.Test
    }
    catch {
        $row.Status = 'ERROR'; $row.Notes = "Could not read setting: $($_.Exception.Message)"
        return [pscustomobject]$row
    }
    $row.Before = [string]$before.Value

    if ($before.Compliant) {
        $row.After = $row.Before; $row.Status = 'COMPLIANT'
        return [pscustomobject]$row
    }
    if ($before.ManualReview) {
        $row.After = $row.Before; $row.Status = 'MANUAL REVIEW'; $row.Notes = $Control.ManualNote
        return [pscustomobject]$row
    }
    if ($AuditOnly -or $null -eq $Control.Remediate) {
        $row.After = $row.Before; $row.Status = 'OPEN FINDING'
        if ($null -eq $Control.Remediate) { $row.Notes = $Control.ManualNote } else { $row.Notes = 'Audit-only mode: no change made.' }
        return [pscustomobject]$row
    }

    try {
        & $Control.Remediate
    }
    catch {
        $row.Status = 'REMEDIATION FAILED'; $row.Notes = "Remediation error: $($_.Exception.Message)"
        try { $row.After = [string](& $Control.Test).Value } catch { $row.After = 'Unreadable' }
        return [pscustomobject]$row
    }

    try {
        $after = & $Control.Test
    }
    catch {
        $row.Status = 'REMEDIATION FAILED'; $row.After = 'Unreadable'
        $row.Notes = "Change applied but could not be verified: $($_.Exception.Message)"
        return [pscustomobject]$row
    }
    $row.After = [string]$after.Value
    if ($after.Compliant) { $row.Status = 'REMEDIATED' }
    else { $row.Status = 'REMEDIATION FAILED'; $row.Notes = 'Change applied but the setting did not verify as compliant.' }
    return [pscustomobject]$row
}

function Invoke-StigAssessment {
    param([hashtable[]]$Controls, [switch]$AuditOnly)
    foreach ($control in $Controls) { Invoke-StigControl -Control $control -AuditOnly:$AuditOnly }
}

function Get-StigExitCode {
    param([object[]]$Results)
    if (@($Results | Where-Object { $_.Status -eq 'ERROR' }).Count -gt 0) { return 2 }
    if (@($Results | Where-Object { $_.Status -notin @('COMPLIANT', 'REMEDIATED') }).Count -gt 0) { return 1 }
    return 0
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

# Run only when executed directly, not when dot-sourced by the tests.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-IsAdministrator)) {
        Write-Error 'Run this script from an elevated (Administrator) PowerShell session.'
        exit 2
    }

    $mode = if ($AuditOnly) { 'AUDIT ONLY (no changes)' } else { 'AUDIT AND REMEDIATE' }
    Write-Host "DISA Windows 11 STIG check - mode: $mode" -ForegroundColor Cyan

    $results = @(Invoke-StigAssessment -Controls (Get-StigControlDefinitions -AdminName $AdminAccountName -GuestName $GuestAccountName) -AuditOnly:$AuditOnly)

    try {
        $results | Export-Csv -Path $ReportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Report saved to: $ReportPath" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Could not write report to ${ReportPath}: $($_.Exception.Message)"
    }

    $results | Format-Table StigId, Severity, Status, Before, After -AutoSize | Out-Host
    $results | Group-Object Status | Sort-Object Name | ForEach-Object { Write-Host ("{0,-20} {1}" -f $_.Name, $_.Count) }

    exit (Get-StigExitCode -Results $results)
}
