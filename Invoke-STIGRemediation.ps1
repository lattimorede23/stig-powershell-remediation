<#
.SYNOPSIS
    Automated DISA STIG V2R7 Audit and Remediation Script for Windows 11
.DESCRIPTION
    Audits 9 of 10 controls from the Windows 11 STIG lab.
    WN11-00-000030 excluded: BitLocker cannot be enforced in a VM without physical TPM.
    Exports a timestamped CSV compliance report on completion.
.AUTHOR
    Derrick Lattimore Jr.
.NOTES
    Must be run as Administrator.
    Framework: DISA STIG V2R7 | NIST SP 800-53 Rev 5
#>

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

# WN11-00-000030 EXCLUDED: BitLocker full-disk encryption cannot be
# enforced via script in a VM environment without physical TPM hardware.
# Documented as Not a Finding in accompanying STIG audit report.

$fve = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -EA SilentlyContinue
$before = $fve.UseAdvancedStartup
if ($before -ne 1) {
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1 -Type DWord
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMKeyPIN" -Value 1 -Type DWord
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000031";Control="BitLocker Pre-Boot PIN";Before=$before;After="1 (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000031";Control="BitLocker Pre-Boot PIN";Before=$before;After=$before;Status="COMPLIANT";Timestamp=$timestamp}) }

$fve2 = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -EA SilentlyContinue
$minpin = $fve2.MinimumPIN
if ($minpin -lt 6) {
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN" -Value 6 -Type DWord
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000032";Control="BitLocker Min PIN";Before=$minpin;After="6 (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000032";Control="BitLocker Min PIN";Before=$minpin;After=$minpin;Status="COMPLIANT";Timestamp=$timestamp}) }

$threshold = (net accounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
if ([int]$threshold -gt 3) {
    net accounts /lockoutthreshold:3 | Out-Null
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000036";Control="Account Lockout Threshold";Before=$threshold;After="3 (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000036";Control="Account Lockout Threshold";Before=$threshold;After=$threshold;Status="COMPLIANT";Timestamp=$timestamp}) }

$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$sam = $lsa.restrictanonymoussam
if ($sam -ne 1) {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value 1 -Type DWord
    $report.Add([PSCustomObject]@{STIG_ID="WN11-SO-000020";Control="Restrict Anonymous SAM";Before=$sam;After="1 (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-SO-000020";Control="Restrict Anonymous SAM";Before=$sam;After=$sam;Status="COMPLIANT";Timestamp=$timestamp}) }

$admin = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
$adminName = $admin.Name
if ($adminName -eq "Administrator") {
    Rename-LocalUser -Name "Administrator" -NewName "LocalAdmin"
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000060";Control="Admin Account Renamed";Before=$adminName;After="LocalAdmin (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000060";Control="Admin Account Renamed";Before=$adminName;After=$adminName;Status="COMPLIANT";Timestamp=$timestamp}) }

$guest = Get-LocalUser | Where-Object {$_.SID -like "*-501"}
$guestEnabled = $guest.Enabled
if ($guestEnabled -eq $true) {
    Disable-LocalUser -SID $guest.SID
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000065";Control="Guest Account Disabled";Before="Enabled";After="Disabled (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000065";Control="Guest Account Disabled";Before="Already Disabled";After="Already Disabled";Status="COMPLIANT";Timestamp=$timestamp}) }

$guestName = $guest.Name
if ($guestName -eq "Guest") {
    Rename-LocalUser -Name "Guest" -NewName "LocalGuest"
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000085";Control="Guest Account Renamed";Before=$guestName;After="LocalGuest (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000085";Control="Guest Account Renamed";Before=$guestName;After=$guestName;Status="COMPLIANT";Timestamp=$timestamp}) }

$auditCheck = auditpol /get /subcategory:"Logon" 2>$null
if ($auditCheck -notmatch "Success and Failure") {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    $report.Add([PSCustomObject]@{STIG_ID="WN11-AU-000500";Control="Audit Logon Events";Before="Not Configured";After="Success and Failure (Remediated)";Status="REMEDIATED";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-AU-000500";Control="Audit Logon Events";Before="Success and Failure";After="Success and Failure";Status="COMPLIANT";Timestamp=$timestamp}) }

$bootEntries = bcdedit /enum all 2>$null
$osCount = ($bootEntries | Select-String "Windows Boot Loader").Count
if ($osCount -gt 1) {
    $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000055";Control="No Alternate OS";Before="$osCount boot entries";After="Manual remediation required";Status="OPEN FINDING";Timestamp=$timestamp})
} else { $report.Add([PSCustomObject]@{STIG_ID="WN11-00-000055";Control="No Alternate OS";Before="$osCount boot entry";After="$osCount boot entry";Status="COMPLIANT";Timestamp=$timestamp}) }

$csvPath = "C:\STIG_Remediation_Report_$timestamp.csv"
$report | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`n=== REMEDIATION COMPLETE ===" -ForegroundColor Green
Write-Host "Report saved to: $csvPath" -ForegroundColor Yellow
$report | Format-Table -AutoSize

