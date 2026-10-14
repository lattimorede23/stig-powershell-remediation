# STIG PowerShell Remediation

[![tests](https://github.com/lattimorede23/stig-powershell-remediation/actions/workflows/test.yml/badge.svg)](https://github.com/lattimorede23/stig-powershell-remediation/actions/workflows/test.yml)

A PowerShell script that audits Windows 11 against 12 DISA STIG rules and can optionally fix them. It re-checks each setting after changing it and writes a CSV compliance report.

It automates the controls assessed by hand in [windows11-stig-hardening-lab](https://github.com/lattimorede23/windows11-stig-hardening-lab).

## What it does

For each rule the script runs three steps:

1. **Read** the current setting.
2. **Fix**, only if the setting is non-compliant, remediation is allowed, and the rule is safe to automate.
3. **Re-read** the setting. It reports `REMEDIATED` only if the new value actually passes.

| Status | Meaning |
| :-- | :-- |
| `COMPLIANT` | Met the requirement before any change |
| `REMEDIATED` | Changed, then re-verified as compliant |
| `REMEDIATION FAILED` | A change was attempted but errored or did not verify |
| `OPEN FINDING` | Non-compliant and not changed (audit-only mode, or a manual-only rule) |
| `MANUAL REVIEW` | The script can't decide; an assessor must check |
| `ERROR` | The current setting couldn't be read |

**Exit codes:**

| Code | Meaning |
| :-- | :-- |
| 0 | Everything compliant or remediated |
| 1 | Findings remain |
| 2 | At least one rule could not be read |

## Rules covered

| STIG ID | Vuln ID | CAT | Rule | Automated fix |
| :-- | :-- | :-- | :-- | :-- |
| WN11-00-000030 | V-253259 | I | BitLocker encrypts all fixed drives | No: audit only |
| WN11-00-000031 | V-253260 | I | BitLocker pre-boot PIN required | Yes |
| WN11-00-000032 | V-253261 | II | BitLocker minimum PIN length of 6 | Yes |
| WN11-00-000035 | V-253262 | II | Application allowlisting | No: audit only |
| WN11-00-000055 | V-253266 | II | No alternate operating systems | No: audit only |
| WN11-AC-000010 | V-253298 | II | Lockout threshold 3 or less, and not 0 | Yes |
| WN11-SO-000145 | V-253453 | I | No anonymous SAM enumeration | Yes |
| WN11-SO-000020 | V-253435 | II | Built-in Administrator renamed | Yes |
| WN11-SO-000010 | V-253433 | II | Built-in Guest disabled | Yes |
| WN11-SO-000025 | V-253436 | II | Built-in Guest renamed | Yes |
| WN11-AU-000070 | V-253316 | II | Audit Logon failures | Yes |
| WN11-AU-000075 | V-253317 | II | Audit Logon successes | Yes |

Three rules are deliberately never changed automatically:

- **BitLocker encryption** needs recovery-key escrow.
- **Allowlisting** needs an approved software list.
- **Removing boot entries** can make a system unbootable.

For allowlisting, the script reports `OPEN FINDING` when no AppLocker rules exist. When rules do exist, it reports `MANUAL REVIEW`, because only an assessor can confirm deny-by-default coverage, including packaged apps. An App Control for Business (WDAC) policy also satisfies the STIG, but the script doesn't detect one.

## Usage

Run from an elevated PowerShell session (Windows PowerShell 5.1 or PowerShell 7):

```powershell
# Report only. Makes no changes.
.\Invoke-STIGRemediation.ps1 -AuditOnly

# Audit and remediate, with a chosen report path and account names.
.\Invoke-STIGRemediation.ps1 -ReportPath C:\Reports\stig.csv -AdminAccountName LocalAdmin -GuestAccountName LocalGuest
```

The report goes to `STIG_Report_<timestamp>.csv` in the current directory unless you pass `-ReportPath`. Columns:

| Column | Contents |
| :-- | :-- |
| `StigId`, `VulnId` | STIG and vulnerability identifiers |
| `Severity` | CAT I, II, or III |
| `Control` | Rule description |
| `Before`, `After` | Setting value before and after any change |
| `Status` | One of the statuses above |
| `Notes` | Errors, or why a rule wasn't changed |
| `Timestamp` | When the rule was checked |

**Run `-AuditOnly` first** and review the report before letting the script change anything.

## How settings are read and written

| Setting | Read | Write |
| :-- | :-- | :-- |
| BitLocker PIN policy, SAM restriction | Registry | Registry; missing keys are created |
| Lockout threshold | `secedit /export` (`LockoutBadCount`, locale independent) | `net accounts /lockoutthreshold:3` |
| Built-in accounts | `Get-LocalUser`, found by SID (-500, -501) | Renamed or disabled by SID |
| Audit Logon | `auditpol /get /r`, using the subcategory GUID | `auditpol /set` |
| Boot entries | `bcdedit /enum osloader` | Never changed |
| BitLocker volumes | `Get-BitLockerVolume` | Never changed |
| AppLocker | `Get-AppLockerPolicy -Effective` | Never changed |

## Testing

| Test layer | Where it runs | What it proves |
| :-- | :-- | :-- |
| 26 Pester unit tests (`tests/`) | Any OS; every Windows call is mocked | Engine logic, status decisions, and parsing |
| CI on `windows-latest`, Pester job | PowerShell 7 and Windows PowerShell 5.1 | The unit tests pass on real Windows |
| CI on `windows-latest`, integration job | GitHub's disposable runner VM | The script runs end to end against a live OS (details below) |

The unit tests cover:

- Lockout threshold of 0 is treated as a finding.
- Verification failure reports `REMEDIATION FAILED`.
- Thrown errors are contained, and the script continues to the next rule.
- Audit-only mode never calls any write function.
- RID matching on built-in accounts.
- Registry key creation.
- Parsing of `secedit` and `auditpol` output.
- Exit codes.

The integration job runs three passes on the runner VM: an audit-only pass, a remediation pass, and a final audit that must show all 9 automatable rules as `COMPLIANT`. Reports are uploaded as workflow artifacts.

Run the unit tests locally:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Invoke-Pester -Path ./tests -Output Detailed
```

## Limitations

- **Windows Server only.** CI runs on Windows Server (GitHub's `windows-latest`), not Windows 11. The script has not been re-run on the original lab VM since this rewrite.
- **English-language parsing.** Audit policy and boot-entry checks parse English-language `auditpol` and `bcdedit` output.
- **Policy registry values vs. GPO.** BitLocker and SAM settings are written as policy registry values. In a managed environment, use Group Policy so a policy refresh doesn't overwrite them.
- **Partial lockout coverage.** The script covers 12 rules, not the full 262-rule benchmark. Lockout duration and reset counter (WN11-AC-000005/000015) are not yet covered.

## Changes in v2.0

v1.0 (commit `393eddb`) had these defects, fixed in v2.0:

| v1.0 defect | v2.0 fix |
| :-- | :-- |
| Wrong STIG IDs for the lockout, SAM, admin rename, guest, and audit rules | IDs and Vuln IDs taken from the SCAP benchmark content |
| Lockout threshold 0 crashed the parse (`net accounts` prints "Never") and the rule dropped from the report | Threshold read from `secedit`; 0 is a finding |
| `REMEDIATED` reported without re-checking; writes to a missing registry key failed silently and were still reported as fixed | Every fix is re-verified; missing keys are created; failures are reported |
| No audit-only mode | `-AuditOnly` |
| No error handling | Each rule fails independently with `ERROR` or `REMEDIATION FAILED` |
| Report written to `C:\` root | Current directory or `-ReportPath` |
| BitLocker encryption and allowlisting not checked | Both audited, never auto-changed |
| Audit Logon "before" value hardcoded | Read from `auditpol` |

**Author:** Derrick Lattimore Jr. · Frameworks: DISA Windows 11 STIG, NIST SP 800-53 Rev 5
