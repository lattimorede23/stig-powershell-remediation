# STIG PowerShell Remediation

Automated PowerShell script that audits and remediates Windows 11 endpoints against the **DISA STIG V2R7** baseline. It checks each control, remediates it if non-compliant, and exports a timestamped before/after compliance report as CSV.

## What it does

For each control, the script:

1. Reads the current ("before") state of the relevant registry key, policy, or account setting.
2. Compares it against the STIG-required value.
3. Remediates the setting if it is out of compliance.
4. Logs the before/after state and status (`COMPLIANT`, `REMEDIATED`, or `OPEN FINDING`) to a report object.

On completion, the full report is exported to `C:\STIG_Remediation_Report_<timestamp>.csv` and printed to the console.

## Controls covered

| STIG ID | Control |
|---|---|
| WN11-00-000031 | BitLocker pre-boot PIN required |
| WN11-00-000032 | BitLocker minimum PIN length (6+) |
| WN11-00-000036 | Account lockout threshold (≤ 3 attempts) |
| WN11-SO-000020 | Restrict anonymous access to SAM |
| WN11-00-000060 | Built-in Administrator account renamed |
| WN11-00-000065 | Guest account disabled |
| WN11-00-000085 | Guest account renamed |
| WN11-AU-000500 | Audit logon events (success and failure) |
| WN11-00-000055 | No alternate operating systems on boot menu |

That's 9 of the 10 controls in the Windows 11 STIG lab scope. WN11-00-000055 is audited but flagged as an **OPEN FINDING** requiring manual remediation if multiple boot entries are detected, since removing boot entries automatically carries risk of breaking the system.

## Excluded control

**WN11-00-000030** (BitLocker full-disk encryption) is intentionally excluded. BitLocker cannot be enforced via script in a VM lab environment without physical TPM hardware, so it is documented as **Not a Finding** in the accompanying STIG audit report. The reason is also noted directly in the script comments above the BitLocker-related checks.

## How to run

1. Copy `Invoke-STIGRemediation.ps1` to the target Windows 11 machine.
2. Open PowerShell **as Administrator**.
3. Run:

   ```powershell
   .\Invoke-STIGRemediation.ps1
   ```

4. Review the console output and the generated CSV report at `C:\STIG_Remediation_Report_<timestamp>.csv`.

## Framework

- DISA STIG V2R7 (Windows 11)
- NIST SP 800-53 Rev 5

## Author

Derrick Lattimore Jr.
