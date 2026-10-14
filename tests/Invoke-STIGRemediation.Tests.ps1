# Pester tests for Invoke-STIGRemediation.ps1.
# Every Windows-specific call is wrapped in a function the tests mock, so these run on
# any OS and never touch a real system. Written to run on Pester 4.10+ and Pester 5.

Describe 'Invoke-STIGRemediation' {

    BeforeAll {
        $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-STIGRemediation.ps1'
        . $scriptPath

        # LocalAccounts cmdlets exist only on Windows; stub them so they can be mocked elsewhere.
        if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
            function Get-LocalUser { [CmdletBinding()] param() throw 'Get-LocalUser stub: not available on this OS' }
        }

        function Get-Control([string]$Id) {
            Get-StigControlDefinitions -AdminName 'LocalAdmin' -GuestName 'LocalGuest' | Where-Object { $_.StigId -eq $Id }
        }
    }

    Context 'STIG mappings' {

        It 'covers exactly the expected rules with correct Vuln IDs' {
            $map = @{}
            Get-StigControlDefinitions | ForEach-Object { $map[$_.StigId] = $_.VulnId }
            $expected = @{
                'WN11-00-000030' = 'V-253259'; 'WN11-00-000031' = 'V-253260'; 'WN11-00-000032' = 'V-253261'
                'WN11-00-000035' = 'V-253262'; 'WN11-00-000055' = 'V-253266'; 'WN11-AC-000010' = 'V-253298'
                'WN11-SO-000145' = 'V-253453'; 'WN11-SO-000020' = 'V-253435'; 'WN11-SO-000010' = 'V-253433'
                'WN11-SO-000025' = 'V-253436'; 'WN11-AU-000070' = 'V-253316'; 'WN11-AU-000075' = 'V-253317'
            }
            $map.Count | Should -Be $expected.Count
            foreach ($key in $expected.Keys) { $map[$key] | Should -Be $expected[$key] }
        }

        It 'does not use any of the incorrect v1.0 IDs' {
            $ids = (Get-StigControlDefinitions).StigId
            foreach ($bad in 'WN11-00-000036', 'WN11-00-000060', 'WN11-00-000065', 'WN11-00-000085', 'WN11-AU-000500') {
                $ids | Should -Not -Contain $bad
            }
        }

        It 'never auto-remediates BitLocker, allowlisting, or boot entries' {
            foreach ($id in 'WN11-00-000030', 'WN11-00-000035', 'WN11-00-000055') {
                (Get-Control $id).Remediate | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Account lockout threshold (WN11-AC-000010)' {

        It 'parses LockoutBadCount from a secedit export' {
            ConvertFrom-SeceditLockoutLine -Lines @('[System Access]', 'MinimumPasswordAge = 0', 'LockoutBadCount = 10') | Should -Be 10
        }

        It 'parses a threshold of 0 (lockout disabled)' {
            ConvertFrom-SeceditLockoutLine -Lines @('[System Access]', 'LockoutBadCount = 0') | Should -Be 0
        }

        It 'throws when LockoutBadCount is missing instead of guessing' {
            { ConvertFrom-SeceditLockoutLine -Lines @('[System Access]') } | Should -Throw
        }

        It 'treats a threshold of 0 as a finding (v1.0 bug)' {
            Mock Get-LockoutThreshold { 0 }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-AC-000010') -AuditOnly
            $result.Status | Should -Be 'OPEN FINDING'
            $result.Before | Should -Be 'LockoutBadCount=0'
        }

        It 'treats a threshold of 3 as compliant' {
            Mock Get-LockoutThreshold { 3 }
            (Invoke-StigControl -Control (Get-Control 'WN11-AC-000010')).Status | Should -Be 'COMPLIANT'
        }

        It 'reports REMEDIATED only after the new value verifies' {
            $script:threshold = 10
            Mock Get-LockoutThreshold { $script:threshold }
            Mock Set-LockoutThreshold { $script:threshold = 3 }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-AC-000010')
            $result.Status | Should -Be 'REMEDIATED'
            $result.Before | Should -Be 'LockoutBadCount=10'
            $result.After | Should -Be 'LockoutBadCount=3'
            Assert-MockCalled Set-LockoutThreshold -Times 1 -Exactly -Scope It
        }
    }

    Context 'Verification after remediation' {

        It 'reports REMEDIATION FAILED when the change does not take effect (v1.0 false positive)' {
            Mock Get-RegistryDword { $null }
            Mock Set-RegistryDword { }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-00-000032')
            $result.Status | Should -Be 'REMEDIATION FAILED'
            $result.Notes | Should -Match 'did not verify'
        }

        It 'reports REMEDIATION FAILED and continues when the change throws' {
            Mock Get-RegistryDword { $null }
            Mock Set-RegistryDword { throw 'Cannot find path' }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-00-000031')
            $result.Status | Should -Be 'REMEDIATION FAILED'
            $result.Notes | Should -Match 'Cannot find path'
        }

        It 'reports ERROR when the current setting cannot be read' {
            Mock Get-BuiltinAccount { throw 'Access denied' }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-SO-000020')
            $result.Status | Should -Be 'ERROR'
            $result.Notes | Should -Match 'Access denied'
        }

        It 'remediates BitLocker PIN policy when values are missing' {
            $script:reg = @{}
            Mock Get-RegistryDword { $script:reg[$Name] }
            Mock Set-RegistryDword { $script:reg[$Name] = $Value }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-00-000031')
            $result.Status | Should -Be 'REMEDIATED'
            Assert-MockCalled Set-RegistryDword -Times 3 -Exactly -Scope It
        }

        It 'accepts UseTPMKeyPIN alone as compliant for the pre-boot PIN rule' {
            Mock Get-RegistryDword { switch ($Name) { 'UseAdvancedStartup' { 1 } 'UseTPMKeyPIN' { 1 } default { 0 } } }
            (Invoke-StigControl -Control (Get-Control 'WN11-00-000031')).Status | Should -Be 'COMPLIANT'
        }
    }

    Context 'Audit-only mode' {

        It 'makes no changes and reports OPEN FINDING for every non-compliant rule' {
            Mock Get-RegistryDword { 0 }
            Mock Get-LockoutThreshold { 10 }
            Mock Get-BuiltinAccount {
                if ($Rid -eq '500') { [pscustomobject]@{ Name = 'Administrator'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' } } }
                else { [pscustomobject]@{ Name = 'Guest'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-501' } } }
            }
            Mock Get-AuditSubcategorySetting { 'No Auditing' }
            Mock Get-OsLoaderEntryCount { 2 }
            Mock Get-UnencryptedFixedVolumes { @('C:') }
            Mock Get-AppLockerRuleCount { 0 }
            Mock Set-RegistryDword { }
            Mock Set-LockoutThreshold { }
            Mock Rename-BuiltinAccount { }
            Mock Disable-BuiltinAccount { }
            Mock Set-AuditSubcategorySuccessFailure { }

            $results = @(Invoke-StigAssessment -Controls (Get-StigControlDefinitions) -AuditOnly)

            $results.Count | Should -Be 12
            @($results | Where-Object { $_.Status -ne 'OPEN FINDING' }).Count | Should -Be 0
            Assert-MockCalled Set-RegistryDword -Times 0 -Exactly -Scope It
            Assert-MockCalled Set-LockoutThreshold -Times 0 -Exactly -Scope It
            Assert-MockCalled Rename-BuiltinAccount -Times 0 -Exactly -Scope It
            Assert-MockCalled Disable-BuiltinAccount -Times 0 -Exactly -Scope It
            Assert-MockCalled Set-AuditSubcategorySuccessFailure -Times 0 -Exactly -Scope It
        }
    }

    Context 'Manual-only rules' {

        It 'never changes BitLocker even when remediation is enabled' {
            Mock Get-UnencryptedFixedVolumes { @('C:') }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-00-000030')
            $result.Status | Should -Be 'OPEN FINDING'
            $result.Notes | Should -Match 'manually'
        }

        It 'flags missing allowlisting as OPEN FINDING' {
            Mock Get-AppLockerRuleCount { 0 }
            (Invoke-StigControl -Control (Get-Control 'WN11-00-000035')).Status | Should -Be 'OPEN FINDING'
        }

        It 'sends existing AppLocker rules to MANUAL REVIEW rather than claiming compliance' {
            Mock Get-AppLockerRuleCount { 5 }
            (Invoke-StigControl -Control (Get-Control 'WN11-00-000035')).Status | Should -Be 'MANUAL REVIEW'
        }
    }

    Context 'Built-in accounts' {

        It 'renames the Administrator account by SID and verifies the new name' {
            $script:adminName = 'Administrator'
            Mock Get-BuiltinAccount { [pscustomobject]@{ Name = $script:adminName; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' } } }
            Mock Rename-BuiltinAccount { $script:adminName = $NewName }
            $result = Invoke-StigControl -Control (Get-Control 'WN11-SO-000020')
            $result.Status | Should -Be 'REMEDIATED'
            $result.After | Should -Be 'LocalAdmin'
            Assert-MockCalled Rename-BuiltinAccount -Times 1 -Exactly -Scope It -ParameterFilter { $Sid -eq 'S-1-5-21-1-2-3-500' }
        }

    }

    Context 'Built-in account lookup' {

        It 'matches RID 500 exactly and not a SID ending in 1500' {
            Mock Get-LocalUser {
                [pscustomobject]@{ Name = 'svc'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1500' } }
                [pscustomobject]@{ Name = 'Administrator'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' } }
            }
            (Get-BuiltinAccount -Rid '500').Name | Should -Be 'Administrator'
        }
    }

    Context 'Audit policy (WN11-AU-000070 / 000075)' {

        It 'parses the Inclusion Setting from auditpol /r output' {
            $lines = @(
                '',
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting',
                'HOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,'
            )
            ConvertFrom-AuditpolCsv -Lines $lines | Should -Be 'Success and Failure'
        }

        It 'passes failures and fails successes when only Failure is audited' {
            Mock Get-AuditSubcategorySetting { 'Failure' }
            (Invoke-StigControl -Control (Get-Control 'WN11-AU-000070') -AuditOnly).Status | Should -Be 'COMPLIANT'
            (Invoke-StigControl -Control (Get-Control 'WN11-AU-000075') -AuditOnly).Status | Should -Be 'OPEN FINDING'
        }
    }

    Context 'Registry writes' {

        It 'creates a missing registry key before writing the value' {
            Mock Test-Path { $false }
            Mock New-Item { }
            Mock New-ItemProperty { }
            Set-RegistryDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'MinimumPIN' -Value 6
            Assert-MockCalled New-Item -Times 1 -Exactly -Scope It
            Assert-MockCalled New-ItemProperty -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'MinimumPIN' -and $Value -eq 6 }
        }
    }

    Context 'Exit code' {

        It 'returns 0 when everything is compliant or remediated' {
            Get-StigExitCode -Results @([pscustomobject]@{ Status = 'COMPLIANT' }, [pscustomobject]@{ Status = 'REMEDIATED' }) | Should -Be 0
        }

        It 'returns 1 when findings remain' {
            Get-StigExitCode -Results @([pscustomobject]@{ Status = 'COMPLIANT' }, [pscustomobject]@{ Status = 'OPEN FINDING' }) | Should -Be 1
        }

        It 'returns 2 when any rule errored' {
            Get-StigExitCode -Results @([pscustomobject]@{ Status = 'OPEN FINDING' }, [pscustomobject]@{ Status = 'ERROR' }) | Should -Be 2
        }
    }
}
