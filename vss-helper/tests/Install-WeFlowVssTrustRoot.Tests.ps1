Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$installer = Join-Path $PSScriptRoot "..\Install-WeFlowVssTrustRoot.ps1"
. $installer

function New-NormalComponent {
    [pscustomobject]@{
        IsContainer = $true
        Attributes = [IO.FileAttributes]::Directory
    }
}

Describe "fixed VSS trust-root bootstrap" {
    It "declares no parameters, contains no self-elevation, and is safe to dot-source" {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $installer, [ref]$tokens, [ref]$errors)
        $errors.Count | Should Be 0
        $ast.ParamBlock.Parameters.Count | Should Be 0
        @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq "Start-Process"
        }, $true)).Count | Should Be 0
        { Assert-FixedTrustRootInstallerArguments } |
            Should Not Throw
        { Assert-FixedTrustRootInstallerArguments `
              -SuppliedArguments @("SENSITIVE") } |
            Should Throw "installer_arguments_rejected"
    }

    It "checks the fixed parent chain before creating only the fixed root" {
        $events = New-Object System.Collections.Generic.List[string]
        $state = [pscustomobject]@{ Created = $false }
        $normal = New-NormalComponent
        $inspect = {
            param($path)
            $events.Add("inspect:" + $path)
            if ($path -in @("C:\", "C:\ProgramData") -or $state.Created) {
                return $normal
            }
            return $null
        }.GetNewClosure()
        $exists = { param($path) return $false }
        $initialize = {
            param($path)
            $events.Add("initialize:" + $path)
            $state.Created = $true
        }.GetNewClosure()
        $verify = {
            param($path) $events.Add("verify:" + $path)
        }.GetNewClosure()

        Invoke-FixedTrustRootInstall -InspectComponent $inspect `
            -RootExists $exists -InitializeAcl $initialize -VerifyAcl $verify

        $target = "C:\ProgramData\WeFlowRecovery\shadows"
        ($events.IndexOf("initialize:" + $target) -gt
            $events.IndexOf("inspect:C:\ProgramData")) | Should Be $true
        ($events.IndexOf("verify:" + $target) -gt
            $events.IndexOf("initialize:" + $target)) | Should Be $true
        $initializations = @($events | Where-Object { $_ -like "initialize:*" })
        $initializations.Count | Should Be 1
        $initializations[0] | Should Be ("initialize:" + $target)
    }

    It "fails closed when creation cannot be confirmed" {
        $verifications = New-Object System.Collections.Generic.List[string]
        $inspect = {
            param($path)
            if ($path -in @("C:\", "C:\ProgramData")) {
                return New-NormalComponent
            }
            return $null
        }
        $verify = {
            param($path)
            $verifications.Add($path)
        }.GetNewClosure()

        { Invoke-FixedTrustRootInstall -InspectComponent $inspect `
              -RootExists { param($path) $false } `
              -InitializeAcl { param($path) } -VerifyAcl $verify } |
            Should Throw "trust_root_creation_not_confirmed"
        $verifications.Count | Should Be 0
    }

    It "rejects a parent reparse point before initialization" {
        $initializations = New-Object System.Collections.Generic.List[string]
        $inspect = {
            param($path)
            if ($path -eq "C:\ProgramData") {
                return [pscustomobject]@{
                    IsContainer = $true
                    Attributes = [IO.FileAttributes]::ReparsePoint
                }
            }
            return New-NormalComponent
        }
        $initialize = {
            param($path) $initializations.Add($path)
        }.GetNewClosure()
        { Invoke-FixedTrustRootInstall -InspectComponent $inspect `
              -RootExists { param($path) $false } `
              -InitializeAcl $initialize -VerifyAcl { param($path) } } |
            Should Throw "trust_root_parent_reparse"
        $initializations.Count | Should Be 0
    }

    It "is a no-write success when the existing ACL is exact" {
        $initializations = New-Object System.Collections.Generic.List[string]
        $verifications = New-Object System.Collections.Generic.List[string]
        $initialize = {
            param($path) $initializations.Add($path)
        }.GetNewClosure()
        $verify = {
            param($path) $verifications.Add($path)
        }.GetNewClosure()
        $arguments = @{
            InspectComponent = { param($path) New-NormalComponent }
            RootExists = { param($path) $true }
            InitializeAcl = $initialize
            VerifyAcl = $verify
        }
        Invoke-FixedTrustRootInstall @arguments
        Invoke-FixedTrustRootInstall @arguments
        $initializations.Count | Should Be 0
        $verifications.Count | Should Be 2
    }

    It "rejects existing ACL drift instead of repairing it" {
        $initializations = New-Object System.Collections.Generic.List[string]
        $initialize = {
            param($path) $initializations.Add($path)
        }.GetNewClosure()
        { Invoke-FixedTrustRootInstall `
              -InspectComponent { param($path) New-NormalComponent } `
              -RootExists { param($path) $true } `
              -InitializeAcl $initialize `
              -VerifyAcl { param($path) throw "journal_acl_unexpected_rule" } } |
            Should Throw "journal_acl_unexpected_rule"
        $initializations.Count | Should Be 0
    }

    It "bounds the explicit bootstrap child wait and fails closed" {
        $waits = New-Object System.Collections.Generic.List[int]
        $process = [pscustomobject]@{ ExitCode = 0 }
        $wait = {
            param($milliseconds)
            $waits.Add([int]$milliseconds)
            return $false
        }.GetNewClosure()
        $process | Add-Member -MemberType ScriptMethod -Name WaitForExit `
            -Value $wait
        { Wait-FixedTrustRootBootstrapProcess -Process $process } |
            Should Throw "trust_root_install_timeout"
        $waits.Count | Should Be 1
        $waits[0] | Should Be 60000
    }

    It "accepts only a completed zero-exit bootstrap child" {
        foreach ($case in @(
            @{ Completed = $true; ExitCode = 0; Throws = $false },
            @{ Completed = $true; ExitCode = 7; Throws = $true }
        )) {
            $process = [pscustomobject]@{ ExitCode = $case.ExitCode }
            $completed = $case.Completed
            $wait = { param($milliseconds) return $completed }.GetNewClosure()
            $process | Add-Member -MemberType ScriptMethod -Name WaitForExit `
                -Value $wait
            if ($case.Throws) {
                { Wait-FixedTrustRootBootstrapProcess -Process $process } |
                    Should Throw "trust_root_install_failed"
            } else {
                { Wait-FixedTrustRootBootstrapProcess -Process $process } |
                    Should Not Throw
            }
        }
    }
}
