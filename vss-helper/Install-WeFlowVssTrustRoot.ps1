[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:JournalRoot = "C:\ProgramData\WeFlowRecovery\shadows"
$script:BootstrapTimeoutMilliseconds = 60000
Import-Module (Join-Path $PSScriptRoot "WeFlowVssHelper.psm1") -Force

function Get-FixedTrustRootComponents {
    @(
        "C:\",
        "C:\ProgramData",
        "C:\ProgramData\WeFlowRecovery",
        $script:JournalRoot
    )
}

function Assert-FixedTrustRootInstallerArguments {
    param([object[]]$SuppliedArguments = @())
    if ($SuppliedArguments.Count -ne 0) {
        throw "installer_arguments_rejected"
    }
}

function Wait-FixedTrustRootBootstrapProcess {
    param([Parameter(Mandatory)]$Process)
    if (-not $Process.WaitForExit($script:BootstrapTimeoutMilliseconds)) {
        throw "trust_root_install_timeout"
    }
    if ($Process.ExitCode -ne 0) {
        throw "trust_root_install_failed"
    }
}

function Invoke-FixedTrustRootInstall {
    param(
        [scriptblock]$InspectComponent = {
            param($path)
            if (-not (Test-Path -LiteralPath $path)) {
                return $null
            }
            $item = Get-Item -LiteralPath $path -Force
            return [pscustomobject]@{
                IsContainer = $item.PSIsContainer
                Attributes = $item.Attributes
            }
        },
        [scriptblock]$RootExists = {
            param($path)
            Test-Path -LiteralPath $path -PathType Container
        },
        [scriptblock]$InitializeAcl = {
            param($path)
            Initialize-JournalRootAcl -Root $path
        },
        [scriptblock]$VerifyAcl = {
            param($path)
            Assert-JournalRootAcl -Root $path | Out-Null
        }
    )

    foreach ($component in Get-FixedTrustRootComponents) {
        $item = & $InspectComponent $component
        if ($null -eq $item) {
            continue
        }
        if (-not $item.IsContainer) {
            throw "trust_root_parent_not_directory"
        }
        if (([IO.FileAttributes]$item.Attributes -band
             [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "trust_root_parent_reparse"
        }
    }

    if (& $RootExists $script:JournalRoot) {
        & $VerifyAcl $script:JournalRoot
        return
    }

    & $InitializeAcl $script:JournalRoot

    foreach ($component in Get-FixedTrustRootComponents) {
        $item = & $InspectComponent $component
        if ($null -eq $item -or -not $item.IsContainer) {
            throw "trust_root_creation_not_confirmed"
        }
        if (([IO.FileAttributes]$item.Attributes -band
             [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "trust_root_parent_reparse"
        }
    }

    & $VerifyAcl $script:JournalRoot
}

if ($MyInvocation.InvocationName -ne ".") {
    $argumentVariable = Get-Variable -Name args `
        -ErrorAction SilentlyContinue
    $installerArguments = @()
    if ($null -ne $argumentVariable) {
        $installerArguments = @($argumentVariable.Value)
    }
    Assert-FixedTrustRootInstallerArguments `
        -SuppliedArguments $installerArguments
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "installer_requires_elevation"
    }
    Invoke-FixedTrustRootInstall
}
