[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("PrepareCreate","Create","Adopt","DeleteExact","InspectOwned")]
    [string]$Action,
    [Parameter(Mandatory=$true)][string]$RunId,
    [string]$SourceVolume,
    [string]$ExpectedShadowId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "WeFlowVssHelper.psm1") -Force
Assert-JournalRootAcl | Out-Null

$result = switch ($Action) {
    "PrepareCreate" {
        if ($PSBoundParameters.ContainsKey("ExpectedShadowId")) {
            throw "unexpected_shadow_id"
        }
        Prepare-OwnedShadowCreate -RunId $RunId `
            -SourceVolume $SourceVolume
    }
    "Create" {
        if ($PSBoundParameters.ContainsKey("ExpectedShadowId")) {
            throw "unexpected_shadow_id"
        }
        New-OwnedShadow -RunId $RunId -SourceVolume $SourceVolume
    }
    "Adopt" {
        if ($PSBoundParameters.ContainsKey("SourceVolume")) {
            throw "unexpected_source_volume"
        }
        Adopt-OwnedShadow -RunId $RunId -ExpectedShadowId $ExpectedShadowId
    }
    "DeleteExact" {
        if ($PSBoundParameters.ContainsKey("SourceVolume")) {
            throw "unexpected_source_volume"
        }
        Remove-OwnedShadowExact -RunId $RunId `
            -ExpectedShadowId $ExpectedShadowId
    }
    "InspectOwned" {
        if ($PSBoundParameters.ContainsKey("SourceVolume") -or
            $PSBoundParameters.ContainsKey("ExpectedShadowId")) {
            throw "unexpected_inspect_argument"
        }
        Get-OwnedShadow -RunId $RunId
    }
}
$result | ConvertTo-Json -Compress
