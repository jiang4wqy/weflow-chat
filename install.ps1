[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$ArchiveUri,
    [Parameter(Mandatory)][string]$ArchiveSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-BootstrapInputs {
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$ArchiveUri,
        [Parameter(Mandatory)][string]$ArchiveSha256
    )
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        $ArchiveSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "bootstrap_input_invalid"
    }
    try {
        $uri = [Uri]$ArchiveUri
    } catch {
        throw "bootstrap_input_invalid"
    }
    $expectedName = "weflow-chat-$Version-win-x64.zip"
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne "https" -or
        [IO.Path]::GetFileName($uri.AbsolutePath) -ne $expectedName) {
        throw "bootstrap_input_invalid"
    }
}

function Expand-VerifiedWeFlowChatArchive {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Version
    )
    if ($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "archive_hash_invalid"
    }
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
    if (-not [string]::Equals($actual, $ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "archive_hash_mismatch"
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "archive_destination_exists"
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $expectedRoot = "weflow-chat-$Version"
        if ($archive.Entries.Count -eq 0) {
            throw "archive_layout_invalid"
        }
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            $segments = @($name -split '/' | Where-Object { $_ -ne "" })
            if ([string]::IsNullOrWhiteSpace($name) -or
                $name -match '^[\\/]' -or
                $name -match '^[A-Za-z]:' -or
                $segments.Count -eq 0 -or
                $segments[0] -ne $expectedRoot -or
                $segments -contains "." -or
                $segments -contains ".." -or
                $name.IndexOf([char]0) -ge 0) {
                throw "archive_layout_invalid"
            }
        }
    } finally {
        $archive.Dispose()
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $Destination)
    $packageRoot = Join-Path $Destination "weflow-chat-$Version"
    $installer = Join-Path $packageRoot "scripts\Install-WeFlowChat.ps1"
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
        throw "archive_installer_missing"
    }
    return $packageRoot
}

function Invoke-WeFlowChatBootstrap {
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$ArchiveUri,
        [Parameter(Mandatory)][string]$ArchiveSha256,
        [scriptblock]$DownloadFile = {
            param($uri, $path)
            Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $path
        },
        [scriptblock]$PackageInstaller = {
            param($root)
            & (Join-Path $root "scripts\Install-WeFlowChat.ps1") `
                -PackageRoot $root
        }
    )
    Assert-BootstrapInputs -Version $Version -ArchiveUri $ArchiveUri `
        -ArchiveSha256 $ArchiveSha256
    $base = Join-Path ([Environment]::GetFolderPath(
        [Environment+SpecialFolder]::LocalApplicationData)) `
        "WeFlowChatBootstrap"
    [IO.Directory]::CreateDirectory($base) | Out-Null
    $token = [Guid]::NewGuid().ToString("N")
    $work = Join-Path $base $token
    [IO.Directory]::CreateDirectory($work) | Out-Null
    try {
        $archive = Join-Path $work "package.zip"
        & $DownloadFile $ArchiveUri $archive
        $expanded = Join-Path $work "expanded"
        $packageRoot = Expand-VerifiedWeFlowChatArchive `
            -ArchivePath $archive -ExpectedSha256 $ArchiveSha256 `
            -Destination $expanded -Version $Version
        & $PackageInstaller $packageRoot
    } finally {
        $canonicalBase = [IO.Path]::GetFullPath($base)
        $canonicalWork = [IO.Path]::GetFullPath($work)
        if ([IO.Path]::GetDirectoryName($canonicalWork) -ne $canonicalBase -or
            [IO.Path]::GetFileName($canonicalWork) -notmatch '^[0-9a-f]{32}$') {
            throw "bootstrap_cleanup_path_rejected"
        }
        if (Test-Path -LiteralPath $canonicalWork) {
            Remove-Item -LiteralPath $canonicalWork -Recurse -Force
        }
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-WeFlowChatBootstrap -Version $Version -ArchiveUri $ArchiveUri `
        -ArchiveSha256 $ArchiveSha256
}
