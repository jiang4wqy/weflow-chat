[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [string]$OutputDirectory = "",
    [string]$Repository = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:PythonRuntime = [pscustomobject]@{
    Version = "3.12.10"
    Uri = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip"
    Sha256 = "4ACBED6DD1C744B0376E3B1CF57CE906F9DC9E95E68824584C8099A63025A3C3"
}
$script:NodeRuntime = [pscustomobject]@{
    Version = "24.14.1"
    Uri = "https://nodejs.org/dist/v24.14.1/node-v24.14.1-win-x64.zip"
    Sha256 = "6E50CE5498C0CEBC20FD39AB3FF5DF836ED2F8A31AA093CECAD8497CFF126D70"
}

function Assert-ReleaseBuildVersion {
    param([Parameter(Mandatory)][string]$Version)
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "release_version_invalid"
    }
}

function Assert-CleanReleaseTree {
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    $status = & git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace(
            ($status | Out-String))) {
        throw "release_tree_not_clean"
    }
}

function Get-VerifiedRuntimeArchive {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][string]$Destination,
        [string]$ExistingArchive = "",
        [scriptblock]$Downloader = {
            param($source, $target)
            Invoke-WebRequest -UseBasicParsing -Uri $source -OutFile $target
        }
    )
    if ($Sha256 -notmatch '^[0-9A-F]{64}$') {
        throw "runtime_hash_contract_invalid"
    }
    if ([string]::IsNullOrWhiteSpace($ExistingArchive)) {
        & $Downloader $Uri $Destination
        $path = $Destination
    } else {
        $path = [IO.Path]::GetFullPath($ExistingArchive)
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $Sha256) {
        throw "runtime_archive_hash_mismatch"
    }
    return $path
}

function Copy-ReleaseFile {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$PackageRoot,
        [Parameter(Mandatory)][string]$RelativePath
    )
    $source = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "release_source_missing"
    }
    $destination = Join-Path $PackageRoot $RelativePath
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) |
        Out-Null
    Copy-Item -LiteralPath $source -Destination $destination
}

function Copy-ReleaseSources {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$PackageRoot
    )
    foreach ($relative in @(
        "README.md",
        "LICENSE",
        "PRIVACY.md",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        "install.ps1",
        "validator-node\package.json",
        "validator-node\package-lock.json",
        "vss-helper\Install-WeFlowVssTrustRoot.ps1",
        "vss-helper\Invoke-WeFlowVssHelper.ps1",
        "vss-helper\WeFlowVssHelper.psm1",
        "scripts\Install-WeFlowChat.ps1",
        "scripts\Run-WeFlowChatInstalled.cmd"
    )) {
        Copy-ReleaseFile -RepositoryRoot $RepositoryRoot `
            -PackageRoot $PackageRoot -RelativePath $relative
    }
    foreach ($source in @(
        Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot "src") `
            -File -Recurse -Filter "*.py"
        Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot "validator-node\src") `
            -File -Recurse | Where-Object { $_.Extension -in @(".cjs", ".mjs") }
    )) {
        $relative = $source.FullName.Substring($RepositoryRoot.Length).TrimStart('\')
        Copy-ReleaseFile -RepositoryRoot $RepositoryRoot `
            -PackageRoot $PackageRoot -RelativePath $relative
    }
}

function Write-ReleaseManifest {
    param(
        [Parameter(Mandatory)][string]$PackageRoot,
        [Parameter(Mandatory)][string]$Version
    )
    $files = @(
        Get-ChildItem -LiteralPath $PackageRoot -File -Force -Recurse |
            Where-Object { $_.Name -ne "release-manifest.json" } |
            ForEach-Object {
                [pscustomobject]@{
                    path = $_.FullName.Substring($PackageRoot.Length).TrimStart('\').Replace('\', '/')
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                    size = [long]$_.Length
                }
            } |
            Sort-Object path
    )
    [pscustomobject]@{
        schemaVersion = 1
        version = $Version
        files = $files
    } | ConvertTo-Json -Depth 5 | Set-Content `
        -LiteralPath (Join-Path $PackageRoot "release-manifest.json") `
        -Encoding UTF8
}

function Remove-ExactBuildDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OutputRoot
    )
    $target = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($OutputRoot)
    if ([IO.Path]::GetDirectoryName($target) -ne $parent -or
        [IO.Path]::GetFileName($target) -notmatch '^\.build\.[0-9a-f]{32}$') {
        throw "release_cleanup_path_rejected"
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

function New-WeFlowChatRelease {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$Version,
        [string]$PythonArchive = "",
        [string]$NodeArchive = "",
        [string]$PythonSha256 = $script:PythonRuntime.Sha256,
        [string]$NodeSha256 = $script:NodeRuntime.Sha256,
        [switch]$SkipCleanCheck,
        [scriptblock]$DependencyInstaller = {
            param($validatorRoot)
            & npm --prefix $validatorRoot ci --omit=dev --ignore-scripts `
                --registry=https://registry.npmjs.org
            if ($LASTEXITCODE -ne 0) { throw "node_dependency_install_failed" }
        },
        [scriptblock]$RuntimeProbe = {
            param($packageRoot)
            & (Join-Path $packageRoot "runtime\python\python.exe") --version
            if ($LASTEXITCODE -ne 0) { throw "bundled_python_invalid" }
            & (Join-Path $packageRoot "runtime\node\node.exe") --version
            if ($LASTEXITCODE -ne 0) { throw "bundled_node_invalid" }
        }
    )
    Assert-ReleaseBuildVersion $Version
    $repository = [IO.Path]::GetFullPath($RepositoryRoot)
    $output = [IO.Path]::GetFullPath($OutputDirectory)
    if (-not $SkipCleanCheck) {
        Assert-CleanReleaseTree $repository
    }
    $sourceVersion = Select-String -LiteralPath (
        Join-Path $repository "src\weflow_chat\__init__.py") `
        -Pattern ('^__version__ = "' + [regex]::Escape($Version) + '"$')
    if ($null -eq $sourceVersion) {
        throw "release_version_source_mismatch"
    }
    [IO.Directory]::CreateDirectory($output) | Out-Null
    $assetName = "weflow-chat-$Version-win-x64.zip"
    $asset = Join-Path $output $assetName
    $digestPath = $asset + ".sha256"
    $bootstrapAsset = Join-Path $output "weflow-chat-$Version-install.ps1"
    if ((Test-Path -LiteralPath $asset) -or
        (Test-Path -LiteralPath $digestPath) -or
        (Test-Path -LiteralPath $bootstrapAsset)) {
        throw "release_asset_exists"
    }
    $build = Join-Path $output (".build." + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($build) | Out-Null
    try {
        $package = Join-Path $build "weflow-chat-$Version"
        [IO.Directory]::CreateDirectory($package) | Out-Null
        Copy-ReleaseSources -RepositoryRoot $repository -PackageRoot $package

        $download = Join-Path $build "downloads"
        [IO.Directory]::CreateDirectory($download) | Out-Null
        $pythonZip = Get-VerifiedRuntimeArchive `
            -Uri $script:PythonRuntime.Uri -Sha256 $PythonSha256 `
            -Destination (Join-Path $download "python.zip") `
            -ExistingArchive $PythonArchive
        $nodeZip = Get-VerifiedRuntimeArchive `
            -Uri $script:NodeRuntime.Uri -Sha256 $NodeSha256 `
            -Destination (Join-Path $download "node.zip") `
            -ExistingArchive $NodeArchive

        $pythonRoot = Join-Path $package "runtime\python"
        [IO.Directory]::CreateDirectory($pythonRoot) | Out-Null
        Expand-Archive -LiteralPath $pythonZip -DestinationPath $pythonRoot
        $pth = @(Get-ChildItem -LiteralPath $pythonRoot -Filter "python312._pth")
        if ($pth.Count -ne 1) { throw "python_path_file_missing" }
        @("python312.zip", ".", "..\..\src", "import site") |
            Set-Content -LiteralPath $pth[0].FullName -Encoding ASCII

        $nodeExpanded = Join-Path $build "node-expanded"
        Expand-Archive -LiteralPath $nodeZip -DestinationPath $nodeExpanded
        $nodeSource = Join-Path $nodeExpanded (
            "node-v" + $script:NodeRuntime.Version + "-win-x64")
        if (-not (Test-Path -LiteralPath (Join-Path $nodeSource "node.exe") -PathType Leaf)) {
            throw "node_archive_layout_invalid"
        }
        $nodeRoot = Join-Path $package "runtime\node"
        [IO.Directory]::CreateDirectory($nodeRoot) | Out-Null
        Get-ChildItem -LiteralPath $nodeSource -Force | Copy-Item `
            -Destination $nodeRoot -Recurse

        & $DependencyInstaller (Join-Path $package "validator-node") | Out-Null
        & $RuntimeProbe $package | Out-Null
        Write-ReleaseManifest -PackageRoot $package -Version $Version

        Compress-Archive -LiteralPath $package -DestinationPath $asset `
            -CompressionLevel Optimal
        $digest = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash
        [IO.File]::WriteAllText(
            $digestPath, "$digest  $assetName`r`n", [Text.Encoding]::ASCII)
        Copy-Item -LiteralPath (Join-Path $repository "install.ps1") `
            -Destination $bootstrapAsset
        $bootstrapDigest = (
            Get-FileHash -LiteralPath $bootstrapAsset -Algorithm SHA256).Hash
        [IO.File]::WriteAllText(
            $bootstrapAsset + ".sha256",
            "$bootstrapDigest  $([IO.Path]::GetFileName($bootstrapAsset))`r`n",
            [Text.Encoding]::ASCII)
        return [pscustomobject]@{
            Archive = $asset
            ArchiveSha256 = $digest
            Bootstrap = $bootstrapAsset
            BootstrapSha256 = $bootstrapDigest
        }
    } finally {
        Remove-ExactBuildDirectory -Path $build -OutputRoot $output
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) "release"
    }
    $result = New-WeFlowChatRelease `
        -RepositoryRoot (Split-Path -Parent $PSScriptRoot) `
        -OutputDirectory $OutputDirectory -Version $Version
    if (-not [string]::IsNullOrWhiteSpace($Repository)) {
        & (Join-Path $PSScriptRoot "New-InstallCommand.ps1") `
            -Repository $Repository -Version $Version `
            -ArchiveSha256 $result.ArchiveSha256 `
            -BootstrapSha256 $result.BootstrapSha256 `
            -OutputPath (Join-Path $OutputDirectory "install-command.txt")
    }
    $result | Format-List
}
