[CmdletBinding()]
param(
    [string]$PackageRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallRoot = "",
    [string]$DesktopPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-ReleaseVersion {
    param([Parameter(Mandatory)][string]$Version)
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "release_version_invalid"
    }
}

function Get-CanonicalPath {
    param([Parameter(Mandatory)][string]$Path)
    return [IO.Path]::GetFullPath($Path)
}

function Assert-OrdinaryPackageTree {
    param([Parameter(Mandatory)][string]$Root)
    $canonical = Get-CanonicalPath $Root
    if (-not (Test-Path -LiteralPath $canonical -PathType Container)) {
        throw "package_root_invalid"
    }
    $items = @(
        Get-Item -LiteralPath $canonical -Force
        Get-ChildItem -LiteralPath $canonical -Force -Recurse
    )
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "package_reparse_rejected"
        }
        if (-not $item.PSIsContainer -and -not (Test-Path -LiteralPath $item.FullName -PathType Leaf)) {
            throw "package_entry_invalid"
        }
    }
    return $canonical
}

function Read-WeFlowChatReleaseManifest {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $root = Assert-OrdinaryPackageTree $PackageRoot
    $path = Join-Path $root "release-manifest.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "release_manifest_missing"
    }
    try {
        $manifest = Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch {
        throw "release_manifest_invalid"
    }
    $properties = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object @("files", "schemaVersion", "version") $properties).Count -ne 0 -or
        $manifest.schemaVersion -ne 1) {
        throw "release_manifest_invalid"
    }
    Assert-ReleaseVersion ([string]$manifest.version)
    if ($null -eq $manifest.files -or @($manifest.files).Count -eq 0) {
        throw "release_manifest_invalid"
    }
    return $manifest
}

function Assert-WeFlowChatPackage {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $root = Assert-OrdinaryPackageTree $PackageRoot
    $manifest = Read-WeFlowChatReleaseManifest $root
    $expected = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($manifest.files)) {
        $properties = @($entry.PSObject.Properties.Name | Sort-Object)
        $relative = [string]$entry.path
        $hash = [string]$entry.sha256
        $size = $entry.size
        $segments = @($relative -split '/')
        if (@(Compare-Object @("path", "sha256", "size") $properties).Count -ne 0 -or
            [string]::IsNullOrWhiteSpace($relative) -or
            $relative -match '^[\\/]' -or
            $relative -match '^[A-Za-z]:' -or
            $relative -match '\\' -or
            $segments -contains "" -or
            $segments -contains "." -or
            $segments -contains ".." -or
            $relative -eq "release-manifest.json" -or
            $hash -notmatch '^[0-9A-F]{64}$' -or
            $size -isnot [long] -and $size -isnot [int] -or
            [long]$size -lt 0 -or
            $expected.ContainsKey($relative)) {
            throw "release_manifest_invalid"
        }
        $expected.Add($relative, $entry)
    }
    $required = @(
        "LICENSE",
        "PRIVACY.md",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        "runtime/python/python.exe",
        "runtime/node/node.exe",
        "scripts/Run-WeFlowChatInstalled.cmd",
        "src/weflow_chat/__init__.py"
    )
    foreach ($relative in $required) {
        if (-not $expected.ContainsKey($relative)) {
            throw "release_required_file_missing"
        }
    }
    $actual = @(
        Get-ChildItem -LiteralPath $root -File -Force -Recurse |
            ForEach-Object {
                $_.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
            } |
            Where-Object { $_ -ne "release-manifest.json" } |
            Sort-Object
    )
    $listed = @($expected.Keys | Sort-Object)
    if (@(Compare-Object $listed $actual).Count -ne 0) {
        throw "release_manifest_file_set_mismatch"
    }
    foreach ($relative in $listed) {
        $path = Join-Path $root ($relative.Replace('/', '\'))
        $entry = $expected[$relative]
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Length -ne [long]$entry.size -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne [string]$entry.sha256) {
            throw "release_file_hash_mismatch"
        }
    }
    return [pscustomobject]@{
        Root = $root
        Version = [string]$manifest.version
    }
}

function Test-WeFlowChatBundledRuntimes {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $python = Join-Path $PackageRoot "runtime\python\python.exe"
    $node = Join-Path $PackageRoot "runtime\node\node.exe"
    $pythonVersion = (& $python --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $pythonVersion -notmatch '^Python 3\.12\.') {
        throw "bundled_python_invalid"
    }
    $nodeVersion = (& $node --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v24\.') {
        throw "bundled_node_invalid"
    }
}

function Get-WeFlowChatShortcutContract {
    param([Parameter(Mandatory)][string]$InstallRoot)
    [pscustomobject]@{
        TargetPath = Join-Path $InstallRoot "scripts\Run-WeFlowChatInstalled.cmd"
        Arguments = ""
        WorkingDirectory = $InstallRoot
        IconLocation = (Join-Path $env:SystemRoot "System32\shell32.dll") + ",238"
    }
}

function New-WeFlowChatShortcutObject {
    param([Parameter(Mandatory)][string]$Path)
    $shell = New-Object -ComObject WScript.Shell
    return $shell.CreateShortcut($Path)
}

function Get-WeFlowChatShortcutName {
    return -join @(
        [char]0x5237, [char]0x65B0,
        " WeFlow ",
        [char]0x804A, [char]0x5929,
        [char]0x8BB0, [char]0x5F55,
        ".lnk"
    )
}

function Install-WeFlowChatShortcut {
    param(
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$DesktopPath,
        [scriptblock]$ShortcutFactory = {
            param($path) New-WeFlowChatShortcutObject $path
        }
    )
    if (-not (Test-Path -LiteralPath $DesktopPath -PathType Container)) {
        throw "desktop_path_invalid"
    }
    $shortcutPath = Join-Path $DesktopPath (Get-WeFlowChatShortcutName)
    $contract = Get-WeFlowChatShortcutContract $InstallRoot
    $shortcut = & $ShortcutFactory $shortcutPath
    $shortcut.TargetPath = $contract.TargetPath
    $shortcut.Arguments = $contract.Arguments
    $shortcut.WorkingDirectory = $contract.WorkingDirectory
    $shortcut.IconLocation = $contract.IconLocation
    $shortcut.Save()
    $saved = & $ShortcutFactory $shortcutPath
    if (-not [string]::Equals($saved.TargetPath, $contract.TargetPath, [StringComparison]::OrdinalIgnoreCase) -or
        $saved.Arguments -ne "" -or
        -not [string]::Equals($saved.WorkingDirectory, $contract.WorkingDirectory, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($saved.IconLocation, $contract.IconLocation, [StringComparison]::OrdinalIgnoreCase)) {
        throw "shortcut_readback_mismatch"
    }
    return $shortcutPath
}

function Remove-ExactInstallerDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedParent
    )
    $target = Get-CanonicalPath $Path
    $parent = Get-CanonicalPath $AllowedParent
    if ([IO.Path]::GetDirectoryName($target) -ne $parent -or
        [IO.Path]::GetFileName($target) -notmatch '^\.WeFlowChat\.(?:install|backup|failed)\.[0-9a-f]{32}$') {
        throw "installer_cleanup_path_rejected"
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

function Install-WeFlowChatPackage {
    param(
        [Parameter(Mandatory)][string]$PackageRoot,
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][string]$DesktopPath,
        [scriptblock]$RuntimeProbe = {
            param($root) Test-WeFlowChatBundledRuntimes $root
        },
        [scriptblock]$ShortcutInstaller = {
            param($root, $desktop) Install-WeFlowChatShortcut `
                -InstallRoot $root -DesktopPath $desktop
        }
    )
    $source = (Assert-WeFlowChatPackage $PackageRoot).Root
    $target = Get-CanonicalPath $InstallRoot
    if ([IO.Path]::GetFileName($target) -ne "WeFlowChat") {
        throw "install_root_invalid"
    }
    $parent = [IO.Path]::GetDirectoryName($target)
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $token = [Guid]::NewGuid().ToString("N")
    $staging = Join-Path $parent (".WeFlowChat.install." + $token)
    $backup = Join-Path $parent (".WeFlowChat.backup." + $token)
    $failed = Join-Path $parent (".WeFlowChat.failed." + $token)
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    try {
        Get-ChildItem -LiteralPath $source -Force | Copy-Item `
            -Destination $staging -Recurse -Force
        Assert-WeFlowChatPackage $staging | Out-Null
        & $RuntimeProbe $staging
        $hadExisting = Test-Path -LiteralPath $target -PathType Container
        if ($hadExisting) {
            Move-Item -LiteralPath $target -Destination $backup
        }
        try {
            Move-Item -LiteralPath $staging -Destination $target
            & $ShortcutInstaller $target $DesktopPath | Out-Null
        } catch {
            if (Test-Path -LiteralPath $target) {
                Move-Item -LiteralPath $target -Destination $failed
            }
            if ($hadExisting -and (Test-Path -LiteralPath $backup)) {
                Move-Item -LiteralPath $backup -Destination $target
            } elseif (-not $hadExisting) {
                $shortcutPath = Join-Path $DesktopPath `
                    (Get-WeFlowChatShortcutName)
                if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
                    Remove-Item -LiteralPath $shortcutPath -Force
                }
            }
            throw
        }
        if (Test-Path -LiteralPath $backup) {
            Remove-ExactInstallerDirectory -Path $backup -AllowedParent $parent
        }
        if (Test-Path -LiteralPath $failed) {
            Remove-ExactInstallerDirectory -Path $failed -AllowedParent $parent
        }
        return [pscustomobject]@{
            InstallRoot = $target
            Version = (Read-WeFlowChatReleaseManifest $target).version
        }
    } finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-ExactInstallerDirectory -Path $staging -AllowedParent $parent
        }
        if (Test-Path -LiteralPath $failed) {
            Remove-ExactInstallerDirectory -Path $failed -AllowedParent $parent
        }
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
        $InstallRoot = Join-Path ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::LocalApplicationData)) `
            "Programs\WeFlowChat"
    }
    if ([string]::IsNullOrWhiteSpace($DesktopPath)) {
        $DesktopPath = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Desktop)
    }
    Install-WeFlowChatPackage -PackageRoot $PackageRoot `
        -InstallRoot $InstallRoot -DesktopPath $DesktopPath | Out-Host
}
