Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$installer = Join-Path $PSScriptRoot "..\..\scripts\Install-WeFlowChat.ps1"
. $installer

function New-TestPackage {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string]$Version = "0.1.0"
    )
    $files = @{
        "LICENSE" = "license"
        "PRIVACY.md" = "privacy"
        "SECURITY.md" = "security"
        "THIRD_PARTY_NOTICES.md" = "notices"
        "runtime/python/python.exe" = "synthetic-python"
        "runtime/node/node.exe" = "synthetic-node"
        "scripts/Run-WeFlowChatInstalled.cmd" = "@echo off"
        "src/weflow_chat/__init__.py" = "__version__ = '$Version'"
    }
    foreach ($relative in $files.Keys) {
        $path = Join-Path $Root ($relative.Replace('/', '\'))
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) |
            Out-Null
        [IO.File]::WriteAllText($path, $files[$relative], [Text.Encoding]::UTF8)
    }
    $entries = @(
        foreach ($relative in ($files.Keys | Sort-Object)) {
            $path = Join-Path $Root ($relative.Replace('/', '\'))
            [pscustomobject]@{
                path = $relative
                sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                size = [long](Get-Item -LiteralPath $path).Length
            }
        }
    )
    [pscustomobject]@{
        schemaVersion = 1
        version = $Version
        files = $entries
    } | ConvertTo-Json -Depth 5 | Set-Content `
        -LiteralPath (Join-Path $Root "release-manifest.json") `
        -Encoding UTF8
    return $Root
}

Describe "user-level WeFlowChat package installer" {
    It "accepts only a complete hash-bound package" {
        $package = New-TestPackage (Join-Path $TestDrive "package")
        $result = Assert-WeFlowChatPackage $package
        $result.Version | Should Be "0.1.0"

        Add-Content -LiteralPath (Join-Path $package "LICENSE") -Value "tamper"
        { Assert-WeFlowChatPackage $package } |
            Should Throw "release_file_hash_mismatch"
    }

    It "installs atomically and removes the superseded version" {
        $package = New-TestPackage (Join-Path $TestDrive "package-new")
        $programs = Join-Path $TestDrive "Programs"
        $target = Join-Path $programs "WeFlowChat"
        $desktop = Join-Path $TestDrive "Desktop"
        [IO.Directory]::CreateDirectory($target) | Out-Null
        [IO.Directory]::CreateDirectory($desktop) | Out-Null
        Set-Content -LiteralPath (Join-Path $target "old-version.txt") `
            -Value "old"
        $events = New-Object System.Collections.Generic.List[string]

        $result = Install-WeFlowChatPackage -PackageRoot $package `
            -InstallRoot $target -DesktopPath $desktop `
            -RuntimeProbe { param($root) $events.Add("probe") } `
            -ShortcutInstaller {
                param($root, $desktopPath)
                $events.Add("shortcut")
            }

        $result.InstallRoot | Should Be ([IO.Path]::GetFullPath($target))
        $events.ToArray() | Should Be @("probe", "shortcut")
        Test-Path -LiteralPath (Join-Path $target "old-version.txt") |
            Should Be $false
        (Assert-WeFlowChatPackage $target).Version | Should Be "0.1.0"
        @(Get-ChildItem -LiteralPath $programs -Force |
            Where-Object { $_.Name -like ".WeFlowChat.*" }).Count |
            Should Be 0
    }

    It "restores the old install when shortcut publication fails" {
        $package = New-TestPackage (Join-Path $TestDrive "package-fail")
        $programs = Join-Path $TestDrive "Programs-fail"
        $target = Join-Path $programs "WeFlowChat"
        $desktop = Join-Path $TestDrive "Desktop-fail"
        [IO.Directory]::CreateDirectory($target) | Out-Null
        [IO.Directory]::CreateDirectory($desktop) | Out-Null
        Set-Content -LiteralPath (Join-Path $target "old-version.txt") `
            -Value "preserve"

        { Install-WeFlowChatPackage -PackageRoot $package `
              -InstallRoot $target -DesktopPath $desktop `
              -RuntimeProbe { param($root) } `
              -ShortcutInstaller { param($root, $path) throw "shortcut_failed" } } |
            Should Throw "shortcut_failed"

        (Get-Content -LiteralPath (Join-Path $target "old-version.txt") -Raw).Trim() |
            Should Be "preserve"
        @(Get-ChildItem -LiteralPath $programs -Force |
            Where-Object { $_.Name -like ".WeFlowChat.*" }).Count |
            Should Be 0
    }

    It "removes a newly created shortcut when first install fails" {
        $package = New-TestPackage (Join-Path $TestDrive "package-first-fail")
        $target = Join-Path $TestDrive "Programs-first-fail\WeFlowChat"
        $desktop = Join-Path $TestDrive "Desktop-first-fail"
        [IO.Directory]::CreateDirectory($desktop) | Out-Null
        $shortcut = Join-Path $desktop "刷新 WeFlow 聊天记录.lnk"
        $failAfterShortcut = {
            param($root, $path)
            Set-Content -LiteralPath $shortcut -Value "created"
            throw "shortcut_failed"
        }.GetNewClosure()

        { Install-WeFlowChatPackage -PackageRoot $package `
              -InstallRoot $target -DesktopPath $desktop `
              -RuntimeProbe { param($root) } `
              -ShortcutInstaller $failAfterShortcut } |
            Should Throw "shortcut_failed"

        Test-Path -LiteralPath $target | Should Be $false
        Test-Path -LiteralPath $shortcut | Should Be $false
    }

    It "creates a fixed no-argument shortcut and reads it back" {
        $desktop = Join-Path $TestDrive "Desktop-shortcut"
        $target = Join-Path $TestDrive "Programs-shortcut\WeFlowChat"
        [IO.Directory]::CreateDirectory($desktop) | Out-Null
        [IO.Directory]::CreateDirectory($target) | Out-Null
        $state = [pscustomobject]@{ Shortcut = $null; Paths = @() }
        $factory = {
            param($path)
            $state.Paths += $path
            if ($null -ne $state.Shortcut) { return $state.Shortcut }
            $shortcut = [pscustomobject]@{
                TargetPath = ""
                Arguments = "unexpected"
                WorkingDirectory = ""
                IconLocation = ""
            }
            $shortcut | Add-Member -MemberType ScriptMethod -Name Save -Value {}
            $state.Shortcut = $shortcut
            return $shortcut
        }.GetNewClosure()

        $path = Install-WeFlowChatShortcut -InstallRoot $target `
            -DesktopPath $desktop -ShortcutFactory $factory

        $state.Paths.Count | Should Be 2
        $state.Shortcut.Arguments | Should Be ""
        $state.Shortcut.TargetPath | Should Be (
            Join-Path $target "scripts\Run-WeFlowChatInstalled.cmd")
        $path | Should Be (Join-Path $desktop "刷新 WeFlow 聊天记录.lnk")
    }

    It "uses only package-relative Python and Node in the installed wrapper" {
        $wrapper = Join-Path $PSScriptRoot `
            "..\..\scripts\Run-WeFlowChatInstalled.cmd"
        $text = Get-Content -LiteralPath $wrapper -Raw
        $text | Should Match 'if not "%~1"==""'
        $text | Should Match 'runtime\\python\\python\.exe'
        $text | Should Match 'runtime\\node'
        $text | Should Not Match 'C:\\Windows\\py\.exe|\npy '
    }
}
