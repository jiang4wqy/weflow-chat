Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$builder = Join-Path $PSScriptRoot "..\..\scripts\Build-Release.ps1"
. $builder -Version "0.1.0"
$installer = Join-Path $PSScriptRoot "..\..\scripts\Install-WeFlowChat.ps1"
. $installer

function New-SyntheticRuntimeArchives {
    param([Parameter(Mandatory)][string]$Root)
    $pythonRoot = Join-Path $Root "python"
    [IO.Directory]::CreateDirectory($pythonRoot) | Out-Null
    Set-Content -LiteralPath (Join-Path $pythonRoot "python.exe") `
        -Value "synthetic-python"
    Set-Content -LiteralPath (Join-Path $pythonRoot "python312._pth") `
        -Value @("python312.zip", ".", "#import site")
    Set-Content -LiteralPath (Join-Path $pythonRoot "python312.zip") `
        -Value "synthetic-stdlib"
    $pythonZip = Join-Path $Root "python.zip"
    Compress-Archive -Path (Join-Path $pythonRoot "*") `
        -DestinationPath $pythonZip

    $nodeParent = Join-Path $Root "node"
    $nodeRoot = Join-Path $nodeParent "node-v24.14.1-win-x64"
    [IO.Directory]::CreateDirectory($nodeRoot) | Out-Null
    Set-Content -LiteralPath (Join-Path $nodeRoot "node.exe") `
        -Value "synthetic-node"
    Set-Content -LiteralPath (Join-Path $nodeRoot "LICENSE") `
        -Value "synthetic-license"
    $nodeZip = Join-Path $Root "node.zip"
    Compress-Archive -LiteralPath $nodeRoot -DestinationPath $nodeZip
    return [pscustomobject]@{
        Python = $pythonZip
        PythonSha256 = (Get-FileHash -LiteralPath $pythonZip -Algorithm SHA256).Hash
        Node = $nodeZip
        NodeSha256 = (Get-FileHash -LiteralPath $nodeZip -Algorithm SHA256).Hash
    }
}

Describe "Windows release builder" {
    It "pins official runtime sources and hashes" {
        $script:PythonRuntime.Version | Should Be "3.12.10"
        $script:PythonRuntime.Uri | Should Be `
            "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip"
        $script:PythonRuntime.Sha256 | Should Match '^[0-9A-F]{64}$'
        $script:NodeRuntime.Version | Should Be "24.14.1"
        $script:NodeRuntime.Uri | Should Be `
            "https://nodejs.org/dist/v24.14.1/node-v24.14.1-win-x64.zip"
        $script:NodeRuntime.Sha256 | Should Match '^[0-9A-F]{64}$'
    }

    It "builds a hash-bound package from synthetic runtimes" {
        $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
        $archives = New-SyntheticRuntimeArchives (
            Join-Path $TestDrive "runtimes")
        $output = Join-Path $TestDrive "release"
        $dependencies = {
            param($validatorRoot)
            $license = Join-Path $validatorRoot `
                "node_modules\synthetic-package\LICENSE"
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($license)) |
                Out-Null
            Set-Content -LiteralPath $license -Value "synthetic-license"
            "dependency-noise"
        }

        $result = New-WeFlowChatRelease -RepositoryRoot $repo `
            -OutputDirectory $output -Version "0.1.0" `
            -PythonArchive $archives.Python `
            -PythonSha256 $archives.PythonSha256 `
            -NodeArchive $archives.Node -NodeSha256 $archives.NodeSha256 `
            -DependencyInstaller $dependencies `
            -RuntimeProbe { param($root) "runtime-noise" } `
            -SkipCleanCheck

        Test-Path -LiteralPath $result.Archive -PathType Leaf |
            Should Be $true
        (Get-FileHash -LiteralPath $result.Archive -Algorithm SHA256).Hash |
            Should Be $result.ArchiveSha256
        Test-Path -LiteralPath ($result.Archive + ".sha256") -PathType Leaf |
            Should Be $true
        Test-Path -LiteralPath $result.Bootstrap -PathType Leaf |
            Should Be $true
        Test-Path -LiteralPath ($result.Bootstrap + ".sha256") -PathType Leaf |
            Should Be $true
        @(Get-ChildItem -LiteralPath $output -Force |
            Where-Object { $_.Name -like ".build.*" }).Count | Should Be 0

        $expanded = Join-Path $TestDrive "expanded-release"
        Expand-Archive -LiteralPath $result.Archive -DestinationPath $expanded
        $package = Join-Path $expanded "weflow-chat-0.1.0"
        (Assert-WeFlowChatPackage $package).Version | Should Be "0.1.0"
        Get-Content -LiteralPath (
            Join-Path $package "runtime\python\python312._pth") -Raw |
            Should Match '\.\.\\\.\.\\src'
    }

    It "generates a one-line installer that verifies before execution" {
        $output = Join-Path $TestDrive "install-command.txt"
        & (Join-Path $PSScriptRoot "..\..\scripts\New-InstallCommand.ps1") `
            -Repository "example/weflow-chat" -Version "0.1.0" `
            -ArchiveSha256 ("A" * 64) -BootstrapSha256 ("B" * 64) `
            -OutputPath $output
        $text = (Get-Content -LiteralPath $output -Raw).Trim()

        ($text -split "`n").Count | Should Be 1
        $text | Should Match 'Get-FileHash'
        $text | Should Match 'weflow-chat-0\.1\.0-install\.ps1'
        $text | Should Match 'weflow-chat-0\.1\.0-win-x64\.zip'
        $text | Should Not Match 'Invoke-Expression|\biex\b|ScriptBlock]::Create'
        $text.IndexOf("Get-FileHash") -lt $text.IndexOf("& `$p") |
            Should Be $true
    }
}
