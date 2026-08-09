Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$bootstrap = Join-Path $PSScriptRoot "..\..\install.ps1"
. $bootstrap -Version "0.1.0" `
    -ArchiveUri "https://example.invalid/v0.1.0/weflow-chat-0.1.0-win-x64.zip" `
    -ArchiveSha256 ("A" * 64)

function New-BootstrapArchive {
    param(
        [Parameter(Mandatory)][string]$Parent,
        [string]$Version = "0.1.0"
    )
    $root = Join-Path $Parent "weflow-chat-$Version"
    $scripts = Join-Path $root "scripts"
    [IO.Directory]::CreateDirectory($scripts) | Out-Null
    Set-Content -LiteralPath (Join-Path $scripts "Install-WeFlowChat.ps1") `
        -Value "param()"
    $archive = Join-Path $Parent "weflow-chat-$Version-win-x64.zip"
    Compress-Archive -LiteralPath $root -DestinationPath $archive
    return $archive
}

Describe "verified online bootstrap" {
    It "contains no string-evaluation execution path" {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $bootstrap, [ref]$tokens, [ref]$errors)
        $errors.Count | Should Be 0
        $text = Get-Content -LiteralPath $bootstrap -Raw
        $text | Should Not Match 'Invoke-Expression|\biex\b|ScriptBlock]::Create'
        @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq "Invoke-Expression"
        }, $true)).Count | Should Be 0
    }

    It "checks the archive hash before extraction" {
        $archive = New-BootstrapArchive (Join-Path $TestDrive "valid")
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        $destination = Join-Path $TestDrive "expanded"

        $root = Expand-VerifiedWeFlowChatArchive -ArchivePath $archive `
            -ExpectedSha256 $hash -Destination $destination -Version "0.1.0"

        $root | Should Be (Join-Path $destination "weflow-chat-0.1.0")
        { Expand-VerifiedWeFlowChatArchive -ArchivePath $archive `
              -ExpectedSha256 ("0" * 64) `
              -Destination (Join-Path $TestDrive "must-not-exist") `
              -Version "0.1.0" } | Should Throw "archive_hash_mismatch"
        Test-Path -LiteralPath (Join-Path $TestDrive "must-not-exist") |
            Should Be $false
    }

    It "rejects archive traversal before writing any entry" {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archivePath = Join-Path $TestDrive "traversal.zip"
        $stream = [IO.File]::Open($archivePath, [IO.FileMode]::CreateNew)
        $archive = New-Object IO.Compression.ZipArchive(
            $stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $archive.CreateEntry(
                "weflow-chat-0.1.0/../escape.txt")
            $writer = New-Object IO.StreamWriter($entry.Open())
            try { $writer.Write("escape") } finally { $writer.Dispose() }
        } finally {
            $archive.Dispose()
            $stream.Dispose()
        }
        $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        $destination = Join-Path $TestDrive "traversal-output"

        { Expand-VerifiedWeFlowChatArchive -ArchivePath $archivePath `
              -ExpectedSha256 $hash -Destination $destination `
              -Version "0.1.0" } | Should Throw "archive_layout_invalid"
        Test-Path -LiteralPath $destination | Should Be $false
    }

    It "never invokes the package installer after a corrupt download" {
        $source = New-BootstrapArchive (Join-Path $TestDrive "download")
        $called = [pscustomobject]@{ Value = $false }
        $download = {
            param($uri, $path)
            Copy-Item -LiteralPath $source -Destination $path
        }.GetNewClosure()
        $install = {
            param($root) $called.Value = $true
        }.GetNewClosure()

        { Invoke-WeFlowChatBootstrap -Version "0.1.0" `
              -ArchiveUri "https://example.invalid/v0.1.0/weflow-chat-0.1.0-win-x64.zip" `
              -ArchiveSha256 ("0" * 64) -DownloadFile $download `
              -PackageInstaller $install } | Should Throw "archive_hash_mismatch"
        $called.Value | Should Be $false
    }
}
