[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$ArchiveSha256,
    [Parameter(Mandatory)][string]$BootstrapSha256,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
    $ArchiveSha256 -notmatch '^[0-9A-F]{64}$' -or
    $BootstrapSha256 -notmatch '^[0-9A-F]{64}$') {
    throw "install_command_input_invalid"
}

$base = "https://github.com/$Repository/releases/download/v$Version"
$bootstrapName = "weflow-chat-$Version-install.ps1"
$archiveName = "weflow-chat-$Version-win-x64.zip"
$bootstrapUri = "$base/$bootstrapName"
$archiveUri = "$base/$archiveName"
$command = '$ErrorActionPreference=''Stop'';' +
    '$p=Join-Path ([IO.Path]::GetTempPath()) (''weflow-chat-''+[Guid]::NewGuid().ToString(''N'')+''.ps1'');' +
    'try{Invoke-WebRequest -UseBasicParsing -Uri ''' + $bootstrapUri + ''' -OutFile $p;' +
    'if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne ''' + $BootstrapSha256 + '''){throw ''bootstrap_hash_mismatch''};' +
    '& $p -Version ''' + $Version + ''' -ArchiveUri ''' + $archiveUri + ''' -ArchiveSha256 ''' + $ArchiveSha256 +
    '''}finally{if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Force}}'

[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName(
    [IO.Path]::GetFullPath($OutputPath))) | Out-Null
[IO.File]::WriteAllText(
    [IO.Path]::GetFullPath($OutputPath), $command + "`r`n", [Text.Encoding]::UTF8)
