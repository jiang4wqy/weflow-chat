Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:JournalRoot = "C:\ProgramData\WeFlowRecovery\shadows"
$script:States = @("creating", "created", "adopted", "deleted")
$script:JournalKeys = @(
    "version", "runId", "sourceVolume", "volumeDeviceId", "state",
    "shadowId", "deviceObject", "createdAtUtc", "updatedAtUtc"
)
$script:Transitions = @{
    creating = @("created")
    created  = @("adopted", "deleted")
    adopted  = @("deleted")
    deleted  = @()
}
$script:DeviceObjectPattern = '^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[1-9][0-9]*$'
$script:VolumeDevicePattern = '^\\\\\?\\Volume\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\$'

if ($null -eq ("WeFlowRecovery.JournalDurability" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WeFlowRecovery {
    public static class JournalDurability {
        public const uint PublishFlags = 0x00000001 | 0x00000008;
        public const uint DirectoryOpenFlags = 0x02000000 | 0x00200000;
        private const uint GenericWrite = 0x40000000;
        private const uint ShareReadWriteDelete = 0x00000007;
        private const uint OpenExisting = 3;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileExW(
            string existingName, string newName, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlushFileBuffers(SafeFileHandle handle);

        public static void Publish(string temporary, string destination) {
            if (!MoveFileExW(temporary, destination, PublishFlags)) {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(), "journal_publish_failed");
            }
        }

        public static void FlushDirectory(string directory) {
            using (SafeFileHandle handle = CreateFileW(
                directory, GenericWrite, ShareReadWriteDelete, IntPtr.Zero,
                OpenExisting, DirectoryOpenFlags, IntPtr.Zero)) {
                if (handle.IsInvalid) {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "journal_directory_open_failed");
                }
                if (!FlushFileBuffers(handle)) {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "journal_directory_flush_failed");
                }
            }
        }
    }
}
'@
}

function Assert-RunId {
    param([Parameter(Mandatory=$true)]$RunId)
    if ($RunId -isnot [string]) { throw "invalid_run_id" }
    $parsed = [guid]::Empty
    if (-not [guid]::TryParseExact($RunId, "D", [ref]$parsed) -or
        $RunId -cne $parsed.ToString("D")) {
        throw "invalid_run_id"
    }
}

function Assert-SourceVolume {
    param([Parameter(Mandatory=$true)]$SourceVolume)
    if ($SourceVolume -isnot [string] -or
        $SourceVolume -cnotmatch '^[A-Za-z]:\\$') {
        throw "invalid_source_volume"
    }
}

function ConvertTo-CanonicalShadowId {
    param([Parameter(Mandatory=$true)]$ShadowId)
    if ($ShadowId -isnot [string] -or
        $ShadowId -cnotmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
        throw "invalid_shadow_id"
    }
    $parsed = [guid]::Empty
    if (-not [guid]::TryParseExact($ShadowId, "B", [ref]$parsed)) {
        throw "invalid_shadow_id"
    }
    return $parsed.ToString("B").ToUpperInvariant()
}

function Assert-ShadowId {
    param([Parameter(Mandatory=$true)]$ShadowId)
    [void](ConvertTo-CanonicalShadowId $ShadowId)
}

function Assert-CanonicalUtcTimestamp {
    param([Parameter(Mandatory=$true)]$Value)
    if ($Value -isnot [string] -or
        $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') {
        throw "journal_timestamp_invalid"
    }
    $parsed = [DateTime]::MinValue
    $styles = ([Globalization.DateTimeStyles]::AssumeUniversal -bor
               [Globalization.DateTimeStyles]::AdjustToUniversal)
    if (-not [DateTime]::TryParseExact(
            $Value, "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            $styles, [ref]$parsed) -or
        $parsed.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'") -cne $Value) {
        throw "journal_timestamp_invalid"
    }
}

function Assert-DeviceObject {
    param([Parameter(Mandatory=$true)][string]$DeviceObject)
    if ($DeviceObject -notmatch $script:DeviceObjectPattern) {
        throw "invalid_device_object"
    }
}

function Assert-VolumeDeviceId {
    param([Parameter(Mandatory=$true)]$VolumeDeviceId)
    if ($VolumeDeviceId -isnot [string] -or
        $VolumeDeviceId -cnotmatch $script:VolumeDevicePattern) {
        throw "invalid_volume_device_id"
    }
}

function Assert-JournalRootAcl {
    param([string]$Root=$script:JournalRoot)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "journal_root_missing"
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) { throw "current_user_sid_missing" }
    $systemSid = New-Object Security.Principal.SecurityIdentifier(
        [Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $actual = [IO.Directory]::GetAccessControl($Root)
    if (-not $actual.AreAccessRulesProtected) {
        throw "journal_acl_not_protected"
    }
    $expectedSids = @($identity.User.Value, $systemSid.Value) |
        Sort-Object -Unique
    $rules = @($actual.GetAccessRules(
        $true, $true, [Security.Principal.SecurityIdentifier]))
    $expectedInheritance = [int](
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $expectedRights = [int64](
        [Security.AccessControl.FileSystemRights]::FullControl)
    $expectedTuples = @($expectedSids | ForEach-Object {
        @($_, "Allow", $expectedRights, $expectedInheritance, 0, $false) -join "|"
    } | Sort-Object)
    $actualTuples = @($rules | ForEach-Object {
        @(
            $_.IdentityReference.Value,
            $_.AccessControlType.ToString(),
            [int64]$_.FileSystemRights,
            [int]$_.InheritanceFlags,
            [int]$_.PropagationFlags,
            [bool]$_.IsInherited
        ) -join "|"
    } | Sort-Object)
    if ($rules.Count -ne 2 -or
        @(Compare-Object $expectedTuples $actualTuples).Count -ne 0) {
        throw "journal_acl_unexpected_rule"
    }
    return $actual
}

function Initialize-JournalRootAcl {
    param([string]$Root=$script:JournalRoot)
    if (Test-Path -LiteralPath $Root) {
        Assert-JournalRootAcl -Root $Root | Out-Null
        return
    }
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) { throw "current_user_sid_missing" }
    $systemSid = New-Object Security.Principal.SecurityIdentifier(
        [Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.User, $systemSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($Root, $security)
    Assert-JournalRootAcl -Root $Root | Out-Null
}

function Write-JournalAtomic {
    param([Parameter(Mandatory=$true)][string]$Path,
          [Parameter(Mandatory=$true)][hashtable]$Value,
          [scriptblock]$PublishJournal=${function:Publish-JournalWriteThrough},
          [scriptblock]$FlushDirectory=${function:Flush-JournalDirectory})
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "journal_root_missing"
    }
    $temporary = Join-Path $directory (".journal." + [guid]::NewGuid().ToString("N"))
    $json = $Value | ConvertTo-Json -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    try {
        $stream = [IO.File]::Open($temporary, "CreateNew", "Write", "None")
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        & $PublishJournal $temporary $Path
        & $FlushDirectory $directory
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Publish-JournalWriteThrough {
    param([Parameter(Mandatory=$true)][string]$Temporary,
          [Parameter(Mandatory=$true)][string]$Destination)
    [WeFlowRecovery.JournalDurability]::Publish($Temporary, $Destination)
}

function Flush-JournalDirectory {
    param([Parameter(Mandatory=$true)][string]$Directory)
    [WeFlowRecovery.JournalDurability]::FlushDirectory($Directory)
}

function ConvertTo-JournalHashtable {
    param([Parameter(Mandatory=$true)]$Value)
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object ($script:JournalKeys | Sort-Object) $actual).Count -ne 0) {
        throw "journal_schema_invalid"
    }
    if ($Value.version -isnot [int] -or $Value.version -ne 1) {
        throw "journal_version_invalid"
    }
    Assert-RunId $Value.runId
    Assert-SourceVolume $Value.sourceVolume
    if ($Value.state -isnot [string] -or
        $script:States -cnotcontains $Value.state) {
        throw "journal_state_invalid"
    }
    Assert-CanonicalUtcTimestamp $Value.createdAtUtc
    Assert-CanonicalUtcTimestamp $Value.updatedAtUtc
    $normalizedShadowId = $null
    if ($Value.state -eq "creating") {
        if ($null -ne $Value.shadowId -or $null -ne $Value.deviceObject -or
            $null -ne $Value.volumeDeviceId) {
            throw "creating_journal_has_identity"
        }
    } else {
        $normalizedShadowId = ConvertTo-CanonicalShadowId $Value.shadowId
        if ($Value.deviceObject -isnot [string]) {
            throw "invalid_device_object"
        }
        Assert-DeviceObject $Value.deviceObject
        Assert-VolumeDeviceId $Value.volumeDeviceId
    }
    return @{
        version=$Value.version; runId=$Value.runId
        sourceVolume=$Value.sourceVolume
        volumeDeviceId=$Value.volumeDeviceId; state=$Value.state
        shadowId=$normalizedShadowId; deviceObject=$Value.deviceObject
        createdAtUtc=$Value.createdAtUtc; updatedAtUtc=$Value.updatedAtUtc
    }
}

function Assert-JournalJsonHasExactKeys {
    param([Parameter(Mandatory=$true)][string]$Json)
    $matches = [regex]::Matches(
        $Json, '(?<!\\)"(?<key>(?:\\.|[^"\\])*)"\s*:')
    $rawKeys = @($matches | ForEach-Object { $_.Groups["key"].Value })
    $expectedKeys = @($script:JournalKeys | Sort-Object)
    $actualKeys = @($rawKeys | Sort-Object)
    $differences = @(Compare-Object $expectedKeys $actualKeys)
    if ($rawKeys.Count -ne $script:JournalKeys.Count -or
        $differences.Count -ne 0) {
        throw "journal_json_keys_invalid"
    }
}

function Read-OwnershipJournal {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId)
    Assert-RunId $RunId
    $path = Join-Path $Root ($RunId + ".json")
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "journal_missing"
    }
    $raw = Get-Content -Raw -LiteralPath $path
    Assert-JournalJsonHasExactKeys $raw
    $value = $raw | ConvertFrom-Json
    $journal = ConvertTo-JournalHashtable $value
    if ($journal.version -ne 1 -or $journal.runId -cne $RunId) {
        throw "journal_identity_invalid"
    }
    return $journal
}

function New-OwnershipJournal {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId,
          [Parameter(Mandatory=$true)][string]$SourceVolume,
          [scriptblock]$AclInitializer=${function:Initialize-JournalRootAcl})
    Assert-RunId $RunId
    Assert-SourceVolume $SourceVolume
    & $AclInitializer $Root
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "journal_acl_initialization_failed"
    }
    $path = Join-Path $Root ($RunId + ".json")
    if (Test-Path -LiteralPath $path) { throw "journal_exists" }
    $now = [DateTime]::UtcNow.ToString("o")
    $value = @{
        version=1; runId=$RunId; sourceVolume=$SourceVolume
        volumeDeviceId=$null; state="creating"; shadowId=$null
        deviceObject=$null; createdAtUtc=$now; updatedAtUtc=$now
    }
    Write-JournalAtomic -Path $path -Value $value
    return $path
}

function Set-OwnershipJournal {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId,
          [Parameter(Mandatory=$true)][ValidateSet("created","adopted","deleted")]
          [string]$State,
          [string]$VolumeDeviceId,
          [string]$ShadowId,
          [string]$DeviceObject)
    $current = Read-OwnershipJournal -Root $Root -RunId $RunId
    if ($script:Transitions[$current.state] -notcontains $State) {
        throw "invalid_journal_transition"
    }
    if ($State -eq "created") {
        $normalizedShadowId = ConvertTo-CanonicalShadowId $ShadowId
        Assert-DeviceObject $DeviceObject
        Assert-VolumeDeviceId $VolumeDeviceId
        $current.volumeDeviceId = $VolumeDeviceId
        $current.shadowId = $normalizedShadowId
        $current.deviceObject = $DeviceObject
    } else {
        if ($PSBoundParameters.ContainsKey("ShadowId") -or
            $PSBoundParameters.ContainsKey("DeviceObject") -or
            $PSBoundParameters.ContainsKey("VolumeDeviceId")) {
            throw "journal_identity_is_immutable"
        }
    }
    $current.state = $State
    $current.updatedAtUtc = [DateTime]::UtcNow.ToString("o")
    $path = Join-Path $Root ($RunId + ".json")
    Write-JournalAtomic -Path $path -Value $current
    return Read-OwnershipJournal -Root $Root -RunId $RunId
}

function Invoke-WmiCreateShadow {
    param([Parameter(Mandatory=$true)][string]$SourceVolume)
    return ([wmiclass]"Win32_ShadowCopy").Create(
        $SourceVolume, "ClientAccessible")
}

function Resolve-WmiVolumeDeviceId {
    param([Parameter(Mandatory=$true)][string]$SourceVolume)
    Assert-SourceVolume $SourceVolume
    $drive = $SourceVolume.Substring(0, 2)
    $escaped = $drive.Replace("'", "''")
    $items = @(Get-WmiObject -Class Win32_Volume `
        -Filter ("DriveLetter='" + $escaped + "'"))
    if ($items.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$items[0].DeviceID)) {
        throw "source_volume_not_unique"
    }
    return [string]$items[0].DeviceID
}

function Find-WmiShadow {
    param([Parameter(Mandatory=$true)][string]$ShadowId)
    $canonicalShadowId = ConvertTo-CanonicalShadowId $ShadowId
    $escaped = $canonicalShadowId.Replace("\\", "\\\\").Replace("'", "''")
    $items = @(Get-WmiObject -Class Win32_ShadowCopy `
        -Filter ("ID='" + $escaped + "'"))
    if ($items.Count -gt 1) { throw "shadow_id_not_unique" }
    if ($items.Count -eq 0) { return $null }
    return $items[0]
}

function Remove-WmiShadow {
    param([Parameter(Mandatory=$true)]$Shadow)
    $result = $Shadow.Delete()
    if ($null -ne $result -and $result.ReturnValue -ne 0) {
        throw "shadow_delete_failed"
    }
}

function Assert-ShadowMatchesJournal {
    param([Parameter(Mandatory=$true)][AllowNull()]$Shadow,
          [Parameter(Mandatory=$true)][hashtable]$Journal)
    if ($null -eq $Shadow) { throw "owned_shadow_missing" }
    $actualShadowId = ConvertTo-CanonicalShadowId ([string]$Shadow.ID)
    $journalShadowId = ConvertTo-CanonicalShadowId $Journal.shadowId
    if ($actualShadowId -cne $journalShadowId) {
        throw "shadow_id_mismatch"
    }
    if ([string]$Shadow.VolumeName -cne [string]$Journal.volumeDeviceId) {
        throw "shadow_volume_mismatch"
    }
    if ([string]$Shadow.DeviceObject -cne [string]$Journal.deviceObject) {
        throw "shadow_device_mismatch"
    }
    Assert-DeviceObject ([string]$Shadow.DeviceObject)
}

function Prepare-OwnedShadowCreate {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId,
          [Parameter(Mandatory=$true)][string]$SourceVolume,
          [scriptblock]$AclInitializer=${function:Initialize-JournalRootAcl})
    New-OwnershipJournal -Root $Root -RunId $RunId `
        -SourceVolume $SourceVolume -AclInitializer $AclInitializer | Out-Null
    $journal = Read-OwnershipJournal -Root $Root -RunId $RunId
    if ($journal.state -cne "creating" -or
        $journal.sourceVolume -cne $SourceVolume) {
        throw "shadow_create_prepare_failed"
    }
    return $journal
}

function New-OwnedShadow {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId,
          [Parameter(Mandatory=$true)][string]$SourceVolume,
          [scriptblock]$ResolveVolume=${function:Resolve-WmiVolumeDeviceId},
          [scriptblock]$CreateShadow=${function:Invoke-WmiCreateShadow},
          [scriptblock]$FindShadow=${function:Find-WmiShadow},
          [scriptblock]$BeforeCreatedJournal={})
    Assert-SourceVolume $SourceVolume
    try {
        $prepared = Read-OwnershipJournal -Root $Root -RunId $RunId
    } catch {
        throw "shadow_create_not_prepared"
    }
    if ($prepared.state -cne "creating" -or
        $prepared.sourceVolume -cne $SourceVolume -or
        $null -ne $prepared.volumeDeviceId -or
        $null -ne $prepared.shadowId -or
        $null -ne $prepared.deviceObject) {
        throw "shadow_create_not_prepared"
    }
    $volumeDeviceId = & $ResolveVolume $SourceVolume
    Assert-VolumeDeviceId $volumeDeviceId
    $created = & $CreateShadow $SourceVolume
    if ($null -eq $created -or [int]$created.ReturnValue -ne 0) {
        throw "shadow_create_failed"
    }
    $shadowId = ConvertTo-CanonicalShadowId ([string]$created.ShadowID)
    $shadow = & $FindShadow $shadowId
    if ($null -eq $shadow) { throw "created_shadow_missing" }
    Assert-DeviceObject ([string]$shadow.DeviceObject)
    if ((ConvertTo-CanonicalShadowId ([string]$shadow.ID)) -cne $shadowId -or
        [string]$shadow.VolumeName -cne [string]$volumeDeviceId) {
        throw "created_shadow_identity_mismatch"
    }
    & $BeforeCreatedJournal
    return Set-OwnershipJournal -Root $Root -RunId $RunId `
        -State "created" -VolumeDeviceId ([string]$volumeDeviceId) `
        -ShadowId $shadowId -DeviceObject ([string]$shadow.DeviceObject)
}

function Adopt-OwnedShadow {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId,
          [Parameter(Mandatory=$true)][string]$ExpectedShadowId)
    $canonicalExpectedId = ConvertTo-CanonicalShadowId $ExpectedShadowId
    $journal = Read-OwnershipJournal -Root $Root -RunId $RunId
    if ($journal.state -ne "created" -or
        $journal.shadowId -cne $canonicalExpectedId) {
        throw "shadow_not_adoptable"
    }
    return Set-OwnershipJournal -Root $Root -RunId $RunId -State "adopted"
}

function Get-OwnedShadow {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId)
    return Read-OwnershipJournal -Root $Root -RunId $RunId
}

function Remove-OwnedShadowExact {
    param([string]$Root=$script:JournalRoot,
          [Parameter(Mandatory=$true)][string]$RunId,
          [Parameter(Mandatory=$true)][string]$ExpectedShadowId,
          [scriptblock]$FindShadow=${function:Find-WmiShadow},
          [scriptblock]$DeleteShadow=${function:Remove-WmiShadow})
    $canonicalExpectedId = ConvertTo-CanonicalShadowId $ExpectedShadowId
    $journal = Read-OwnershipJournal -Root $Root -RunId $RunId
    if ($journal.state -eq "creating") {
        throw "shadow_identity_not_journaled"
    }
    if ($journal.shadowId -cne $canonicalExpectedId) {
        throw "shadow_delete_not_owned"
    }
    if ($journal.state -eq "deleted") { return $journal }
    if ($journal.state -notin @("created", "adopted")) {
        throw "shadow_delete_not_owned"
    }
    $shadow = & $FindShadow $canonicalExpectedId
    Assert-ShadowMatchesJournal -Shadow $shadow -Journal $journal
    & $DeleteShadow $shadow
    if ($null -ne (& $FindShadow $canonicalExpectedId)) {
        throw "shadow_delete_not_confirmed"
    }
    return Set-OwnershipJournal -Root $Root -RunId $RunId -State "deleted"
}

Export-ModuleMember -Function @(
    "Assert-JournalRootAcl"
    "Initialize-JournalRootAcl"
    "Assert-RunId"
    "Assert-SourceVolume"
    "ConvertTo-CanonicalShadowId"
    "Assert-ShadowId"
    "Assert-CanonicalUtcTimestamp"
    "Assert-DeviceObject"
    "Assert-VolumeDeviceId"
    "New-OwnershipJournal"
    "Read-OwnershipJournal"
    "Set-OwnershipJournal"
    "Prepare-OwnedShadowCreate"
    "Resolve-WmiVolumeDeviceId"
    "Find-WmiShadow"
    "New-OwnedShadow"
    "Adopt-OwnedShadow"
    "Get-OwnedShadow"
    "Remove-OwnedShadowExact"
)
