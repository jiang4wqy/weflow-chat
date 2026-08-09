Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module "$PSScriptRoot\..\WeFlowVssHelper.psm1" -Force

Describe "protected ownership journal" {
    It "exports only the approved public interface" {
        $expected = @(
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
        ) | Sort-Object
        $actual = @(
            (Get-Module WeFlowVssHelper).ExportedFunctions.Keys |
                Sort-Object
        )

        @(Compare-Object $expected $actual).Count | Should Be 0
    }

    It "restricts the production ACL to current user and SYSTEM" {
        $root = Join-Path $TestDrive "real-acl"
        Initialize-JournalRootAcl -Root $root
        $security = [IO.Directory]::GetAccessControl($root)
        $security.AreAccessRulesProtected | Should Be $true
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $system = (New-Object Security.Principal.SecurityIdentifier(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null)).Value
        $allowSids = @($security.GetAccessRules(
            $true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq "Allow" } |
            ForEach-Object { $_.IdentityReference.Value } |
            Sort-Object -Unique)
        @(Compare-Object @($current, $system) $allowSids).Count | Should Be 0
        { Assert-JournalRootAcl -Root $root } | Should Not Throw
    }

    It "is idempotent only while the existing ACL remains exact" {
        $root = Join-Path $TestDrive "idempotent-acl"
        Initialize-JournalRootAcl -Root $root
        { Initialize-JournalRootAcl -Root $root } | Should Not Throw

        $security = [IO.Directory]::GetAccessControl($root)
        $administrators = New-Object Security.Principal.SecurityIdentifier(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
            $null)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $administrators,
            [Security.AccessControl.FileSystemRights]::Read,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
        [IO.Directory]::SetAccessControl($root, $security)

        { Initialize-JournalRootAcl -Root $root } |
            Should Throw "journal_acl_unexpected_rule"
    }

    It "rejects partial, deny, and wrong-inheritance ACE tuples" {
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $cases = @(
            @{
                Rights = [Security.AccessControl.FileSystemRights]::Read
                Inheritance = [Security.AccessControl.InheritanceFlags]::None
                Propagation = [Security.AccessControl.PropagationFlags]::None
                Type = [Security.AccessControl.AccessControlType]::Allow
            },
            @{
                Rights = [Security.AccessControl.FileSystemRights]::Read
                Inheritance = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                Propagation = [Security.AccessControl.PropagationFlags]::None
                Type = [Security.AccessControl.AccessControlType]::Deny
            },
            @{
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
                Inheritance = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                Propagation = [Security.AccessControl.PropagationFlags]::InheritOnly
                Type = [Security.AccessControl.AccessControlType]::Allow
            }
        )
        for ($index = 0; $index -lt $cases.Count; $index++) {
            $root = Join-Path $TestDrive ("tuple-drift-" + $index)
            Initialize-JournalRootAcl -Root $root
            $security = [IO.Directory]::GetAccessControl($root)
            $originalSddl = $security.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::Access)
            $case = $cases[$index]
            $existingRules = @($security.GetAccessRules(
                $true, $false, [Security.Principal.SecurityIdentifier]))
            foreach ($existingRule in $existingRules) {
                if ($existingRule.IdentityReference.Value -eq $current.Value) {
                    $security.RemoveAccessRuleSpecific($existingRule)
                }
            }
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $current, $case.Rights, $case.Inheritance,
                $case.Propagation, $case.Type)
            $security.AddAccessRule($rule)
            try {
                [IO.Directory]::SetAccessControl($root, $security)
                { Assert-JournalRootAcl -Root $root } |
                    Should Throw "journal_acl_unexpected_rule"
            } finally {
                $restored = New-Object Security.AccessControl.DirectorySecurity
                $restored.SetSecurityDescriptorSddlForm(
                    $originalSddl,
                    [Security.AccessControl.AccessControlSections]::Access)
                [IO.Directory]::SetAccessControl($root, $restored)
            }
        }
    }

    It "initializes the ACL before creating the first journal" {
        $root = Join-Path $TestDrive "journals"
        $order = New-Object System.Collections.Generic.List[string]
        $aclInitializer = {
            param($path)
            $order.Add("acl")
            [IO.Directory]::CreateDirectory($path) | Out-Null
        }.GetNewClosure()

        $path = New-OwnershipJournal `
            -Root $root `
            -RunId "11111111-1111-1111-1111-111111111111" `
            -SourceVolume "F:\" `
            -AclInitializer $aclInitializer

        $order.Count | Should Be 1
        $order[0] | Should Be "acl"
        Test-Path -LiteralPath $path | Should Be $true
    }

    It "uses only the approved transition graph" {
        $root = Join-Path $TestDrive "graph"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        $runId = "11111111-1111-1111-1111-111111111111"
        New-OwnershipJournal -Root $root -RunId $runId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null

        { Set-OwnershipJournal -Root $root -RunId $runId `
              -State "adopted" } | Should Throw "invalid_journal_transition"

        Set-OwnershipJournal -Root $root -RunId $runId `
            -State "created" `
            -VolumeDeviceId "\\?\Volume{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}\" `
            -ShadowId "{22222222-2222-2222-2222-222222222222}" `
            -DeviceObject "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99" | Out-Null
        Set-OwnershipJournal -Root $root -RunId $runId `
            -State "adopted" | Out-Null
        Set-OwnershipJournal -Root $root -RunId $runId `
            -State "deleted" | Out-Null

        { Set-OwnershipJournal -Root $root -RunId $runId `
              -State "created" } | Should Throw "invalid_journal_transition"
    }

    It "allows created to transition directly to deleted" {
        $root = Join-Path $TestDrive "created-delete"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        $runId = "11111111-1111-1111-1111-111111111111"
        New-OwnershipJournal -Root $root -RunId $runId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        Set-OwnershipJournal -Root $root -RunId $runId `
            -State "created" `
            -VolumeDeviceId "\\?\Volume{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}\" `
            -ShadowId "{22222222-2222-2222-2222-222222222222}" `
            -DeviceObject "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99" | Out-Null
        Set-OwnershipJournal -Root $root -RunId $runId `
            -State "deleted" | Out-Null
        (Read-OwnershipJournal -Root $root -RunId $runId).state |
            Should Be "deleted"
    }

    It "pins the native durability flags used by production" {
        [WeFlowRecovery.JournalDurability]::PublishFlags | Should Be 9
        [WeFlowRecovery.JournalDurability]::DirectoryOpenFlags |
            Should Be 35651584
    }

    It "publishes in the same directory before flushing that directory" {
        InModuleScope WeFlowVssHelper {
            $root = Join-Path $TestDrive "durable-order"
            [IO.Directory]::CreateDirectory($root) | Out-Null
            $path = Join-Path $root "journal.json"
            $events = New-Object System.Collections.Generic.List[string]
            $publish = {
                param($temporary, $destination)
                (Split-Path -Parent $temporary) | Should Be (
                    Split-Path -Parent $destination)
                $events.Add("publish") | Out-Null
                [IO.File]::Move($temporary, $destination)
            }.GetNewClosure()
            $flushDirectory = {
                param($directory)
                $events.Add("flush-directory") | Out-Null
                $directory | Should Be $root
                Test-Path -LiteralPath $path -PathType Leaf | Should Be $true
            }.GetNewClosure()

            Write-JournalAtomic -Path $path -Value @{ version = 1 } `
                -PublishJournal $publish -FlushDirectory $flushDirectory

            $events.Count | Should Be 2
            $events[0] | Should Be "publish"
            $events[1] | Should Be "flush-directory"
        }
    }

    It "fails closed when write-through publication or directory flush fails" {
        InModuleScope WeFlowVssHelper {
            $root = Join-Path $TestDrive "durability-faults"
            [IO.Directory]::CreateDirectory($root) | Out-Null
            $publishPath = Join-Path $root "publish-fails.json"
            $counter = [pscustomobject]@{ FlushCalls = 0 }
            { Write-JournalAtomic -Path $publishPath `
                  -Value @{ version = 1 } `
                  -PublishJournal { throw "synthetic_publish_failure" } `
                  -FlushDirectory { $counter.FlushCalls += 1 } } |
                Should Throw "synthetic_publish_failure"
            $counter.FlushCalls | Should Be 0
            Test-Path -LiteralPath $publishPath | Should Be $false

            $flushPath = Join-Path $root "directory-flush-fails.json"
            { Write-JournalAtomic -Path $flushPath `
                  -Value @{ version = 1 } `
                  -PublishJournal {
                      param($temporary, $destination)
                      [IO.File]::Move($temporary, $destination)
                  } `
                  -FlushDirectory {
                      throw "synthetic_directory_flush_failure"
                  } } | Should Throw "synthetic_directory_flush_failure"
            Test-Path -LiteralPath $flushPath -PathType Leaf | Should Be $true
            @(Get-ChildItem -LiteralPath $root -Filter ".journal.*").Count |
                Should Be 0
        }
    }
}

Describe "exact owned shadow lifecycle" {
    BeforeEach {
        $script:RunId = "11111111-1111-1111-1111-111111111111"
        $script:ShadowId = "{22222222-2222-2222-2222-222222222222}"
        $script:VolumeId = "\\?\Volume{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}\"
        $script:Device = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"
    }

    It "durably prepares the secured creating intent without WMI" {
        $root = Join-Path $TestDrive "prepare"
        $order = New-Object System.Collections.Generic.List[string]
        $acl = {
            param($path)
            $order.Add("acl")
            [IO.Directory]::CreateDirectory($path) | Out-Null
        }.GetNewClosure()

        $prepared = Prepare-OwnedShadowCreate -Root $root `
            -RunId $script:RunId -SourceVolume "F:\" `
            -AclInitializer $acl

        $order.Count | Should Be 1
        $order[0] | Should Be "acl"
        $prepared.state | Should Be "creating"
        $prepared.sourceVolume | Should Be "F:\"
        $prepared.shadowId | Should Be $null
        $prepared.deviceObject | Should Be $null
        $prepared.volumeDeviceId | Should Be $null
    }

    It "consumes the exact prepared intent before WMI create" {
        $root = Join-Path $TestDrive "order"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        $runId = $script:RunId
        $shadowId = $script:ShadowId
        $volumeId = $script:VolumeId
        $device = $script:Device
        $order = New-Object System.Collections.Generic.List[string]
        $order.Add("prepared")
        $create = {
            param($volume)
            $order.Add("create") | Out-Null
            $journal = Get-Content -Raw -LiteralPath (
                Join-Path $root ($runId + ".json")) | ConvertFrom-Json
            $journal.state | Should Be "creating" | Out-Null
            [pscustomobject]@{ ReturnValue=0; ShadowID=$shadowId }
        }.GetNewClosure()
        $find = {
            param($id)
            [pscustomobject]@{
                ID=$shadowId; VolumeName=$volumeId
                DeviceObject=$device
            }
        }.GetNewClosure()

        New-OwnedShadow -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" `
            -ResolveVolume { param($volume) $script:VolumeId } `
            -CreateShadow $create -FindShadow $find | Out-Null

        $order[0] | Should Be "prepared"
        $order[1] | Should Be "create"
        (Read-OwnershipJournal -Root $root -RunId $script:RunId).state |
            Should Be "created"
    }

    It "touches no WMI adapter without an exact creating intent" {
        foreach ($fault in @("missing", "wrong-source", "wrong-state")) {
            $root = Join-Path $TestDrive ("not-prepared-" + $fault)
            $acl = {
                param($path) [IO.Directory]::CreateDirectory($path) | Out-Null
            }
            if ($fault -eq "wrong-source") {
                Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
                    -SourceVolume "E:\" -AclInitializer $acl | Out-Null
            }
            if ($fault -eq "wrong-state") {
                Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
                    -SourceVolume "F:\" -AclInitializer $acl | Out-Null
                Set-OwnershipJournal -Root $root -RunId $script:RunId `
                    -State created -VolumeDeviceId $script:VolumeId `
                    -ShadowId $script:ShadowId `
                    -DeviceObject $script:Device | Out-Null
            }
            $calls = [pscustomobject]@{ Resolve = 0; Create = 0; Find = 0 }
            { New-OwnedShadow -Root $root -RunId $script:RunId `
                  -SourceVolume "F:\" `
                  -ResolveVolume { $calls.Resolve += 1; $script:VolumeId } `
                  -CreateShadow { $calls.Create += 1; throw "must_not_run" } `
                  -FindShadow { $calls.Find += 1; throw "must_not_run" } } |
                Should Throw "shadow_create_not_prepared"
            $calls.Resolve | Should Be 0
            $calls.Create | Should Be 0
            $calls.Find | Should Be 0
        }
    }

    It "rejects duplicate keys and wrong primitive types before WMI" {
        foreach ($fault in @(
            "duplicate", "escaped-key", "version-bool", "version-string", "run-number",
            "source-number",
            "state-number", "timestamp-noncanonical"
        )) {
            $root = Join-Path $TestDrive ("malformed-" + $fault)
            $acl = {
                param($path) [IO.Directory]::CreateDirectory($path) | Out-Null
            }
            Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
                -SourceVolume "F:\" -AclInitializer $acl | Out-Null
            $path = Join-Path $root ($script:RunId + ".json")
            $raw = Get-Content -Raw -LiteralPath $path
            if ($fault -eq "duplicate") {
                $raw = $raw -replace '"version"\s*:\s*1',
                    '"version":1,"version":1'
            } elseif ($fault -eq "escaped-key") {
                $raw = $raw.Replace('"version"', '"\u0076ersion"')
            } else {
                $value = $raw | ConvertFrom-Json
                if ($fault -eq "version-bool") { $value.version = $true }
                if ($fault -eq "version-string") { $value.version = "1" }
                if ($fault -eq "run-number") { $value.runId = 7 }
                if ($fault -eq "source-number") { $value.sourceVolume = 7 }
                if ($fault -eq "state-number") { $value.state = 7 }
                if ($fault -eq "timestamp-noncanonical") {
                    $value.updatedAtUtc = "2026-07-21T00:00:00Z"
                }
                $raw = $value | ConvertTo-Json -Compress
            }
            [IO.File]::WriteAllText(
                $path, $raw, (New-Object Text.UTF8Encoding($false)))
            $calls = [pscustomobject]@{ Resolve = 0; Create = 0; Find = 0 }
            { New-OwnedShadow -Root $root -RunId $script:RunId `
                  -SourceVolume "F:\" `
                  -ResolveVolume { $calls.Resolve += 1; $script:VolumeId } `
                  -CreateShadow { $calls.Create += 1; throw "must_not_run" } `
                  -FindShadow { $calls.Find += 1; throw "must_not_run" } } |
                Should Throw "shadow_create_not_prepared"
            $calls.Resolve | Should Be 0
            $calls.Create | Should Be 0
            $calls.Find | Should Be 0
        }
    }

    It "canonicalizes mixed-case IDs through create and exact delete" {
        $root = Join-Path $TestDrive "canonical-shadow-id"
        $mixed = "{abcdefab-cdef-abcd-efab-cdefabcdefab}"
        $canonical = "{ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB}"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        $volumeId = $script:VolumeId
        $device = $script:Device
        $state = [pscustomobject]@{ Present = $true; DeleteCalls = 0 }
        $find = {
            param($id)
            $id | Should Be $canonical | Out-Null
            if (-not $state.Present) { return $null }
            return [pscustomobject]@{
                ID=$mixed; VolumeName=$volumeId
                DeviceObject=$device
            }
        }.GetNewClosure()
        $created = New-OwnedShadow -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" `
            -ResolveVolume { param($volume) $script:VolumeId } `
            -CreateShadow { param($volume) [pscustomobject]@{
                ReturnValue=0; ShadowID=$mixed } } -FindShadow $find
        $created.shadowId | Should Be $canonical
        $delete = {
            param($shadow)
            $state.DeleteCalls += 1
            $state.Present = $false
        }.GetNewClosure()
        $deleted = Remove-OwnedShadowExact -Root $root `
            -RunId $script:RunId -ExpectedShadowId $mixed `
            -FindShadow $find -DeleteShadow $delete
        $state.DeleteCalls | Should Be 1
        $deleted.state | Should Be "deleted"
        $deleted.shadowId | Should Be $canonical
    }

    It "leaves creating without guessing after create fails" {
        $root = Join-Path $TestDrive "create-fails"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        { New-OwnedShadow -Root $root -RunId $script:RunId `
              -SourceVolume "F:\" `
              -ResolveVolume { param($volume) $script:VolumeId } `
              -CreateShadow { param($volume) throw "synthetic_create_failure" } `
              -FindShadow { throw "must_not_be_called" } } |
            Should Throw "synthetic_create_failure"
        (Get-OwnedShadow -Root $root -RunId $script:RunId).state |
            Should Be "creating"
    }

    It "adopts and inspects from the strict journal without WMI" {
        $root = Join-Path $TestDrive "journal-only-normal-actions"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        New-OwnershipJournal -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State created -VolumeDeviceId $script:VolumeId `
            -ShadowId $script:ShadowId -DeviceObject $script:Device | Out-Null

        (Adopt-OwnedShadow -Root $root -RunId $script:RunId `
            -ExpectedShadowId $script:ShadowId).state | Should Be "adopted"
        $inspected = Get-OwnedShadow -Root $root -RunId $script:RunId
        $inspected.state | Should Be "adopted"
        $inspected.shadowId | Should Be $script:ShadowId
        $inspected.deviceObject | Should Be $script:Device
    }

    It "keeps WMI commands out of Adopt and InspectOwned" {
        $tokens = $null
        $errors = $null
        $modulePath = Join-Path $PSScriptRoot "..\WeFlowVssHelper.psm1"
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $modulePath, [ref]$tokens, [ref]$errors)
        $errors.Count | Should Be 0
        foreach ($name in @(
            "Prepare-OwnedShadowCreate", "Adopt-OwnedShadow", "Get-OwnedShadow"
        )) {
            $function = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Where-Object { $_.Name -eq $name })
            $function.Count | Should Be 1
            @($function[0].Body.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -in @("Get-WmiObject", "Find-WmiShadow")
            }, $true)).Count | Should Be 0
        }
    }

    It "never deletes a shadow created before its ID was journaled" {
        $root = Join-Path $TestDrive "unknown-shadow"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        Prepare-OwnedShadowCreate -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        { New-OwnedShadow -Root $root -RunId $script:RunId `
              -SourceVolume "F:\" `
              -ResolveVolume { param($volume) $script:VolumeId } `
              -CreateShadow { param($volume) [pscustomobject]@{
                    ReturnValue=0; ShadowID=$script:ShadowId } } `
              -FindShadow { param($id) [pscustomobject]@{
                    ID=$script:ShadowId; VolumeName=$script:VolumeId
                    DeviceObject=$script:Device } } `
              -BeforeCreatedJournal { throw "synthetic_exit_before_id_flush" } } |
            Should Throw "synthetic_exit_before_id_flush"

        $deleteCalls = 0
        { Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
              -ExpectedShadowId $script:ShadowId `
              -FindShadow { throw "must_not_be_called" } `
              -DeleteShadow { $deleteCalls += 1 } } |
            Should Throw "shadow_identity_not_journaled"
        $deleteCalls | Should Be 0
    }

    It "deletes the exact object from created and marks deleted" {
        $root = Join-Path $TestDrive "delete-created"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        New-OwnershipJournal -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State created -VolumeDeviceId $script:VolumeId `
            -ShadowId $script:ShadowId -DeviceObject $script:Device | Out-Null
        $shadowId = $script:ShadowId
        $volumeId = $script:VolumeId
        $device = $script:Device
        $state = [pscustomobject]@{ Present = $true }
        $find = {
            param($id)
            if (-not $state.Present) { return $null }
            [pscustomobject]@{ ID=$shadowId; VolumeName=$volumeId
                              DeviceObject=$device }
        }.GetNewClosure()
        $delete = { param($shadow) $state.Present = $false }.GetNewClosure()
        Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
            -ExpectedShadowId $script:ShadowId `
            -FindShadow $find -DeleteShadow $delete | Out-Null
        (Read-OwnershipJournal -Root $root -RunId $script:RunId).state |
            Should Be "deleted"
    }

    It "deletes the exact object from adopted and marks deleted" {
        $root = Join-Path $TestDrive "delete-adopted"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        New-OwnershipJournal -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State created -VolumeDeviceId $script:VolumeId `
            -ShadowId $script:ShadowId -DeviceObject $script:Device | Out-Null
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State adopted | Out-Null
        $shadowId = $script:ShadowId
        $volumeId = $script:VolumeId
        $device = $script:Device
        $state = [pscustomobject]@{ Present = $true; DeleteCalls = 0 }
        $find = {
            param($id)
            if (-not $state.Present) { return $null }
            [pscustomobject]@{ ID=$shadowId; VolumeName=$volumeId
                              DeviceObject=$device }
        }.GetNewClosure()
        $delete = {
            param($shadow)
            $state.DeleteCalls += 1
            $state.Present = $false
        }.GetNewClosure()
        Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
            -ExpectedShadowId $script:ShadowId `
            -FindShadow $find -DeleteShadow $delete | Out-Null
        $state.DeleteCalls | Should Be 1
        (Read-OwnershipJournal -Root $root -RunId $script:RunId).state |
            Should Be "deleted"
    }

    It "refuses a requested ID that differs from the journal before WMI" {
        $root = Join-Path $TestDrive "delete-request-mismatch"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        $other = "{33333333-3333-3333-3333-333333333333}"
        New-OwnershipJournal -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State created -VolumeDeviceId $script:VolumeId `
            -ShadowId $script:ShadowId -DeviceObject $script:Device | Out-Null
        $findCalls = 0
        $deleteCalls = 0
        { Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
              -ExpectedShadowId $other `
              -FindShadow { $findCalls += 1; throw "must_not_be_called" } `
              -DeleteShadow { $deleteCalls += 1 } } |
            Should Throw "shadow_delete_not_owned"
        $findCalls | Should Be 0
        $deleteCalls | Should Be 0
    }

    It "refuses every existing-object identity mismatch without deletion" {
        $otherId = "{33333333-3333-3333-3333-333333333333}"
        $otherVolume = "\\?\Volume{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}\"
        $otherDevice = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy100"
        $cases = @(
            @{ Name="id"; Error="shadow_id_mismatch"; Shadow=[pscustomobject]@{
                ID=$otherId; VolumeName=$script:VolumeId; DeviceObject=$script:Device } },
            @{ Name="volume"; Error="shadow_volume_mismatch"; Shadow=[pscustomobject]@{
                ID=$script:ShadowId; VolumeName=$otherVolume; DeviceObject=$script:Device } },
            @{ Name="device"; Error="shadow_device_mismatch"; Shadow=[pscustomobject]@{
                ID=$script:ShadowId; VolumeName=$script:VolumeId; DeviceObject=$otherDevice } }
        )
        foreach ($case in $cases) {
            $root = Join-Path $TestDrive ("delete-mismatch-" + $case.Name)
            $acl = {
                param($path) [IO.Directory]::CreateDirectory($path) | Out-Null
            }
            New-OwnershipJournal -Root $root -RunId $script:RunId `
                -SourceVolume "F:\" -AclInitializer $acl | Out-Null
            Set-OwnershipJournal -Root $root -RunId $script:RunId `
                -State created -VolumeDeviceId $script:VolumeId `
                -ShadowId $script:ShadowId -DeviceObject $script:Device | Out-Null
            $counter = [pscustomobject]@{ DeleteCalls = 0 }
            $find = { param($id) return $case.Shadow }.GetNewClosure()
            $delete = {
                param($shadow) $counter.DeleteCalls += 1
            }.GetNewClosure()
            { Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
                  -ExpectedShadowId $script:ShadowId `
                  -FindShadow $find -DeleteShadow $delete } |
                Should Throw $case.Error
            $counter.DeleteCalls | Should Be 0
        }
    }

    It "refuses a missing exact object and treats deleted as WMI-free terminal" {
        $root = Join-Path $TestDrive "delete-missing"
        $acl = { param($path) [IO.Directory]::CreateDirectory($path) | Out-Null }
        New-OwnershipJournal -Root $root -RunId $script:RunId `
            -SourceVolume "F:\" -AclInitializer $acl | Out-Null
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State created -VolumeDeviceId $script:VolumeId `
            -ShadowId $script:ShadowId -DeviceObject $script:Device | Out-Null
        { Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
              -ExpectedShadowId $script:ShadowId `
              -FindShadow { param($id) return $null } `
              -DeleteShadow { throw "must_not_be_called" } } |
            Should Throw "owned_shadow_missing"
        Set-OwnershipJournal -Root $root -RunId $script:RunId `
            -State deleted | Out-Null
        $terminal = Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
            -ExpectedShadowId $script:ShadowId `
            -FindShadow { throw "must_not_be_called" } `
            -DeleteShadow { throw "must_not_be_called" }
        $terminal.state | Should Be "deleted"
        { Remove-OwnedShadowExact -Root $root -RunId $script:RunId `
              -ExpectedShadowId "{33333333-3333-3333-3333-333333333333}" `
              -FindShadow { throw "must_not_be_called" } `
              -DeleteShadow { throw "must_not_be_called" } } |
            Should Throw "shadow_delete_not_owned"
    }
}
