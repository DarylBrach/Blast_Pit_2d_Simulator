[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Contract
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Schema = 'blast-pit.acl-lease-contract.v1'
$SnapshotSchema = 'blast-pit.acl-root-snapshot.v1'
$LimitingMask = [int64]0x1201bf
$Sections = [System.Security.AccessControl.AccessControlSections]'Access, Owner, Group'
$MaxContractBytes = 1048576

function Convert-ToCanonicalJson([object]$Value) {
    return ($Value | ConvertTo-Json -Depth 12 -Compress)
}

function Get-Sha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Assert-ExactProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) {
        throw "$Label properties do not match the fixed contract"
    }
}

function Resolve-SafeDirectory([string]$RawPath, [string]$RawParent) {
    if (-not [System.IO.Path]::IsPathRooted($RawPath) -or -not [System.IO.Path]::IsPathRooted($RawParent)) {
        throw 'ACL root and authorized parent must be absolute'
    }
    $path = [System.IO.Path]::GetFullPath($RawPath).TrimEnd('\')
    $parent = [System.IO.Path]::GetFullPath($RawParent).TrimEnd('\')
    if ($path.Length -le $parent.Length -or -not $path.StartsWith($parent + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'ACL root is outside the authorized parent'
    }
    if ($path -eq [System.IO.Path]::GetPathRoot($path).TrimEnd('\')) {
        throw 'filesystem roots cannot be ACL lease roots'
    }
    if (-not [System.IO.Directory]::Exists($path) -or -not [System.IO.Directory]::Exists($parent)) {
        throw 'ACL root or authorized parent is missing'
    }
    $cursor = New-Object System.IO.DirectoryInfo($path)
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse-point ACL path is forbidden: $($cursor.FullName)"
        }
        if ($cursor.FullName.TrimEnd('\') -ieq $parent) { break }
        $cursor = $cursor.Parent
    }
    if ($null -eq $cursor) { throw 'authorized parent is not an ACL root ancestor' }
    return $path
}

function Get-RuleRows([System.Security.AccessControl.DirectorySecurity]$Acl) {
    $rows = @()
    foreach ($rule in $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $rows += [ordered]@{
            sid = $rule.IdentityReference.Value
            rights = [int64]$rule.FileSystemRights
            access_type = [string]$rule.AccessControlType
            inheritance_flags = [string]$rule.InheritanceFlags
            propagation_flags = [string]$rule.PropagationFlags
            inherited = [bool]$rule.IsInherited
        }
    }
    return @($rows | Sort-Object sid, rights, access_type, inheritance_flags, propagation_flags, inherited)
}

function Get-Snapshot([string]$Root, [string]$Parent) {
    $acl = Get-Acl -LiteralPath $Root
    $sddl = $acl.GetSecurityDescriptorSddlForm($Sections)
    return [ordered]@{
        schema_version = $SnapshotSchema
        root = $Root
        authorized_parent = $Parent
        sddl = $sddl
        sddl_sha256 = Get-Sha256 $sddl
        owner = $acl.Owner
        group = $acl.Group
        access_rules_protected = [bool]$acl.AreAccessRulesProtected
        rules = @(Get-RuleRows $acl)
    }
}

function Assert-Empty([string]$Root) {
    $enumerator = [System.IO.Directory]::EnumerateFileSystemEntries($Root).GetEnumerator()
    try {
        if ($enumerator.MoveNext()) { throw 'ACL lease root must be empty' }
    } finally {
        if ($enumerator -is [System.IDisposable]) { $enumerator.Dispose() }
    }
}

function Rule-Key([object]$Rule) {
    return @($Rule.sid, $Rule.rights, $Rule.access_type, $Rule.inheritance_flags, $Rule.propagation_flags, $Rule.inherited) -join '|'
}

function Get-AddedRules([object[]]$Baseline, [object[]]$Current) {
    $remaining = New-Object 'System.Collections.Generic.List[string]'
    foreach ($row in $Baseline) { [void]$remaining.Add((Rule-Key $row)) }
    $added = @()
    foreach ($row in $Current) {
        $key = Rule-Key $row
        $index = $remaining.IndexOf($key)
        if ($index -ge 0) {
            $remaining.RemoveAt($index)
        } else {
            $added += $row
        }
    }
    if ($remaining.Count -ne 0) {
        throw 'ACL rule multiset removed or changed a baseline rule'
    }
    return @($added)
}

function Get-LimitingSid([object]$Request, [System.Security.AccessControl.DirectorySecurity]$Acl) {
    if ($Acl.Owner -cne [string]$Request.snapshot.owner -or $Acl.Group -cne [string]$Request.snapshot.group -or
        [bool]$Acl.AreAccessRulesProtected -ne [bool]$Request.snapshot.access_rules_protected) {
        throw 'sandbox ACL materialization changed owner, group, or protection state'
    }
    $currentRows = @(Get-RuleRows $Acl)
    $delta = @(Get-AddedRules @($Request.snapshot.rules) $currentRows)
    if ($delta.Count -ne 1) {
        throw 'sandbox ACL delta must be exactly one added rule'
    }
    $candidate = $delta[0]
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUserSid = $currentIdentity.User.Value
    $tokenSids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    [void]$tokenSids.Add($currentUserSid)
    foreach ($group in $currentIdentity.Groups) { [void]$tokenSids.Add($group.Value) }
    $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    $groupSid = $Acl.GetGroup([System.Security.Principal.SecurityIdentifier]).Value
    if ($candidate.access_type -ne 'Allow' -or [int64]$candidate.rights -ne $LimitingMask -or
        $candidate.inherited -or $candidate.inheritance_flags -notmatch 'ContainerInherit' -or
        $candidate.inheritance_flags -notmatch 'ObjectInherit' -or $candidate.propagation_flags -ne 'None' -or
        $candidate.sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$' -or
        $candidate.sid -ceq $ownerSid -or $candidate.sid -ceq $groupSid -or $tokenSids.Contains([string]$candidate.sid)) {
        throw 'sandbox limiting SID rule is not the exact fixed materialization delta'
    }
    $restrictedSid = New-Object System.Security.Principal.SecurityIdentifier([string]$candidate.sid)
    try {
        [void]$restrictedSid.Translate([System.Security.Principal.NTAccount])
        throw 'sandbox limiting SID unexpectedly resolves to an account'
    } catch [System.Security.Principal.IdentityNotMappedException] {
        # Expected for the restricted-token SID.
    }
    return [ordered]@{ sid = $restrictedSid; delta = $delta; rows = $currentRows }
}

$contractPath = [System.IO.Path]::GetFullPath($Contract)
$contractInfo = Get-Item -LiteralPath $contractPath -Force
if (-not $contractInfo.PSIsContainer -and $contractInfo.Length -le $MaxContractBytes -and ($contractInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
    $contractLength = $contractInfo.Length
    $contractWriteTime = $contractInfo.LastWriteTimeUtc.Ticks
    $request = Get-Content -LiteralPath $contractPath -Raw -Encoding UTF8 | ConvertFrom-Json
} else {
    throw 'ACL contract is missing, oversized, or unsafe'
}
Assert-ExactProperties $request @('schema_version', 'operation', 'lease_id', 'root', 'authorized_parent', 'control_dir', 'snapshot', 'restricted_sid') 'ACL contract'
if ($request.schema_version -cne $Schema -or $request.lease_id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') {
    throw 'ACL contract identity is invalid'
}
if ($request.operation -notin @('snapshot', 'discover', 'upgrade', 'restore', 'verify')) {
    throw 'ACL contract operation is invalid'
}
$controlDir = [System.IO.Path]::GetFullPath([string]$request.control_dir).TrimEnd('\')
if (-not [System.IO.Directory]::Exists($controlDir) -or
    [System.IO.Path]::GetDirectoryName($contractPath).TrimEnd('\') -ine $controlDir) {
    throw 'ACL contract is outside the fixed control directory'
}
$cursor = (Get-Item -LiteralPath $contractPath -Force).Directory
while ($null -ne $cursor) {
    if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "reparse-point ACL contract path is forbidden: $($cursor.FullName)"
    }
    if ($cursor.FullName.TrimEnd('\') -ieq $controlDir) { break }
    $cursor = $cursor.Parent
}
if ($null -eq $cursor) { throw 'ACL contract control-directory ancestry is invalid' }
$contractAfter = Get-Item -LiteralPath $contractPath -Force
if ($contractAfter.Length -ne $contractLength -or $contractAfter.LastWriteTimeUtc.Ticks -ne $contractWriteTime) {
    throw 'ACL contract changed while it was read'
}
$parent = [System.IO.Path]::GetFullPath([string]$request.authorized_parent).TrimEnd('\')
$root = Resolve-SafeDirectory ([string]$request.root) $parent

if ($request.operation -eq 'snapshot') {
    if ($null -ne $request.snapshot -or $null -ne $request.restricted_sid) { throw 'snapshot operation received mutable fields' }
    Assert-Empty $root
    $result = [ordered]@{
        schema_version = 'blast-pit.acl-helper-result.v1'
        operation = 'snapshot'
        lease_id = $request.lease_id
        pass = $true
        snapshot = Get-Snapshot $root $parent
        restricted_sid = $null
    }
    Write-Output (Convert-ToCanonicalJson $result)
    exit 0
}

if ($null -eq $request.snapshot) { throw 'ACL snapshot is required' }
Assert-ExactProperties $request.snapshot @('schema_version', 'root', 'authorized_parent', 'sddl', 'sddl_sha256', 'owner', 'group', 'access_rules_protected', 'rules') 'ACL snapshot'
if ($request.snapshot.schema_version -cne $SnapshotSchema -or [string]$request.snapshot.root -cne $root -or [string]$request.snapshot.authorized_parent -cne $parent) {
    throw 'ACL snapshot path binding is invalid'
}
if ((Get-Sha256 ([string]$request.snapshot.sddl)) -cne [string]$request.snapshot.sddl_sha256) {
    throw 'ACL snapshot hash is invalid'
}

if ($request.operation -in @('discover', 'upgrade')) {
    Assert-Empty $root
    $currentAcl = Get-Acl -LiteralPath $root
    $limiting = Get-LimitingSid $request $currentAcl
    $restrictedSid = $limiting.sid
    $delta = @($limiting.delta)
    if ($request.operation -eq 'discover') {
        if ($null -ne $request.restricted_sid) { throw 'discover does not accept a restricted SID' }
        $result = [ordered]@{
            schema_version = 'blast-pit.acl-helper-result.v1'
            operation = 'discover'
            lease_id = $request.lease_id
            pass = $true
            snapshot = $request.snapshot
            restricted_sid = $restrictedSid.Value
            materialized_delta = $delta
        }
        Write-Output (Convert-ToCanonicalJson $result)
        exit 0
    }
    if ($null -eq $request.restricted_sid -or [string]$request.restricted_sid -cne $restrictedSid.Value) {
        throw 'upgrade restricted SID does not match the discovered materialization SID'
    }
    $deleteRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $restrictedSid,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$currentAcl.AddAccessRule($deleteRule)
    Set-Acl -LiteralPath $root -AclObject $currentAcl
    $after = Get-Acl -LiteralPath $root
    $afterRows = @(Get-RuleRows $after)
    $upgradeDelta = @(Get-AddedRules @($limiting.rows) $afterRows)
    $deleteRows = @($afterRows | Where-Object {
        $_.sid -ceq $restrictedSid.Value -and -not $_.inherited -and $_.access_type -eq 'Allow' -and
        ([int64]$_.rights -band [int64][System.Security.AccessControl.FileSystemRights]::Delete) -ne 0 -and
        $_.inheritance_flags -match 'ContainerInherit' -and $_.inheritance_flags -match 'ObjectInherit' -and
        $_.propagation_flags -eq 'InheritOnly'
    })
    $rootDeleteRows = @($afterRows | Where-Object {
        $_.sid -ceq $restrictedSid.Value -and -not $_.inherited -and $_.access_type -eq 'Allow' -and
        ([int64]$_.rights -band [int64][System.Security.AccessControl.FileSystemRights]::Delete) -ne 0 -and
        $_.propagation_flags -ne 'InheritOnly'
    })
    $dangerousRows = @($afterRows | Where-Object {
        $_.sid -ceq $restrictedSid.Value -and -not $_.inherited -and
        (([int64]$_.rights -band [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions) -ne 0 -or
         ([int64]$_.rights -band [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership) -ne 0)
    })
    if ($upgradeDelta.Count -ne 1 -or $deleteRows.Count -ne 1 -or
        (Rule-Key $upgradeDelta[0]) -cne (Rule-Key $deleteRows[0]) -or
        $rootDeleteRows.Count -ne 0 -or $dangerousRows.Count -ne 0 -or
        $after.Owner -cne [string]$request.snapshot.owner -or $after.Group -cne [string]$request.snapshot.group -or
        [bool]$after.AreAccessRulesProtected -ne [bool]$request.snapshot.access_rules_protected) {
        throw 'ACL child-delete rule is broader than the fixed policy'
    }
    $result = [ordered]@{
        schema_version = 'blast-pit.acl-helper-result.v1'
        operation = 'upgrade'
        lease_id = $request.lease_id
        pass = $true
        snapshot = $request.snapshot
        restricted_sid = $restrictedSid.Value
        materialized_delta = $delta
        upgraded_sddl_sha256 = Get-Sha256 ($after.GetSecurityDescriptorSddlForm($Sections))
    }
    Write-Output (Convert-ToCanonicalJson $result)
    exit 0
}

$restricted = $null
if ($null -ne $request.restricted_sid) {
    if ([string]$request.restricted_sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
        throw 'restore/verify restricted SID is invalid'
    }
    $restricted = New-Object System.Security.Principal.SecurityIdentifier([string]$request.restricted_sid)
}

if ($request.operation -eq 'restore') {
    Assert-Empty $root
    $acl = Get-Acl -LiteralPath $root
    $acl.SetSecurityDescriptorSddlForm([string]$request.snapshot.sddl, $Sections)
    Set-Acl -LiteralPath $root -AclObject $acl
}

$verified = Get-Snapshot $root $parent
if ($verified.sddl_sha256 -cne [string]$request.snapshot.sddl_sha256 -or $verified.sddl -cne [string]$request.snapshot.sddl) {
    throw 'ACL baseline restoration verification failed'
}
foreach ($rule in $verified.rules) {
    if ($null -ne $restricted -and $rule.sid -ceq $restricted.Value) { throw 'restricted SID remains after ACL restoration' }
}
$result = [ordered]@{
    schema_version = 'blast-pit.acl-helper-result.v1'
    operation = [string]$request.operation
    lease_id = $request.lease_id
    pass = $true
    snapshot = $verified
    restricted_sid = if ($null -eq $restricted) { $null } else { $restricted.Value }
}
Write-Output (Convert-ToCanonicalJson $result)
exit 0
