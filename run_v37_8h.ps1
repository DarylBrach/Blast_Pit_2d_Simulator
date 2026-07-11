[CmdletBinding()]
param(
    [switch]$DryRun,
    [ValidateRange(1, 10000)][int]$Generations = 100,
    [string]$Python = 'E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe',
    [string]$ApprovalRecord = 'approval_v37_8h_001.json',
    [string]$AuditSeedFile = 'audit_seeds_v37_8h_001_committed.txt'
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$ExperimentId = 'robustness-v37-8h-001'
$ArtifactRoot = Join-Path $ProjectRoot 'artifacts\v37'
$ExperimentRoot = Join-Path $ArtifactRoot $ExperimentId
$Checkpoint = Join-Path $ExperimentRoot 'evolution_state_v37.npz'
$EvidenceRoot = Join-Path $ProjectRoot "run_evidence\$ExperimentId"
$KillSwitch = ".supervisor_stop.$ExperimentId"
$GracefulSeconds = 28200
$HardTimeoutSeconds = 28800

Set-Location -LiteralPath $ProjectRoot

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Configured Python does not exist: $Python"
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is required for the governed preflight.'
}
if (-not (Test-Path -LiteralPath '.git')) {
    throw 'This checkout is not a Git worktree. Clone or initialize the authorized repository first.'
}

$GitStatus = @(git status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Git status.' }
if ($GitStatus.Count -ne 0) {
    throw "Git worktree is not clean. Commit or intentionally remove changes before launch:`n$($GitStatus -join "`n")"
}

$ApprovalPath = Join-Path $ProjectRoot $ApprovalRecord
$AuditSeedPath = Join-Path $ProjectRoot $AuditSeedFile
if (-not (Test-Path -LiteralPath $ApprovalPath -PathType Leaf)) {
    throw "Missing scoped approval: $ApprovalPath. Create and review an exact approval for $ExperimentId; another experiment's approval is invalid."
}
if (-not (Test-Path -LiteralPath $AuditSeedPath -PathType Leaf)) {
    throw "Missing committed audit seed file: $AuditSeedPath"
}

$Approval = Get-Content -LiteralPath $ApprovalPath -Raw | ConvertFrom-Json
if ($Approval.experiment_id -ne $ExperimentId -or $Approval.status -ne 'approved' -or $Approval.authority -ne 'human-owner') {
    throw "Approval is not scoped to approved human-owner experiment $ExperimentId."
}
if ([int]$Approval.supervisor_hard_timeout_seconds -ne $HardTimeoutSeconds) {
    throw "Approval supervisor timeout does not match the governed $HardTimeoutSeconds-second ceiling."
}

$StopPath = Join-Path $ProjectRoot $KillSwitch
if (Test-Path -LiteralPath $StopPath) {
    throw "Stale scoped kill switch exists: $StopPath. Review its provenance, then remove it explicitly before launch."
}

New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$Stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$Preflight = Join-Path $EvidenceRoot "preflight-$Stamp"
New-Item -ItemType Directory -Force -Path $Preflight | Out-Null

$Commit = (git rev-parse HEAD).Trim()
$Remote = (git remote get-url origin 2>$null)
& $Python --version 2>&1 | Set-Content -LiteralPath (Join-Path $Preflight 'python-version.txt') -Encoding utf8
& $Python -m pip freeze | Set-Content -LiteralPath (Join-Path $Preflight 'requirements-lock.txt') -Encoding utf8

$HashInputs = @(
    'CodexLightRunner_v3.py', 'tmp_2d_simulator_v37.py', 'tmp_2d_simulator_v36.py',
    $ApprovalRecord, $AuditSeedFile, 'requirements.txt'
)
$Hashes = foreach ($Item in $HashInputs) {
    $Resolved = Join-Path $ProjectRoot $Item
    if (-not (Test-Path -LiteralPath $Resolved -PathType Leaf)) { throw "Required evidence input is missing: $Resolved" }
    Get-FileHash -LiteralPath $Resolved -Algorithm SHA256 | Select-Object Path, Algorithm, Hash
}
$Hashes | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $Preflight 'input-hashes.json') -Encoding utf8

$Mode = if (Test-Path -LiteralPath $Checkpoint -PathType Leaf) { 'continue' } else { 'train' }
$RequiredAction = if ($Mode -eq 'continue') { 'resume' } else { 'train' }
if (@($Approval.authorized_actions) -notcontains $RequiredAction) {
    throw "Approval does not authorize $RequiredAction for $ExperimentId."
}
$Metadata = [ordered]@{
    schema_version = 'blast-pit.v37.operator-preflight.v1'
    created_utc = (Get-Date).ToUniversalTime().ToString('o')
    experiment_id = $ExperimentId
    mode = $Mode
    git_commit = $Commit
    git_remote = $Remote
    git_clean = $true
    python = $Python
    graceful_runtime_seconds = $GracefulSeconds
    supervisor_timeout_seconds = $HardTimeoutSeconds
    kill_switch = $StopPath
    approval_record = $ApprovalPath
    audit_seed_file = $AuditSeedPath
    dry_run = [bool]$DryRun
}
$Metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Preflight 'preflight.json') -Encoding utf8

$TargetArgs = if ($Mode -eq 'continue') {
    @(
        'train', '--experiment-id', $ExperimentId,
        '--resume', $Checkpoint,
        '--source-v36', (Join-Path $ProjectRoot 'artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz'),
        '--audit-seed-file', $AuditSeedPath,
        '--artifact-root', $ArtifactRoot,
        '--approval-record', $ApprovalPath,
        '--generations', $Generations.ToString(),
        '--max-runtime-seconds', $GracefulSeconds.ToString(),
        '--runtime-grace-seconds', '300'
    )
} else {
    @(
        'train', '--experiment-id', $ExperimentId,
        '--source-v36', (Join-Path $ProjectRoot 'artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz'),
        '--audit-seed-file', $AuditSeedPath,
        '--artifact-root', $ArtifactRoot,
        '--approval-record', $ApprovalPath,
        '--generations', $Generations.ToString(),
        '--max-runtime-seconds', $GracefulSeconds.ToString(),
        '--runtime-grace-seconds', '300'
    )
}

$RunnerArgs = @(
    (Join-Path $ProjectRoot 'CodexLightRunner_v3.py'),
    '--python', $Python,
    '--cwd', $ProjectRoot,
    '--name', $ExperimentId,
    '--artifacts', $EvidenceRoot,
    '--timeout', $HardTimeoutSeconds.ToString(),
    '--stall', '0',
    '--retries', '0',
    '--no-ollama',
    '--governed',
    '--kill-switch', $KillSwitch
)
if ($DryRun) { $RunnerArgs += '--dry-run' }
$RunnerArgs += @((Join-Path $ProjectRoot 'tmp_2d_simulator_v37.py'), '--') + $TargetArgs

Write-Host "Mode: $Mode"
Write-Host "Experiment: $ExperimentId"
Write-Host "Preflight evidence: $Preflight"
Write-Host "Scoped stop file: $StopPath"
& $Python @RunnerArgs
exit $LASTEXITCODE
