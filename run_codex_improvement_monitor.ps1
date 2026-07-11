[CmdletBinding()]
param(
    [ValidateSet('Run', 'DryRun', 'Status', 'Review', 'Verify', 'Stop', 'InspectTerminal')]
    [string]$Mode = 'Run',
    [ValidateRange(1, 10)][int]$Cycles = 1,
    [string]$RunId,
    [switch]$Json,
    [string]$Python = 'E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe',
    [string]$Codex = "$env:APPDATA\npm\codex.cmd"
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot.TrimEnd('\')
$ProjectParent = Split-Path -Parent $ProjectRoot
$ProjectName = Split-Path -Leaf $ProjectRoot
$EvidenceRoot = Join-Path $ProjectParent "_codex_improvement_evidence_$ProjectName"
$WorktreeRoot = Join-Path $ProjectParent "_codex_improvement_worktrees_$ProjectName"
$RunnerEvidenceRoot = Join-Path $ProjectParent "_codex_light_runner_evidence_$ProjectName"
$Controller = Join-Path $ProjectRoot 'CodexImprovementController_v2.py'
$Operator = Join-Path $ProjectRoot 'improvement_operator.py'
$Authorization = Join-Path $ProjectRoot 'approval_codex_improvement_v2.json'
$Evaluator = Join-Path $ProjectRoot 'improvement_score_checkpoint_v2.py'
$Runner = Join-Path $ProjectRoot 'CodexLightRunner_v3.py'
$KillSwitchName = '.supervisor_stop.codex-improvement-controller-v2'
$KillSwitch = Join-Path $ProjectRoot $KillSwitchName

Set-Location -LiteralPath $ProjectRoot

function Assert-Leaf([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label not found: $Path" }
}

if ($Mode -eq 'Status' -or $Mode -eq 'Review' -or $Mode -eq 'Verify') {
    Assert-Leaf $Python 'Python'
    Assert-Leaf $Operator 'v2 operator'
    $OperatorArguments = @($Operator, $Mode.ToLowerInvariant(), '--artifact-root', $EvidenceRoot)
    if ($Mode -eq 'Verify' -and $RunId) { $OperatorArguments += @('--run-id', $RunId) }
    if ($Json) { $OperatorArguments += '--json' }
    & $Python @OperatorArguments
    exit $LASTEXITCODE
}

if ($Mode -eq 'Stop') {
    if (Test-Path -LiteralPath $KillSwitch) {
        Write-Host "BLUF: stop is already requested for the v2 improvement controller."
    } else {
        New-Item -ItemType File -Path $KillSwitch -ErrorAction Stop | Out-Null
        Write-Host "BLUF: stop requested. The supervisor will kill the controller process tree and retain KILLED evidence."
    }
    Write-Host "Kill switch: $KillSwitch"
    Write-Host "Runner evidence: $RunnerEvidenceRoot"
    Write-Host "A killed/partial controller run is not resumable in place; retain it and start a fresh recovery run."
    exit 0
}

Assert-Leaf $Python 'Python'
Assert-Leaf $Codex 'Codex CLI'
Assert-Leaf $Controller 'v2 controller'
Assert-Leaf $Authorization 'v2 authorization'
Assert-Leaf $Evaluator 'v2 evaluator'

$Dirty = @(git status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $Dirty.Count -ne 0) {
    throw "The v2 controller requires a clean protected Git checkout.`n$($Dirty -join "`n")"
}

if ($Mode -eq 'InspectTerminal') {
    if (-not $RunId) { throw '-Mode InspectTerminal requires -RunId.' }
    & $Python $Controller `
        '--repo' $ProjectRoot `
        '--python' $Python `
        '--codex' $Codex `
        '--authorization' $Authorization `
        '--artifact-root' $EvidenceRoot `
        '--worktree-root' $WorktreeRoot `
        '--evaluator' $Evaluator `
        '--resume-run' $RunId
    exit $LASTEXITCODE
}

if (Test-Path -LiteralPath $KillSwitch) {
    throw "Stale v2 stop file exists: $KillSwitch. Confirm the old supervisor stopped, then remove only this exact file."
}

$ControllerArguments = @(
    '--repo', $ProjectRoot,
    '--python', $Python,
    '--codex', $Codex,
    '--authorization', $Authorization,
    '--artifact-root', $EvidenceRoot,
    '--worktree-root', $WorktreeRoot,
    '--evaluator', $Evaluator,
    '--model', 'gpt-5.5',
    '--cycles', $Cycles.ToString(),
    '--max-runtime-seconds', '28200',
    '--role-timeout-seconds', '1200',
    '--command-timeout-seconds', '600',
    '--evaluation-timeout-seconds', '900',
    '--remediation-cap', '2',
    '--max-parallel-specialists', '3',
    '--sandbox-implementation', 'unelevated'
)
if ($Mode -eq 'DryRun') { $ControllerArguments += '--dry-run' }

$RunnerArguments = @(
    $Runner,
    '--python', $Python,
    '--cwd', $ProjectRoot,
    '--name', 'codex-improvement-controller-v2',
    '--artifacts', $RunnerEvidenceRoot,
    '--timeout', '28800',
    '--stall', '0',
    '--retries', '0',
    '--no-ollama',
    '--governed',
    '--kill-switch', $KillSwitchName,
    $Controller,
    '--'
) + $ControllerArguments

Write-Host "BLUF: starting governed v2 $Mode; up to $Cycles cumulative cycle(s); eight-hour supervisor cap; no push, merge, promotion, audit, export, or release authority."
Write-Host "Controller evidence: $EvidenceRoot"
Write-Host "Candidate worktrees: $WorktreeRoot"
Write-Host "Runner evidence: $RunnerEvidenceRoot"
& $Python @RunnerArguments
exit $LASTEXITCODE
