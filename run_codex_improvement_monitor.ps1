[CmdletBinding()]
param(
    [ValidateRange(1, 10)][int]$Cycles = 1,
    [switch]$DryRun,
    [string]$Python = 'E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe',
    [string]$Codex = "$env:APPDATA\npm\codex.cmd"
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$EvidenceRoot = Join-Path $ProjectRoot 'run_evidence\codex-improvement-controller'
$KillSwitch = '.supervisor_stop.codex-improvement-controller'
Set-Location -LiteralPath $ProjectRoot

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python not found: $Python" }
if (-not (Test-Path -LiteralPath $Codex -PathType Leaf)) { throw "Codex CLI not found: $Codex" }
$Dirty = @(git status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $Dirty.Count -ne 0) { throw "Improvement controller requires a clean Git worktree.`n$($Dirty -join "`n")" }
if (Test-Path -LiteralPath (Join-Path $ProjectRoot $KillSwitch)) { throw "Stale improvement-controller stop file exists." }

$ControllerArgs = @(
    (Join-Path $ProjectRoot 'CodexImprovementController_v1.py'),
    '--repo', $ProjectRoot,
    '--python', $Python,
    '--codex', $Codex,
    '--cycles', $Cycles.ToString()
)
if ($DryRun) { $ControllerArgs += '--dry-run' }

$RunnerArgs = @(
    (Join-Path $ProjectRoot 'CodexLightRunner_v3.py'),
    '--python', $Python,
    '--cwd', $ProjectRoot,
    '--name', 'codex-improvement-controller',
    '--artifacts', $EvidenceRoot,
    '--timeout', '7200',
    '--stall', '0',
    '--retries', '0',
    '--no-ollama',
    '--governed',
    '--kill-switch', $KillSwitch,
    (Join-Path $ProjectRoot 'CodexImprovementController_v1.py'),
    '--'
) + $ControllerArgs[1..($ControllerArgs.Count - 1)]

& $Python @RunnerArgs
exit $LASTEXITCODE
