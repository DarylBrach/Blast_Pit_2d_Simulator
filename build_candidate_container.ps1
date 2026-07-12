[CmdletBinding()]
param(
    [string]$Docker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe',
    [string]$Tag = 'blast-pit-candidate-runtime:2.2.0'
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Dockerfile = Join-Path $Root 'Dockerfile.candidate'
$Lock = Join-Path $Root 'requirements-candidate.lock'

foreach ($Path in @($Docker, $Dockerfile, $Lock)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required candidate-image input is missing: $Path"
    }
}

Write-Host 'BLUF: building a reviewed candidate image is a maintenance action, never an improvement-run action.'
& $Docker build --pull=false --file $Dockerfile --tag $Tag $Root
if ($LASTEXITCODE -ne 0) { throw "Docker image build failed with exit $LASTEXITCODE" }

$ImageId = (& $Docker image inspect $Tag --format '{{.Id}}').Trim()
if ($LASTEXITCODE -ne 0 -or $ImageId -notmatch '^sha256:[a-f0-9]{64}$') {
    throw 'Docker did not return an immutable candidate image ID.'
}
& $Docker run --rm --pull never --network none --read-only --cap-drop ALL `
    --security-opt no-new-privileges:true --security-opt seccomp=builtin `
    --user 65532:65532 --pids-limit 128 --memory 2g --memory-swap 2g --cpus 2 `
    --tmpfs '/tmp:rw,nosuid,nodev,size=256m,mode=1777' `
    $ImageId python -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Candidate image package verification failed.' }

Write-Host "Candidate image tag: $Tag"
Write-Host "Candidate image ID:  $ImageId"
Write-Host 'Renew approval_codex_improvement_v2.json with this exact ID before any governed run.'
