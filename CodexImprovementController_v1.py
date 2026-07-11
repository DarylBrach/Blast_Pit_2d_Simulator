from __future__ import annotations

"""Governed propose-test-evaluate-retain loop for Blast_Pit v37."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


VERSION = "1.0.0"
ALLOWED_CHANGED_FILES = {"tmp_2d_simulator_v37.py", "test_tmp_2d_simulator_v37.py"}
FORBIDDEN_ADDED_PATTERNS = (
    r"^\+.*\b(?:subprocess|socket|requests|urllib|http\.client)\b",
    r"^\+.*\b(?:eval|exec|compile)\s*\(",
    r"^\+.*\bos\.(?:system|popen|remove|unlink|rmdir)\s*\(",
    r"^\+.*\b(?:shutil\.rmtree|Path\([^)]*\)\.unlink)\s*\(",
)


class ImprovementError(RuntimeError):
    pass


@dataclass(frozen=True)
class ControllerConfig:
    repo: Path
    python: Path
    codex: Path
    artifact_root: Path
    worktree_root: Path
    model: str
    cycles: int
    codex_timeout_seconds: int
    test_timeout_seconds: int
    evaluation_timeout_seconds: int
    max_diff_bytes: int
    dry_run: bool


@dataclass
class CommandResult:
    command: list[str]
    cwd: str
    return_code: int
    stdout: str
    stderr: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(config: ControllerConfig, args: Sequence[str | Path], cwd: Path, timeout: int, *, env: dict[str, str] | None = None) -> CommandResult:
    values = [str(value) for value in args]
    completed = subprocess.run(values, cwd=str(cwd), env=env, text=True, encoding="utf-8", errors="replace",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return CommandResult(values, str(cwd), completed.returncode, completed.stdout or "", completed.stderr or "")


def require_success(result: CommandResult, label: str) -> CommandResult:
    if result.return_code != 0:
        raise ImprovementError(f"{label} failed with code {result.return_code}: {result.stderr[-2000:]}")
    return result


def git(config: ControllerConfig, args: Sequence[str], cwd: Path | None = None, timeout: int = 120) -> CommandResult:
    return command(config, ["git", *args], cwd or config.repo, timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Governed Codex improvement controller")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--codex", type=Path, default=Path(os.environ.get("APPDATA", "")) / "npm" / "codex.cmd")
    parser.add_argument("--artifact-root", type=Path, default=Path.home() / ".codex_light_runner" / "improvements" / "Blast_Pit_2d_Simulator")
    parser.add_argument("--worktree-root", type=Path, default=Path.home() / ".codex_light_runner" / "improvement_worktrees" / "Blast_Pit_2d_Simulator")
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--codex-timeout", type=int, default=1800)
    parser.add_argument("--test-timeout", type=int, default=300)
    parser.add_argument("--evaluation-timeout", type=int, default=600)
    parser.add_argument("--max-diff-bytes", type=int, default=120_000)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def make_config(argv: Sequence[str] | None = None) -> ControllerConfig:
    args = build_parser().parse_args(argv)
    config = ControllerConfig(
        repo=args.repo.resolve(), python=args.python.resolve(), codex=args.codex.resolve(),
        artifact_root=args.artifact_root.resolve(), worktree_root=args.worktree_root.resolve(), model=str(args.model),
        cycles=max(1, args.cycles), codex_timeout_seconds=max(60, args.codex_timeout),
        test_timeout_seconds=max(30, args.test_timeout), evaluation_timeout_seconds=max(60, args.evaluation_timeout),
        max_diff_bytes=max(1_000, args.max_diff_bytes), dry_run=bool(args.dry_run),
    )
    if not (config.repo / ".git").exists():
        raise ImprovementError(f"Repository is not a Git worktree: {config.repo}")
    if not config.python.is_file():
        raise ImprovementError(f"Python interpreter not found: {config.python}")
    if not config.codex.is_file():
        raise ImprovementError(f"Codex executable not found: {config.codex}")
    return config


def clean_repo(config: ControllerConfig) -> str:
    status = require_success(git(config, ["status", "--porcelain=v1"]), "git status").stdout.strip()
    if status:
        raise ImprovementError(f"Base repository must be clean before autonomous work:\n{status}")
    return require_success(git(config, ["rev-parse", "HEAD"]), "git rev-parse").stdout.strip()


def write_command_evidence(path: Path, result: CommandResult) -> None:
    atomic_json(path, asdict(result))


def candidate_train(config: ControllerConfig, source_root: Path, output_root: Path, experiment_id: str, cycle_dir: Path) -> Path:
    result = command(config, [
        config.python, "-u", source_root / "improvement_candidate_driver.py",
        "--experiment-id", experiment_id,
        "--artifact-root", output_root,
        "--source-v36", source_root / "artifacts" / "v36" / "qdppo-evaluation-001" / "evolution_state_v36.npz",
        "--seed-file", source_root / "improvement_dev_seeds_v1.txt",
        "--generations", "4", "--max-frames", "64", "--rollout-frames", "64",
    ], source_root, config.evaluation_timeout_seconds)
    write_command_evidence(cycle_dir / "candidate_training.json", result)
    require_success(result, "candidate development training")
    checkpoint = output_root / experiment_id / "evolution_state_v37.npz"
    if not checkpoint.is_file():
        raise ImprovementError("Candidate training did not produce a checkpoint")
    return checkpoint


def trusted_score(config: ControllerConfig, checkpoint: Path, cycle_dir: Path, name: str) -> dict[str, Any]:
    result = command(config, [config.python, config.repo / "improvement_score_checkpoint.py", "--checkpoint", checkpoint],
                     config.repo, config.evaluation_timeout_seconds)
    write_command_evidence(cycle_dir / f"{name}_score_command.json", result)
    require_success(result, f"trusted {name} scoring")
    try:
        score = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise ImprovementError(f"Invalid {name} scoring output") from exc
    atomic_json(cycle_dir / f"{name}_score.json", score)
    return score


def baseline_score(config: ControllerConfig, run_dir: Path) -> dict[str, Any]:
    baseline_dir = run_dir / "baseline"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = candidate_train(config, config.repo, baseline_dir / "artifacts", "baseline-v37", baseline_dir)
    return trusted_score(config, checkpoint, baseline_dir, "baseline")


def create_worktree(config: ControllerConfig, base_ref: str, branch: str, worktree: Path, cycle_dir: Path) -> None:
    worktree.parent.mkdir(parents=True, exist_ok=True)
    result = git(config, ["worktree", "add", "-b", branch, str(worktree), base_ref], timeout=180)
    write_command_evidence(cycle_dir / "worktree_create.json", result)
    require_success(result, "git worktree add")


def prompt_for_cycle(base_score: dict[str, Any], production: dict[str, Any], cycle: int) -> str:
    return f"""You are improving the Blast_Pit v37 training process in an isolated candidate Git worktree.

Mission: make ONE minimal, technically justified improvement to tmp_2d_simulator_v37.py based on the retained production telemetry, and add or update focused tests in test_tmp_2d_simulator_v37.py.

Production evidence:
- completed generations: {production.get('generation', -1) + 1}
- best challenge CVaR during training: {production.get('challenge_cvar')}
- workflow state: {production.get('workflow_state')}
- policy hash: {production.get('hof_policy_hash')}

Trusted development baseline:
{json.dumps(base_score, sort_keys=True)}

Cycle: {cycle}

Hard constraints:
1. Modify only tmp_2d_simulator_v37.py and test_tmp_2d_simulator_v37.py.
2. Preserve all approval, fingerprint, checkpoint, journal, status, runtime, audit, and release gates.
3. No network, subprocess, shell, dynamic code execution, filesystem deletion, dependency, schema, actor ABI, v35, or v36 changes.
4. Do not read or optimize against terminal audit seed files or terminal audit results.
5. Keep deterministic behavior and checkpoint resume parity.
6. Run the focused tests and full pytest suite.
7. If no defensible improvement is possible, make no changes and return category no_change.

Prefer a process/correctness improvement with measurable non-regression. Algorithm changes must be small and explain why the trusted deterministic development score should improve. Your final response must satisfy the supplied JSON schema."""


def codex_cycle(config: ControllerConfig, worktree: Path, cycle_dir: Path, prompt: str) -> dict[str, Any]:
    schema = worktree / "schemas" / "codex_improvement_result.schema.json"
    final_output = cycle_dir / "codex_final.json"
    args = [
        config.codex, "exec", "--cd", worktree, "--sandbox", "workspace-write", "--model", config.model,
        "--ephemeral", "--ignore-user-config", "--json",
        "-c", 'approval_policy="never"', "-c", 'model_reasoning_effort="high"', "--output-schema", schema,
        "--output-last-message", final_output, prompt,
    ]
    result = command(config, args, worktree, config.codex_timeout_seconds, env=os.environ.copy())
    (cycle_dir / "codex_events.jsonl").write_text(result.stdout, encoding="utf-8")
    (cycle_dir / "codex_stderr.log").write_text(result.stderr, encoding="utf-8")
    atomic_json(cycle_dir / "codex_command.json", {"command": [str(value) for value in args[:-1]] + ["<prompt>"], "return_code": result.return_code})
    require_success(result, "codex exec")
    try:
        decision = json.loads(final_output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImprovementError("Codex did not produce valid structured output") from exc
    return decision


def changed_files(config: ControllerConfig, worktree: Path) -> list[str]:
    result = require_success(git(config, ["status", "--porcelain=v1", "--untracked-files=all"], cwd=worktree), "candidate git status")
    files = []
    for line in result.stdout.splitlines():
        value = line[3:].strip()
        if " -> " in value:
            value = value.split(" -> ", 1)[1]
        files.append(value.replace("\\", "/"))
    return sorted(set(files))


def security_gate(config: ControllerConfig, worktree: Path, cycle_dir: Path) -> tuple[bool, list[str], str]:
    files = changed_files(config, worktree)
    reasons: list[str] = []
    if not files:
        reasons.append("no candidate changes")
    unexpected = [path for path in files if path not in ALLOWED_CHANGED_FILES]
    if unexpected:
        reasons.append(f"changed files outside allowlist: {unexpected}")
    diff = require_success(git(config, ["diff", "--no-ext-diff", "--binary", "HEAD"], cwd=worktree), "candidate diff").stdout
    (cycle_dir / "candidate.patch").write_text(diff, encoding="utf-8")
    if len(diff.encode("utf-8")) > config.max_diff_bytes:
        reasons.append("candidate diff exceeds byte limit")
    for pattern in FORBIDDEN_ADDED_PATTERNS:
        if re.search(pattern, diff, flags=re.MULTILINE | re.IGNORECASE):
            reasons.append(f"forbidden added-code pattern: {pattern}")
    for relative in files:
        path = worktree / relative
        if path.exists() and path.is_symlink():
            reasons.append(f"symlink change is forbidden: {relative}")
    atomic_json(cycle_dir / "security_gate.json", {"pass": not reasons, "changed_files": files, "reasons": reasons,
                                                   "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(), "diff_bytes": len(diff.encode())})
    return not reasons, reasons, diff


def validation_gate(config: ControllerConfig, worktree: Path, cycle_dir: Path) -> None:
    compile_result = command(config, [config.python, "-m", "py_compile", "tmp_2d_simulator_v37.py", "test_tmp_2d_simulator_v37.py"],
                             worktree, config.test_timeout_seconds)
    write_command_evidence(cycle_dir / "py_compile.json", compile_result)
    require_success(compile_result, "candidate py_compile")
    test_result = command(config, [config.python, "-m", "pytest", "-q"], worktree, config.test_timeout_seconds)
    write_command_evidence(cycle_dir / "pytest.json", test_result)
    require_success(test_result, "candidate pytest")


def metric_gate(category: str, baseline: dict[str, Any], candidate: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if float(candidate["cvar"]) < float(baseline["cvar"]) - 0.01:
        reasons.append("CVaR regression exceeds 0.01")
    if float(candidate["mean"]) < float(baseline["mean"]) * 0.99:
        reasons.append("mean fitness regression exceeds 1 percent")
    if float(candidate["early_extinction_rate"]) > float(baseline["early_extinction_rate"]) + 0.02:
        reasons.append("early extinction regression exceeds 0.02")
    if category == "algorithm" and not (
        float(candidate["cvar"]) >= float(baseline["cvar"]) + 0.005
        or float(candidate["mean"]) >= float(baseline["mean"]) + 0.005
    ):
        reasons.append("algorithm change lacks required deterministic improvement")
    return not reasons, reasons


def commit_candidate(config: ControllerConfig, worktree: Path, cycle: int, cycle_dir: Path) -> str:
    files = sorted(ALLOWED_CHANGED_FILES & set(changed_files(config, worktree)))
    require_success(git(config, ["add", "--", *files], cwd=worktree), "candidate git add")
    result = git(config, ["commit", "-m", f"Codex improvement candidate cycle {cycle}"], cwd=worktree)
    write_command_evidence(cycle_dir / "candidate_commit.json", result)
    require_success(result, "candidate git commit")
    return require_success(git(config, ["rev-parse", "HEAD"], cwd=worktree), "candidate commit hash").stdout.strip()


def production_status(config: ControllerConfig) -> dict[str, Any]:
    path = config.repo / "artifacts" / "v37" / "robustness-v37-8h-001" / "status_v37.json"
    if not path.is_file():
        raise ImprovementError(f"Completed production status not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def run(config: ControllerConfig) -> int:
    base_commit = clean_repo(config)
    rid = run_id()
    run_dir = config.artifact_root / rid
    run_dir.mkdir(parents=True, exist_ok=False)
    state: dict[str, Any] = {"schema_version": "blast-pit.improvement-controller.v1", "version": VERSION, "run_id": rid,
                             "status": "BASELINE_EVALUATING", "started_at": utc_now(), "base_commit": base_commit,
                             "cycles_requested": config.cycles, "cycles": [], "final_candidate_commit": None}
    atomic_json(run_dir / "state.json", state)
    production = production_status(config)
    baseline = baseline_score(config, run_dir)
    state["baseline_score"] = baseline
    state["status"] = "RUNNING"
    atomic_json(run_dir / "state.json", state)
    if config.dry_run:
        state.update({"status": "DRY_RUN_COMPLETE", "ended_at": utc_now()})
        atomic_json(run_dir / "state.json", state)
        print(json.dumps(state, indent=2, default=str))
        return 0

    current_ref = base_commit
    for cycle in range(1, config.cycles + 1):
        cycle_dir = run_dir / f"cycle_{cycle:03d}"
        cycle_dir.mkdir(parents=True)
        branch = f"codex/improvement-{rid.lower()}-c{cycle:03d}"
        worktree = config.worktree_root / rid / f"cycle_{cycle:03d}"
        record: dict[str, Any] = {"cycle": cycle, "branch": branch, "worktree": str(worktree), "status": "WORKTREE_CREATING",
                                  "started_at": utc_now(), "base_ref": current_ref}
        state["cycles"].append(record)
        atomic_json(run_dir / "state.json", state)
        try:
            create_worktree(config, current_ref, branch, worktree, cycle_dir)
            record["status"] = "CODEX_RUNNING"; atomic_json(run_dir / "state.json", state)
            decision = codex_cycle(config, worktree, cycle_dir, prompt_for_cycle(baseline, production, cycle))
            record["codex_decision"] = decision
            record["status"] = "SECURITY_VALIDATING"; atomic_json(run_dir / "state.json", state)
            security_ok, security_reasons, _ = security_gate(config, worktree, cycle_dir)
            if not security_ok:
                record.update({"status": "REJECTED", "reasons": security_reasons, "ended_at": utc_now()})
                atomic_json(run_dir / "state.json", state); continue
            record["status"] = "TESTING"; atomic_json(run_dir / "state.json", state)
            validation_gate(config, worktree, cycle_dir)
            record["status"] = "EVALUATING"; atomic_json(run_dir / "state.json", state)
            candidate_checkpoint = candidate_train(config, worktree, cycle_dir / "training_artifacts", f"candidate-c{cycle:03d}", cycle_dir)
            candidate = trusted_score(config, candidate_checkpoint, cycle_dir, "candidate")
            accepted, metric_reasons = metric_gate(str(decision.get("category", "algorithm")), baseline, candidate)
            atomic_json(cycle_dir / "promotion_gate.json", {"pass": accepted, "baseline": baseline, "candidate": candidate, "reasons": metric_reasons})
            if not accepted:
                record.update({"status": "REJECTED", "candidate_score": candidate, "reasons": metric_reasons, "ended_at": utc_now()})
                atomic_json(run_dir / "state.json", state); continue
            commit_hash = commit_candidate(config, worktree, cycle, cycle_dir)
            record.update({"status": "ACCEPTED_CANDIDATE_BRANCH", "candidate_score": candidate, "commit": commit_hash, "ended_at": utc_now()})
            state["final_candidate_commit"] = commit_hash
            current_ref = commit_hash
            baseline = candidate
            atomic_json(run_dir / "state.json", state)
        except (ImprovementError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
            record.update({"status": "ERROR", "error": str(exc), "ended_at": utc_now()})
            atomic_json(run_dir / "state.json", state)

    accepted_count = sum(1 for item in state["cycles"] if item["status"] == "ACCEPTED_CANDIDATE_BRANCH")
    state.update({"status": "COMPLETE", "ended_at": utc_now(), "accepted_cycles": accepted_count,
                  "rejected_or_error_cycles": config.cycles - accepted_count,
                  "production_modified": False, "automatic_release": False})
    atomic_json(run_dir / "state.json", state)
    atomic_json(config.artifact_root / "latest.json", state)
    print(json.dumps(state, indent=2, default=str))
    return 0 if all(item["status"] != "ERROR" for item in state["cycles"]) else 2


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(make_config(argv))
    except (ImprovementError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        print(f"[improvement-controller] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
