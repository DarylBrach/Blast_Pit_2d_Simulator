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
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


VERSION = "1.1.0"
ALLOWED_CHANGED_FILES = {"tmp_2d_simulator_v37.py", "test_tmp_2d_simulator_v37.py"}
CODEX_ENV_ALLOWLIST = {
    "APPDATA", "CODEX_HOME", "COMSPEC", "HOME", "LANG", "LC_ALL", "LOCALAPPDATA",
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP",
    "USERPROFILE", "WINDIR",
}
SENSITIVE_ENV_NAME = re.compile(r"(?i)(?:api[_-]?key|auth|credential|password|secret|token)")
VOLATILE_WORKTREE_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
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
    max_runtime_seconds: int
    authorization: Path
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


def canonical_text_sha256(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return hashlib.sha256(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


def directory_manifest(root: Path, *, exclude_volatile: bool = False, include_mtime: bool = False) -> dict[str, dict[str, Any]]:
    """Hash regular files without following symlinks or Windows reparse points."""
    rows: dict[str, dict[str, Any]] = {}
    if not root.exists():
        return rows
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name != ".git"]
        if exclude_volatile:
            directories[:] = [name for name in directories if name not in VOLATILE_WORKTREE_DIRS]
        for name in files:
            path = Path(current) / name
            if exclude_volatile and path.suffix == ".pyc":
                continue
            relative = path.relative_to(root).as_posix()
            stat = path.lstat()
            is_reparse = path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400)
            rows[relative] = {
                "bytes": stat.st_size,
                "kind": "reparse" if is_reparse else "file",
                "sha256": None if is_reparse else sha256_file(path),
            }
            if include_mtime:
                rows[relative]["mtime_ns"] = stat.st_mtime_ns
    return dict(sorted(rows.items()))


def load_authorization(config: ControllerConfig) -> tuple[dict[str, Any], str]:
    path = config.authorization
    if path.is_symlink() or path.stat().st_size > 64_000:
        raise ImprovementError("Improvement authorization file is invalid")
    record = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema_version": "blast-pit.codex-improvement-authorization.v1",
        "project": "Blast_Pit_2d_Simulator",
        "status": "approved",
        "authority": "human-owner",
        "controller_version": VERSION,
        "automatic_merge": False,
        "automatic_push": False,
        "automatic_release": False,
        "candidate_network_access": False,
    }
    if any(record.get(key) != value for key, value in required.items()):
        raise ImprovementError("Improvement authorization scope mismatch")
    try:
        expires = datetime.fromisoformat(str(record["expires_utc"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise ImprovementError("Improvement authorization expiry is invalid") from exc
    if datetime.now(timezone.utc) >= expires:
        raise ImprovementError("Improvement authorization has expired")
    if config.cycles > int(record.get("max_cycles", 0)):
        raise ImprovementError("Requested cycles exceed human authorization")
    if config.max_runtime_seconds > int(record.get("max_runtime_seconds", 0)):
        raise ImprovementError("Requested runtime exceeds human authorization")
    expected_hashes = {
        "controller_source_sha256": canonical_text_sha256(config.repo / "CodexImprovementController_v1.py"),
        "candidate_driver_source_sha256": canonical_text_sha256(config.repo / "improvement_candidate_driver.py"),
        "score_source_sha256": canonical_text_sha256(config.repo / "improvement_score_checkpoint.py"),
        "development_seed_sha256": canonical_text_sha256(config.repo / "improvement_dev_seeds_v1.txt"),
    }
    if any(record.get(key) != value for key, value in expected_hashes.items()):
        raise ImprovementError("Improvement authorization source or seed hash mismatch")
    if sorted(record.get("allowed_changed_files", [])) != sorted(ALLOWED_CHANGED_FILES):
        raise ImprovementError("Improvement authorization file allowlist mismatch")
    return record, canonical_text_sha256(path)


def protection_snapshot(config: ControllerConfig) -> dict[str, Any]:
    production_root = config.repo / "artifacts" / "v37" / "robustness-v37-8h-001"
    return {
        "head": require_success(git(config, ["rev-parse", "HEAD"]), "protected HEAD").stdout.strip(),
        "tree": require_success(git(config, ["rev-parse", "HEAD^{tree}"]), "protected tree").stdout.strip(),
        "status": require_success(git(config, ["status", "--porcelain=v1", "--untracked-files=all"]), "protected status").stdout,
        "production_artifact_root": str(production_root),
        "production_artifacts": directory_manifest(production_root, include_mtime=True),
    }


def finalize_protection(config: ControllerConfig, run_dir: Path, before: dict[str, Any]) -> bool:
    after = protection_snapshot(config)
    passed = before == after
    atomic_json(run_dir / "production_guard.json", {"pass": passed, "before": before, "after": after})
    return passed


def seal_evidence(run_dir: Path, state: dict[str, Any]) -> str:
    manifest = {
        "schema_version": "blast-pit.improvement-evidence-manifest.v1",
        "run_id": state["run_id"],
        "base_commit": state["base_commit"],
        "status": state["status"],
        "controller_source_sha256": canonical_text_sha256(Path(__file__)),
        "files": directory_manifest(run_dir),
        "sealed_at": utc_now(),
    }
    path = run_dir / "evidence_manifest.json"
    atomic_json(path, manifest)
    return sha256_file(path)


def worktree_snapshot(worktree: Path, cycle_dir: Path) -> None:
    atomic_json(cycle_dir / "worktree_baseline_manifest.json", {
        "root": str(worktree),
        "files": directory_manifest(worktree, exclude_volatile=True),
    })


def filesystem_gate(worktree: Path, cycle_dir: Path) -> tuple[bool, list[str]]:
    baseline = json.loads((cycle_dir / "worktree_baseline_manifest.json").read_text(encoding="utf-8"))["files"]
    current = directory_manifest(worktree, exclude_volatile=True)
    changed = sorted(path for path in set(baseline) | set(current) if baseline.get(path) != current.get(path))
    unexpected = [path for path in changed if path not in ALLOWED_CHANGED_FILES]
    deleted_allowed = [path for path in changed if path in ALLOWED_CHANGED_FILES and path not in current]
    reparse = [path for path in changed if current.get(path, {}).get("kind") == "reparse"]
    reasons = []
    if unexpected:
        reasons.append(f"raw filesystem changes outside allowlist: {unexpected}")
    if deleted_allowed:
        reasons.append(f"allowlisted source deletion is forbidden: {deleted_allowed}")
    if reparse:
        reasons.append(f"reparse-point changes are forbidden: {reparse}")
    atomic_json(cycle_dir / "filesystem_gate.json", {
        "pass": not reasons,
        "changed_files": changed,
        "reasons": reasons,
        "before_file_count": len(baseline),
        "after_file_count": len(current),
    })
    return not reasons, reasons


def codex_environment() -> tuple[dict[str, str], list[str]]:
    env = {key: value for key, value in os.environ.items() if key.upper() in CODEX_ENV_ALLOWLIST}
    secrets = [value for key, value in env.items() if SENSITIVE_ENV_NAME.search(key) and len(value) >= 4]
    return env, secrets


def command(config: ControllerConfig, args: Sequence[str | Path], cwd: Path, timeout: int, *, env: dict[str, str] | None = None) -> CommandResult:
    values = [str(value) for value in args]
    completed = subprocess.run(values, cwd=str(cwd), env=env, text=True, encoding="utf-8", errors="replace",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return CommandResult(values, str(cwd), completed.returncode, completed.stdout or "", completed.stderr or "")


def require_success(result: CommandResult, label: str) -> CommandResult:
    if result.return_code != 0:
        raise ImprovementError(f"{label} failed with code {result.return_code}: {result.stderr[-2000:]}")
    return result


def streamed_command(args: Sequence[str | Path], cwd: Path, timeout: int, stdout_path: Path, stderr_path: Path,
                     *, env: dict[str,str] | None=None, redactions: Sequence[str] = ()) -> CommandResult:
    values=[str(value) for value in args]
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform=="win32" else 0
    proc=subprocess.Popen(values,cwd=str(cwd),env=env,text=True,encoding="utf-8",errors="replace",bufsize=1,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=creationflags)
    stdout_lines: list[str]=[]; stderr_lines: list[str]=[]

    def sanitize(value: str) -> str:
        for secret in redactions:
            if secret:
                value = value.replace(secret, "<redacted>")
        return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1<redacted>", value)

    def drain(stream: Any,path: Path,rows: list[str],mirror: bool) -> None:
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("w",encoding="utf-8",newline="\n") as handle:
            for line in iter(stream.readline,""):
                line=sanitize(line)
                rows.append(line); handle.write(line); handle.flush()
                if mirror:
                    sys.stdout.write(line); sys.stdout.flush()

    assert proc.stdout is not None and proc.stderr is not None
    threads=[threading.Thread(target=drain,args=(proc.stdout,stdout_path,stdout_lines,True),daemon=True),
             threading.Thread(target=drain,args=(proc.stderr,stderr_path,stderr_lines,False),daemon=True)]
    for thread in threads: thread.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if sys.platform=="win32":
            subprocess.run(["taskkill","/PID",str(proc.pid),"/T","/F"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        else:
            proc.terminate()
        proc.wait(timeout=15)
        raise
    finally:
        for thread in threads: thread.join(timeout=5)
    return CommandResult(values,str(cwd),int(proc.returncode),"".join(stdout_lines),"".join(stderr_lines))


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
    parser.add_argument("--max-runtime-seconds", type=int, default=28_800)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def make_config(argv: Sequence[str] | None = None) -> ControllerConfig:
    args = build_parser().parse_args(argv)
    config = ControllerConfig(
        repo=args.repo.resolve(), python=args.python.resolve(), codex=args.codex.resolve(),
        artifact_root=args.artifact_root.resolve(), worktree_root=args.worktree_root.resolve(), model=str(args.model),
        cycles=max(1, args.cycles), codex_timeout_seconds=max(60, args.codex_timeout),
        test_timeout_seconds=max(30, args.test_timeout), evaluation_timeout_seconds=max(60, args.evaluation_timeout),
        max_diff_bytes=max(1_000, args.max_diff_bytes), max_runtime_seconds=max(300, args.max_runtime_seconds),
        authorization=(args.authorization or (args.repo / "approval_codex_improvement_v1.json")).resolve(),
        dry_run=bool(args.dry_run),
    )
    if not (config.repo / ".git").exists():
        raise ImprovementError(f"Repository is not a Git worktree: {config.repo}")
    if not config.python.is_file():
        raise ImprovementError(f"Python interpreter not found: {config.python}")
    if not config.codex.is_file():
        raise ImprovementError(f"Codex executable not found: {config.codex}")
    if not config.authorization.is_file():
        raise ImprovementError(f"Improvement authorization not found: {config.authorization}")
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
        "--parent-authorization", source_root / "approval_codex_improvement_v1.json",
        "--generations", "4", "--max-frames", "64", "--rollout-frames", "64",
        "--max-runtime-seconds", str(min(600, config.evaluation_timeout_seconds)),
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


def prompt_for_cycle(base_score: dict[str, Any], production: dict[str, Any], cycle: int,
                     prior_cycles: Sequence[dict[str,Any]] = ()) -> str:
    lessons=[{"cycle":item.get("cycle"),"status":item.get("status"),"hypothesis":item.get("codex_decision",{}).get("hypothesis"),
              "reasons":item.get("reasons",[]),"candidate_score":item.get("candidate_score")} for item in prior_cycles]
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

Prior cycle lessons (do not repeat a rejected approach without directly correcting its failed gates):
{json.dumps(lessons, sort_keys=True)}

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
        "-c", 'windows.sandbox="elevated"', "-c", 'approval_policy="never"', "-c", 'model_reasoning_effort="high"', "--output-schema", schema,
        "--output-last-message", final_output, prompt,
    ]
    env, secrets = codex_environment()
    atomic_json(cycle_dir / "codex_environment.json", {
        "passed_variable_names": sorted(env),
        "redacted_variable_names": sorted(key for key in env if SENSITIVE_ENV_NAME.search(key)),
        "candidate_network_access": False,
        "codex_api_access": True,
    })
    result = streamed_command(args,worktree,config.codex_timeout_seconds,cycle_dir/"codex_events.jsonl",cycle_dir/"codex_stderr.log",
                              env=env, redactions=secrets)
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
    filesystem_ok, filesystem_reasons = filesystem_gate(worktree, cycle_dir)
    if not filesystem_ok:
        reasons.extend(filesystem_reasons)
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
    if float(candidate["standard_mean"]) < float(baseline["standard_mean"]) * 0.95:
        reasons.append("standard-profile mean regression exceeds 5 percent")
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
    started_monotonic = time.monotonic()
    base_commit = clean_repo(config)
    authorization, authorization_sha256 = load_authorization(config)
    rid = run_id()
    run_dir = config.artifact_root / rid
    run_dir.mkdir(parents=True, exist_ok=False)
    previous_state_path=config.artifact_root/"latest.json"
    previous_state=json.loads(previous_state_path.read_text(encoding="utf-8")) if previous_state_path.is_file() else {}
    historical_cycles=list(previous_state.get("cycles",[]))[-3:]
    protection_before = protection_snapshot(config)
    atomic_json(run_dir / "production_guard_before.json", protection_before)
    atomic_json(run_dir / "authorization.json", {"path": str(config.authorization), "sha256": authorization_sha256, "record": authorization})
    state: dict[str, Any] = {"schema_version": "blast-pit.improvement-controller.v1", "version": VERSION, "run_id": rid,
                             "status": "BASELINE_EVALUATING", "started_at": utc_now(), "base_commit": base_commit,
                             "cycles_requested": config.cycles, "cycles": [], "prior_run_id":previous_state.get("run_id"),
                             "historical_lessons_loaded":len(historical_cycles),"final_candidate_commit": None,
                             "authorization_sha256": authorization_sha256, "max_runtime_seconds": config.max_runtime_seconds}
    atomic_json(run_dir / "state.json", state)
    production = production_status(config)
    baseline = baseline_score(config, run_dir)
    state["baseline_score"] = baseline
    state["status"] = "RUNNING"
    atomic_json(run_dir / "state.json", state)
    if config.dry_run:
        protected = finalize_protection(config, run_dir, protection_before)
        state.update({"status": "DRY_RUN_COMPLETE" if protected else "ERROR", "ended_at": utc_now(),
                      "production_modified": not protected, "automatic_release": False,
                      "evidence_manifest": "evidence_manifest.json"})
        atomic_json(run_dir / "state.json", state)
        state["evidence_manifest_sha256"] = seal_evidence(run_dir, state)
        print(json.dumps(state, indent=2, default=str))
        return 0 if protected else 2

    current_ref = base_commit
    for cycle in range(1, config.cycles + 1):
        if time.monotonic() - started_monotonic >= config.max_runtime_seconds:
            state["cycles"].append({"cycle": cycle, "status": "ERROR", "error": "authorized controller runtime exhausted", "ended_at": utc_now()})
            atomic_json(run_dir / "state.json", state)
            break
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
            worktree_snapshot(worktree, cycle_dir)
            record["status"] = "CODEX_RUNNING"; atomic_json(run_dir / "state.json", state)
            decision = codex_cycle(config, worktree, cycle_dir, prompt_for_cycle(baseline, production, cycle,[*historical_cycles,*state["cycles"][:-1]]))
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
    protected = finalize_protection(config, run_dir, protection_before)
    has_cycle_error = any(item["status"] == "ERROR" for item in state["cycles"])
    state.update({"status": "COMPLETE" if protected else "ERROR", "ended_at": utc_now(), "accepted_cycles": accepted_count,
                  "rejected_or_error_cycles": len(state["cycles"]) - accepted_count,
                  "production_modified": not protected, "automatic_release": False,
                  "evidence_manifest": "evidence_manifest.json"})
    atomic_json(run_dir / "state.json", state)
    state["evidence_manifest_sha256"] = seal_evidence(run_dir, state)
    atomic_json(config.artifact_root / "latest.json", state)
    print(json.dumps(state, indent=2, default=str))
    return 0 if protected and not has_cycle_error else 2


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(make_config(argv))
    except (ImprovementError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
        print(f"[improvement-controller] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
