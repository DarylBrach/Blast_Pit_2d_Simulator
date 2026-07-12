#!/usr/bin/env python3
r"""
CodexLightRunner_v3.py

A profileless, one-shot Python supervisor.

Run one target .py file, monitor it, capture evidence, classify failures with
simple deterministic rules, and optionally ask an Ollama endpoint pool for an
advisory failure summary. No config file, no profiles, no scheduler, no live
repo edits, and no automatic Codex execution.

Typical use:

    python CodexLightRunner_v3.py path/to/target.py -- target args here

python CodexLightRunner_v3.py "E:\path\to\target_script.py"

Runner options go before the target path:

    python CodexLightRunner_v3.py --timeout 7200 --stall 900 target.py -- --flag value
    
python CodexLightRunner_v3.py "E:\path\to\target_script.py" -- --config config\reviewer.yaml

python CodexLightRunner_v3.py `
  "E:\path\to\target_script.py" `
  --timeout 7200 `
  --stall 900 `
  --retries 1 `
  -- --config config\reviewer.yaml

Artifacts are written under:

    ~/.codex_light_runner/runs/<target-name>/<utc-run-id>/
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Deque, Optional, Sequence

VERSION = "3.1.0"
DEFAULT_ROOT = Path(os.path.expanduser("~")) / ".codex_light_runner"
DEFAULT_TAIL_LINES = 300
DEFAULT_TIMEOUT_SECONDS = 3600
DEFAULT_STALL_SECONDS = 600
DEFAULT_GRACE_SECONDS = 8
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 15
DEFAULT_KILL_SWITCH = ".supervisor_stop"
MAX_RUNNER_LEDGER_BYTES = 16 * 1024 * 1024
MAX_RUNNER_MANIFEST_BYTES = 4 * 1024 * 1024
RUNNER_LEDGER_LOCK_TIMEOUT_SECONDS = 15.0
RUNNER_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "TIMEOUT", "STALLED", "KILLED", "INTERRUPTED"}
RUNNER_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
RUNNER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
LOWER_HEX_64_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_RUNNER_EVIDENCE_FILES = 20_000
MAX_RUNNER_EVIDENCE_DIRECTORIES = 20_000
MAX_RUNNER_EVIDENCE_BYTES = 512_000_000
RUNNER_LEDGER_KEYS = {
    "schema_version", "sequence", "previous_ledger_hash", "record_id", "runner_name", "run_id",
    "status", "target", "name_binding_hash", "manifest_sha256", "state_sha256", "recorded_at", "ledger_hash",
}
RUNNER_MANIFEST_KEYS = {"schema_version", "run_id", "status", "target", "created_at", "directories", "files"}
RUNNER_MANIFEST_FILE_KEYS = {"path", "bytes", "sha256"}
RUNNER_POINTER_KEYS = {
    "schema_version", "record_id", "runner_name", "run_id", "status", "target",
    "manifest_sha256", "state_sha256", "ledger_hash",
}
RUNNER_STATE_KEYS = {
    "version", "run_id", "target", "target_args", "python", "cwd", "command", "status", "reason",
    "return_code", "started_at", "ended_at", "artifacts_dir", "preflight", "attempts",
    "deterministic_classification", "ollama_classification", "codex_prompt", "kill_switch",
}
RUNNER_PUBLICATION_WAL_KEYS = {
    "schema_version", "phase", "record", "pointer", "created_at", "updated_at",
}
RUNNER_PUBLICATION_PHASES = {"INTENT_FSYNCED", "LEDGER_ANCHORED", "POINTER_PUBLISHED"}
RUNNER_NAME_BINDING_LEDGER_KEYS = {
    "schema_version", "sequence", "previous_binding_hash", "runner_name", "target", "recorded_at", "binding_hash",
}

DEFAULT_OLLAMA_ENDPOINTS: tuple[dict[str, Any], ...] = (
    {"base_url": "http://192.168.1.239:11434", "gpu": "RTX 5090", "weight": 2.25, "context": 32768},
    {"base_url": "http://192.168.1.181:11434", "gpu": "RTX 4090", "weight": 1.65, "context": 16384},
    {"base_url": "http://192.168.1.127:11434", "gpu": "RTX 3090", "weight": 1.00, "context": 32768},
)

PROJECT_ROOT_MARKERS = (".git", "pyproject.toml", "setup.py", "setup.cfg", "AGENTS.md", "README.md")
GUARDRAIL_FILES = ("AGENTS.md", "README.md", "HANDOFF.md", "AEKB_HANDOFF.md", "README_START_HERE.md")
RETRYABLE_STATUSES = {"FAILED", "TIMEOUT", "STALLED"}
SENSITIVE_NAME = re.compile(r"(?i)(secret|token|password|passwd|credential|api[_-]?key|private[_-]?key)")
MINIMAL_ENV_KEYS = {
    "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH", "PATHEXT",
    "USERPROFILE", "HOME", "LOCALAPPDATA", "APPDATA", "LANG", "LC_ALL",
}


class RunnerError(Exception):
    """User-facing runner error."""


@dataclass(frozen=True)
class OllamaEndpoint:
    base_url: str
    gpu: str
    weight: float
    context: int

    @property
    def chat_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api/chat"


@dataclass(frozen=True)
class RunnerConfig:
    target: Path
    target_args: list[str]
    python: Path
    cwd: Path
    artifacts_root: Path
    name: str
    timeout_seconds: int
    stall_seconds: int
    retries: int
    retry_delay_seconds: int
    kill_switch_file: str
    preflight: bool
    ollama_enabled: bool
    ollama_model: str
    ollama_timeout_seconds: int
    codex_prompt: bool
    quiet: bool
    json_stdout: bool
    dry_run: bool
    allow_parallel: bool
    extra_env: dict[str, str]
    path_prepend: list[Path]
    minimal_env: bool
    tail_lines: int = DEFAULT_TAIL_LINES

    @property
    def target_command(self) -> list[str]:
        return [str(self.python), "-u", str(self.target), *self.target_args]

    @property
    def kill_switch_path(self) -> Path:
        return (self.cwd / self.kill_switch_file).resolve()


@dataclass
class CommandResult:
    label: str
    command: list[str]
    status: str
    reason: str
    return_code: Optional[int]
    started_at: str
    ended_at: str
    duration_seconds: float
    stdout_tail: list[str]
    stderr_tail: list[str]
    stdout_log: str
    stderr_log: str
    combined_log: str


@dataclass
class RunPaths:
    run_dir: Path
    attempt_dir: Path
    stdout_log: Path
    stderr_log: Path
    combined_log: Path


class ActivityClock:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last = time.monotonic()

    def touch(self) -> None:
        with self._lock:
            self._last = time.monotonic()

    def idle_seconds(self) -> float:
        with self._lock:
            return time.monotonic() - self._last


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def run_id() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4)


def expand_path(value: str | Path) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()


def slugify(value: str, max_len: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    return (cleaned or "task")[:max_len]


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("<redacted>" if SENSITIVE_NAME.search(str(key)) else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        result: list[Any] = []
        hide_next = False
        for item in value:
            text = str(item)
            if hide_next:
                result.append("<redacted>")
                hide_next = False
            elif SENSITIVE_NAME.search(text.split("=", 1)[0]):
                if "=" in text:
                    result.append(text.split("=", 1)[0] + "=<redacted>")
                else:
                    result.append(text)
                    hide_next = True
            else:
                result.append(redact(item))
        return result
    return value


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def find_project_root(target: Path) -> Path:
    for folder in (target.parent, *target.parents):
        if any((folder / marker).exists() for marker in PROJECT_ROOT_MARKERS):
            return folder
    return target.parent


def parse_key_value(items: Sequence[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise RunnerError(f"Invalid --env value {item!r}; expected KEY=VALUE.")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise RunnerError(f"Invalid --env value {item!r}; key is empty.")
        env[key] = value
    return env


def normalize_target_args(args: list[str]) -> list[str]:
    return args[1:] if args and args[0] == "--" else args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="CodexLightRunner_v3.py",
        description="Run and monitor one target .py file without profiles or config files.",
    )
    parser.add_argument("target", nargs="?", help="Target Python file to supervise.")
    parser.add_argument("--python", default=sys.executable, help="Python interpreter for the target. Default: current interpreter.")
    parser.add_argument("--cwd", default=None, help="Working directory. Default: nearest project root above target.")
    parser.add_argument("--name", default=None, help="Artifact/lock name. Default: target file stem.")
    parser.add_argument("--artifacts", "--artifact-root", dest="artifacts", default=str(DEFAULT_ROOT), help="Artifact root. Default: ~/.codex_light_runner")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Hard timeout in seconds. Default: 3600.")
    parser.add_argument("--stall", type=int, default=DEFAULT_STALL_SECONDS, help="No-output stall timeout in seconds. Use 0 to disable. Default: 600.")
    parser.add_argument("--retries", type=int, default=0, help="Retries after FAILED/TIMEOUT/STALLED. Default: 0.")
    parser.add_argument("--retry-delay", type=int, default=30, help="Seconds between retries. Default: 30.")
    parser.add_argument("--kill-switch", default=DEFAULT_KILL_SWITCH, help="Stop file relative to cwd. Default: .supervisor_stop.")
    parser.add_argument("--no-preflight", action="store_true", help="Skip py_compile preflight.")
    parser.add_argument("--ollama", action="store_true", help="Explicitly allow LAN Ollama failure classification. Disabled by default.")
    parser.add_argument("--no-ollama", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ollama-model", default=DEFAULT_OLLAMA_MODEL, help=f"Ollama model. Default: {DEFAULT_OLLAMA_MODEL}.")
    parser.add_argument("--ollama-timeout", type=int, default=DEFAULT_OLLAMA_TIMEOUT_SECONDS, help="Timeout per Ollama endpoint. Default: 15.")
    parser.add_argument("--no-codex-prompt", action="store_true", help="Do not write a Codex repair prompt on failure.")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE", help="Extra environment variable for the target. Repeatable.")
    parser.add_argument("--minimal-env", "--governed", action="store_true", help="Pass only a minimal OS environment plus explicit --env values.")
    parser.add_argument("--allow-external-target", action="store_true", help="Allow the target outside --cwd (unsafe for governed runs).")
    parser.add_argument("--path-prepend", action="append", default=[], metavar="PATH", help="Path to prepend to PATH. Repeatable.")
    parser.add_argument("--allow-parallel", action="store_true", help="Skip duplicate-run lock for this target/arg set.")
    parser.add_argument("--quiet", action="store_true", help="Do not mirror target output to this console.")
    parser.add_argument("--json", action="store_true", help="Print final state as JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Resolve configuration and print the command without executing target.")
    parser.add_argument("--print-endpoints", "--list-ollama-endpoints", dest="print_endpoints", action="store_true", help="Print the built-in Ollama endpoint pool and exit.")
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    return parser


def make_config(argv: Optional[Sequence[str]] = None) -> RunnerConfig | None:
    # Split runner options from target-script options. Everything after the first
    # standalone "--" is forwarded to the target unchanged. Runner options may
    # appear before or after the target path as long as they are before "--".
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if "--" in raw_argv:
        sep = raw_argv.index("--")
        runner_argv = raw_argv[:sep]
        forwarded_target_args = raw_argv[sep + 1 :]
    else:
        runner_argv = raw_argv
        forwarded_target_args = []

    args = build_parser().parse_args(runner_argv)

    if args.version:
        print(VERSION)
        return None

    endpoints = [OllamaEndpoint(**item) for item in DEFAULT_OLLAMA_ENDPOINTS]
    if args.print_endpoints:
        print(json.dumps([asdict(ep) for ep in endpoints], indent=2))
        return None

    if not args.target:
        raise RunnerError("Missing target .py file.")

    target = expand_path(args.target)
    if not target.exists():
        raise RunnerError(f"Target file does not exist: {target}")
    if not target.is_file() or target.suffix.lower() != ".py":
        raise RunnerError(f"Target must be a .py file: {target}")

    python = expand_path(args.python)
    if not python.exists() or not python.is_file():
        raise RunnerError(f"Python interpreter must be a file: {python}")

    cwd = expand_path(args.cwd) if args.cwd else find_project_root(target)
    if not cwd.exists() or not cwd.is_dir():
        raise RunnerError(f"Working directory does not exist: {cwd}")
    if not args.allow_external_target and not is_within(target, cwd):
        raise RunnerError(f"Target must be within working directory: {cwd}")
    kill_switch = Path(args.kill_switch)
    if kill_switch.is_absolute() or len(kill_switch.parts) != 1 or kill_switch.name in {"", ".", ".."}:
        raise RunnerError("Kill switch must be one simple filename relative to cwd.")

    artifacts_root = expand_path(args.artifacts)
    if artifacts_root.exists() and not artifacts_root.is_dir():
        raise RunnerError(f"Artifact root must be a directory: {artifacts_root}")
    name = slugify(args.name or target.stem)
    return RunnerConfig(
        target=target,
        target_args=forwarded_target_args,
        python=python,
        cwd=cwd,
        artifacts_root=artifacts_root,
        name=name,
        timeout_seconds=max(1, int(args.timeout)),
        stall_seconds=max(0, int(args.stall)),
        retries=max(0, int(args.retries)),
        retry_delay_seconds=max(0, int(args.retry_delay)),
        kill_switch_file=args.kill_switch,
        preflight=not args.no_preflight,
        ollama_enabled=bool(args.ollama and not args.no_ollama),
        ollama_model=args.ollama_model,
        ollama_timeout_seconds=max(1, int(args.ollama_timeout)),
        codex_prompt=not args.no_codex_prompt,
        quiet=(args.quiet or args.json),
        json_stdout=args.json,
        dry_run=args.dry_run,
        allow_parallel=args.allow_parallel,
        extra_env=parse_key_value(args.env),
        path_prepend=[expand_path(path) for path in args.path_prepend],
        minimal_env=bool(args.minimal_env),
    )


def build_env(config: RunnerConfig) -> dict[str, str]:
    env = ({key: value for key, value in os.environ.items() if key.upper() in MINIMAL_ENV_KEYS}
           if config.minimal_env else os.environ.copy())
    env["PYTHONUNBUFFERED"] = "1"

    pythonpath_parts = [str(config.cwd)]
    src = config.cwd / "src"
    if src.exists():
        pythonpath_parts.append(str(src))
    if env.get("PYTHONPATH"):
        pythonpath_parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

    path_parts = [str(path) for path in config.path_prepend]
    if path_parts:
        path_parts.append(env.get("PATH", ""))
        env["PATH"] = os.pathsep.join(path_parts)

    env.update(config.extra_env)
    return env


def ensure_dirs(config: RunnerConfig, rid: str) -> Path:
    run_parent = config.artifacts_root / "runs" / config.name
    run_parent.mkdir(parents=True, exist_ok=True)
    (config.artifacts_root / "locks").mkdir(parents=True, exist_ok=True)
    (config.artifacts_root / "latest").mkdir(parents=True, exist_ok=True)
    validate_no_reparse_ancestors(config.artifacts_root, require_exists=True)
    validate_no_reparse_ancestors(run_parent, require_exists=True)
    validate_no_reparse_ancestors(config.artifacts_root / "locks", require_exists=True)
    validate_no_reparse_ancestors(config.artifacts_root / "latest", require_exists=True)
    return run_parent / rid


def lock_key(config: RunnerConfig) -> str:
    payload = json.dumps(
        {"target": str(config.target), "cwd": str(config.cwd), "args": config.target_args},
        sort_keys=True,
    )
    return f"{config.name}_{short_hash(payload)}"


def acquire_lock(config: RunnerConfig, run_dir: Path) -> Optional[RunnerLedgerLock]:
    if config.allow_parallel:
        return None

    locks_dir = config.artifacts_root / "locks"
    lock_path = locks_dir / f"{lock_key(config)}.lock.json"
    payload = {
        "pid": os.getpid(),
        "created_at": iso_now(),
        "target": str(config.target),
        "cwd": str(config.cwd),
        "args": config.target_args,
        "run_dir": str(run_dir),
    }

    return acquire_kernel_file_lock(
        lock_path,
        payload,
        timeout_seconds=0.0,
        busy_message="A matching run is already active. Use --allow-parallel to override.",
    )


def release_lock(lock: Optional[RunnerLedgerLock]) -> None:
    if lock:
        lock.close()


def popen_kwargs(config: RunnerConfig, stdout: Any, stderr: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "stdout": stdout,
        "stderr": stderr,
        "cwd": str(config.cwd),
        "env": build_env(config),
        "stdin": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["preexec_fn"] = os.setsid
    return kwargs


def terminate_process_tree(proc: subprocess.Popen[Any], grace_seconds: int = DEFAULT_GRACE_SECONDS) -> None:
    if proc.poll() is not None:
        return

    try:
        proc.terminate()
        proc.wait(timeout=grace_seconds)
        return
    except Exception:
        pass

    if proc.poll() is not None:
        return

    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def stream_reader(
    pipe: Any,
    log_path: Path,
    combined_path: Path,
    stream_name: str,
    tail: Deque[str],
    activity: ActivityClock,
    combined_lock: threading.Lock,
    quiet: bool,
) -> None:
    output = sys.stderr if stream_name == "stderr" else sys.stdout
    with log_path.open("ab", buffering=0) as log_file:
        for raw in iter(pipe.readline, b""):
            activity.touch()
            log_file.write(raw)
            text = raw.decode("utf-8", errors="replace")
            for line in text.splitlines():
                tail.append(line)
            prefix = f"[{stream_name}] ".encode("utf-8")
            with combined_lock:
                with combined_path.open("ab", buffering=0) as combined_file:
                    for line in raw.splitlines(keepends=True):
                        combined_file.write(prefix + line)
            if not quiet:
                try:
                    print(text, end="", file=output, flush=True)
                except UnicodeEncodeError:
                    encoding = getattr(output, "encoding", None) or "utf-8"
                    safe = text.encode(encoding, errors="backslashreplace").decode(encoding)
                    print(safe, end="", file=output, flush=True)


def git_metadata(cwd: Path) -> dict[str, Any]:
    def call(*args: str) -> Optional[str]:
        try:
            result = subprocess.run(["git", "-C", str(cwd), *args], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=10, check=False)
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None
    commit = call("rev-parse", "HEAD")
    status = call("status", "--porcelain=v1") if commit else None
    return {"is_repository": commit is not None, "commit": commit,
            "dirty": bool(status) if status is not None else None,
            "status_sha256": hashlib.sha256((status or "").encode()).hexdigest() if status is not None else None}


def execution_metadata(config: RunnerConfig) -> dict[str, Any]:
    inputs: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for raw in config.target_args:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = config.cwd / candidate
        try:
            candidate = candidate.resolve()
            if candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                inputs.append({"path": str(candidate), "bytes": candidate.stat().st_size,
                               "sha256": sha256_file(candidate)})
        except OSError:
            continue
    runner = Path(__file__).resolve()
    return {
        "captured_at": iso_now(), "platform": platform.platform(), "hostname": platform.node(),
        "python_version": platform.python_version(), "python_implementation": platform.python_implementation(),
        "git": git_metadata(config.cwd),
        "files": {
            "runner": {"path": str(runner), "sha256": sha256_file(runner)},
            "target": {"path": str(config.target), "sha256": sha256_file(config.target)},
            "python": {"path": str(config.python), "sha256": sha256_file(config.python)},
            "input_files": inputs,
        },
        "environment_policy": "minimal" if config.minimal_env else "inherited",
        "explicit_environment_keys": sorted(config.extra_env),
    }


def command_result_from_completed(label: str, command: list[str], completed: subprocess.CompletedProcess[str], start: float, stdout_log: Path, stderr_log: Path, combined_log: Path) -> CommandResult:
    status = "SUCCESS" if completed.returncode == 0 else "FAILED"
    reason = "completed successfully" if status == "SUCCESS" else f"exited with code {completed.returncode}"
    return CommandResult(
        label=label,
        command=command,
        status=status,
        reason=reason,
        return_code=completed.returncode,
        started_at=iso_now(),
        ended_at=iso_now(),
        duration_seconds=round(time.monotonic() - start, 2),
        stdout_tail=completed.stdout.splitlines()[-DEFAULT_TAIL_LINES:] if completed.stdout else [],
        stderr_tail=completed.stderr.splitlines()[-DEFAULT_TAIL_LINES:] if completed.stderr else [],
        stdout_log=str(stdout_log),
        stderr_log=str(stderr_log),
        combined_log=str(combined_log),
    )


def run_preflight(config: RunnerConfig, run_dir: Path) -> Optional[CommandResult]:
    if not config.preflight:
        return None

    attempt_dir = run_dir / "preflight"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = attempt_dir / "stdout.log"
    stderr_log = attempt_dir / "stderr.log"
    combined_log = attempt_dir / "combined.log"
    command = [str(config.python), "-m", "py_compile", str(config.target)]
    start = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=str(config.cwd),
        env=build_env(config),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=min(config.timeout_seconds, 300),
        check=False,
    )
    stdout_log.write_text(completed.stdout or "", encoding="utf-8")
    stderr_log.write_text(completed.stderr or "", encoding="utf-8")
    combined_log.write_text(
        ("[stdout]\n" + (completed.stdout or "") + "\n[stderr]\n" + (completed.stderr or "")),
        encoding="utf-8",
    )
    return command_result_from_completed("preflight_py_compile", command, completed, start, stdout_log, stderr_log, combined_log)


def run_target_once(config: RunnerConfig, run_dir: Path, attempt_number: int) -> CommandResult:
    attempt_dir = run_dir / f"attempt_{attempt_number:03d}"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    paths = RunPaths(
        run_dir=run_dir,
        attempt_dir=attempt_dir,
        stdout_log=attempt_dir / "stdout.log",
        stderr_log=attempt_dir / "stderr.log",
        combined_log=attempt_dir / "combined.log",
    )

    command = config.target_command
    stdout_tail: Deque[str] = deque(maxlen=config.tail_lines)
    stderr_tail: Deque[str] = deque(maxlen=config.tail_lines)
    activity = ActivityClock()
    combined_lock = threading.Lock()
    started_at = iso_now()
    start = time.monotonic()

    proc = subprocess.Popen(command, **popen_kwargs(config, subprocess.PIPE, subprocess.PIPE))

    assert proc.stdout is not None
    assert proc.stderr is not None
    threads = [
        threading.Thread(
            target=stream_reader,
            args=(proc.stdout, paths.stdout_log, paths.combined_log, "stdout", stdout_tail, activity, combined_lock, config.quiet or config.json_stdout),
            daemon=True,
        ),
        threading.Thread(
            target=stream_reader,
            args=(proc.stderr, paths.stderr_log, paths.combined_log, "stderr", stderr_tail, activity, combined_lock, config.quiet or config.json_stdout),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    status = "SUCCESS"
    reason = "completed successfully"

    last_heartbeat = 0.0
    try:
        while True:
            rc = proc.poll()
            elapsed = time.monotonic() - start
            if rc is not None:
                if rc != 0:
                    status = "FAILED"
                    reason = f"exited with code {rc}"
                break

            if config.kill_switch_path.exists():
                status = "KILLED"
                reason = f"kill switch detected: {config.kill_switch_path}"
                terminate_process_tree(proc)
                break

            if elapsed > config.timeout_seconds:
                status = "TIMEOUT"
                reason = f"hard timeout exceeded: {config.timeout_seconds}s"
                terminate_process_tree(proc)
                break

            if config.stall_seconds > 0 and activity.idle_seconds() > config.stall_seconds:
                status = "STALLED"
                reason = f"no stdout/stderr activity for {config.stall_seconds}s"
                terminate_process_tree(proc)
                break

            if elapsed - last_heartbeat >= 30:
                heartbeat={"status":"RUNNING","run_id":run_dir.name,"attempt":attempt_number,"pid":proc.pid,
                           "updated_at":iso_now(),"elapsed_seconds":round(elapsed,2),"idle_seconds":round(activity.idle_seconds(),2),
                           "artifacts_dir":str(run_dir),"heartbeat":str(attempt_dir/"heartbeat.json")}
                write_json(attempt_dir / "heartbeat.json",heartbeat)
                write_json(config.artifacts_root / "latest" / f"{config.name}_state.json",heartbeat)
                last_heartbeat = elapsed
            time.sleep(0.5)
    except BaseException:
        terminate_process_tree(proc)
        for thread in threads:
            thread.join(timeout=2)
        raise

    try:
        proc.wait(timeout=DEFAULT_GRACE_SECONDS)
    except Exception:
        terminate_process_tree(proc, grace_seconds=2)
        proc.wait(timeout=2)

    for thread in threads:
        thread.join(timeout=2)

    ended_at = iso_now()
    return CommandResult(
        label=f"attempt_{attempt_number:03d}",
        command=command,
        status=status,
        reason=reason,
        return_code=proc.returncode,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=round(time.monotonic() - start, 2),
        stdout_tail=list(stdout_tail),
        stderr_tail=list(stderr_tail),
        stdout_log=str(paths.stdout_log),
        stderr_log=str(paths.stderr_log),
        combined_log=str(paths.combined_log),
    )


def classify_failure(result: CommandResult) -> dict[str, Any]:
    text = "\n".join([*result.stderr_tail[-80:], *result.stdout_tail[-40:]])
    lowered = text.lower()

    if result.status == "SUCCESS":
        kind = "SUCCESS"
        codex_needed = False
        summary = "Target completed successfully."
    elif result.status == "TIMEOUT":
        kind = "RUNTIME_TIMEOUT"
        codex_needed = True
        summary = "The target exceeded the hard timeout."
    elif result.status == "STALLED":
        kind = "NO_OUTPUT_STALL"
        codex_needed = True
        summary = "The target stopped producing output before completion."
    elif result.status == "KILLED":
        kind = "OPERATOR_STOP"
        codex_needed = False
        summary = "The run was stopped by the kill switch."
    elif "modulenotfounderror" in lowered or "importerror" in lowered:
        kind = "DEPENDENCY_OR_IMPORT_FAILURE"
        codex_needed = False
        summary = "The failure appears related to a missing dependency or import path."
    elif "filenotfounderror" in lowered or "no such file or directory" in lowered or "cannot find the path" in lowered:
        kind = "FILE_OR_PATH_FAILURE"
        codex_needed = False
        summary = "The failure appears related to a missing file or bad path."
    elif "permissionerror" in lowered or "access is denied" in lowered:
        kind = "PERMISSION_FAILURE"
        codex_needed = False
        summary = "The failure appears related to permissions or access control."
    elif "syntaxerror" in lowered or "indentationerror" in lowered:
        kind = "CODE_SYNTAX_FAILURE"
        codex_needed = True
        summary = "The failure appears related to Python syntax or indentation."
    elif "traceback" in lowered:
        kind = "CODE_RUNTIME_FAILURE"
        codex_needed = True
        summary = "The failure includes a Python traceback."
    else:
        kind = "UNKNOWN_NONZERO_FAILURE"
        codex_needed = True
        summary = "The target failed, but the deterministic classifier could not identify a narrow cause."

    return {
        "classification": kind,
        "summary": summary,
        "codex_needed": codex_needed,
        "source": "deterministic_rules",
    }


def build_failure_evidence(config: RunnerConfig, result: CommandResult, classification: dict[str, Any]) -> str:
    stdout_tail = "\n".join(result.stdout_tail[-120:]) or "<no stdout captured>"
    stderr_tail = "\n".join(result.stderr_tail[-120:]) or "<no stderr captured>"
    return f"""# Failure Evidence

## Target
- target: {config.target}
- cwd: {config.cwd}
- python: {config.python}
- args: {json.dumps(redact(config.target_args))}

## Result
- status: {result.status}
- return_code: {result.return_code}
- reason: {result.reason}
- started_at: {result.started_at}
- ended_at: {result.ended_at}
- duration_seconds: {result.duration_seconds}

## Deterministic Classification
```json
{json.dumps(classification, indent=2)}
```

## stderr tail
```text
{stderr_tail}
```

## stdout tail
```text
{stdout_tail}
```
"""


def query_ollama(config: RunnerConfig, evidence: str) -> dict[str, Any]:
    endpoints = [OllamaEndpoint(**item) for item in DEFAULT_OLLAMA_ENDPOINTS]
    endpoints.sort(key=lambda item: item.weight, reverse=True)
    errors: list[dict[str, str]] = []

    system_prompt = (
        "You are an advisory failure classifier for a local Python process supervisor. "
        "Return exactly valid JSON with this schema: "
        "{\"classification\":\"CODE_FAILURE|ENVIRONMENT_FAILURE|DEPENDENCY_FAILURE|DATA_FAILURE|TIMEOUT|STALL|OPERATOR_STOP|UNKNOWN_FAILURE\","
        "\"confidence\":0.0,\"summary\":\"brief plain English summary\",\"recommended_next_step\":\"specific next step\","
        "\"codex_needed\":true}. Do not include markdown."
    )

    for endpoint in endpoints:
        payload = {
            "model": config.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": evidence[-24000:]},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_ctx": int(endpoint.context)},
        }
        try:
            req = urllib.request.Request(
                endpoint.chat_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=config.ollama_timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
            body = json.loads(raw)
            content = body.get("message", {}).get("content", "{}")
            decision = json.loads(content)
            decision["endpoint"] = asdict(endpoint)
            decision["source"] = "ollama_advisory"
            if errors:
                decision["previous_endpoint_errors"] = errors
            return decision
        except Exception as exc:
            errors.append({"endpoint": endpoint.base_url, "gpu": endpoint.gpu, "error": str(exc)})

    return {
        "classification": "UNKNOWN_FAILURE",
        "confidence": 0.0,
        "summary": "No configured Ollama endpoint returned a usable JSON advisory response.",
        "recommended_next_step": "Review failure_evidence.md and endpoint errors.",
        "codex_needed": False,
        "source": "ollama_advisory",
        "endpoint_errors": errors,
    }


def read_guardrails(cwd: Path, limit_chars: int = 24000) -> str:
    chunks: list[str] = []
    remaining = limit_chars
    for name in GUARDRAIL_FILES:
        path = cwd / name
        if not path.exists() or not path.is_file() or remaining <= 0:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")[:remaining]
        chunks.append(f"## {name}\n{text}")
        remaining -= len(text)
    return "\n\n".join(chunks) or "<no guardrail files found>"


def write_codex_prompt(config: RunnerConfig, run_dir: Path, evidence: str, classification: dict[str, Any], ollama: Optional[dict[str, Any]]) -> Path:
    prompt = f"""# Codex Review Prompt

You are operating as a senior Python automation engineer.

## Goal
Review the failed supervised run below and propose the smallest safe fix. Do not modify credentials, `.env` files, secrets, generated artifacts, or files outside the repository root.

## Repository Root
{config.cwd}

## Target Command
```text
{' '.join(redact(config.target_command))}
```

## Guardrails
{read_guardrails(config.cwd)}

## Deterministic Classification
```json
{json.dumps(classification, indent=2)}
```

## Ollama Advisory Classification
```json
{json.dumps(ollama, indent=2) if ollama else '<not requested>'}
```

{evidence}

## Required Output
1. Root cause.
2. Minimal file changes required.
3. Exact validation command to run.
4. Risks or assumptions.
"""
    path = run_dir / "codex_review_prompt.md"
    path.write_text(prompt, encoding="utf-8")
    return path


def is_reparse(path: Path) -> bool:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def validate_no_reparse_ancestors(path: Path, *, require_exists: bool = False) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            break
        if is_reparse(current):
            raise RunnerError(f"Symlink or reparse-point evidence path is forbidden: {current}")
    if require_exists and not absolute.exists():
        raise RunnerError(f"Required evidence path does not exist: {absolute}")
    return absolute.resolve(strict=require_exists)


def strict_regular_file(path: Path, label: str) -> os.stat_result:
    validate_no_reparse_ancestors(path, require_exists=True)
    info = path.stat(follow_symlinks=False)
    if is_reparse(path) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RunnerError(f"Unsafe {label}: {path}")
    return info


def strict_file_record(path: Path, label: str, *, max_bytes: int = MAX_RUNNER_EVIDENCE_BYTES) -> dict[str, Any]:
    before = strict_regular_file(path, label)
    if before.st_size > max_bytes:
        raise RunnerError(f"{label} exceeds its size limit: {path}")
    file_hash = sha256_file(path)
    after = strict_regular_file(path, label)
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)
    if before_identity != after_identity:
        raise RunnerError(f"{label} changed while it was being hashed: {path}")
    return {"bytes": before.st_size, "sha256": file_hash}


def strict_read_bytes(path: Path, label: str, *, max_bytes: int) -> bytes:
    before = strict_regular_file(path, label)
    if before.st_size > max_bytes:
        raise RunnerError(f"{label} exceeds its size limit: {path}")
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"Could not read {label}: {path}") from exc
    after = strict_regular_file(path, label)
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)
    if before_identity != after_identity or len(value) != before.st_size:
        raise RunnerError(f"{label} changed while it was being read: {path}")
    return value


def strict_tree_snapshot(root: Path, *, exclude_root_files: set[str] | None = None) -> tuple[dict[str, dict[str, Any]], set[str]]:
    root = validate_no_reparse_ancestors(root, require_exists=True)
    if not root.is_dir() or is_reparse(root):
        raise RunnerError(f"Runner evidence root is not a safe directory: {root}")
    excluded = exclude_root_files or set()
    files: dict[str, dict[str, Any]] = {}
    directories: set[str] = set()
    total = 0
    for current, names, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if is_reparse(current_path):
            raise RunnerError(f"Runner evidence tree contains a reparse directory: {current_path}")
        names.sort()
        filenames.sort()
        for name in names:
            candidate = current_path / name
            try:
                info = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise RunnerError(f"Runner evidence directory is unsafe: {candidate}") from exc
            if is_reparse(candidate) or not stat.S_ISDIR(info.st_mode):
                raise RunnerError(f"Runner evidence tree contains an unsafe directory: {candidate}")
            directories.add(candidate.relative_to(root).as_posix())
        for name in filenames:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            if relative in excluded:
                strict_regular_file(candidate, "excluded runner manifest file")
                continue
            if name.endswith(".tmp"):
                raise RunnerError(f"Runner evidence tree contains an unfinished temporary file: {candidate}")
            record = strict_file_record(candidate, "runner evidence file")
            total += int(record["bytes"])
            files[relative] = record
            if len(files) > MAX_RUNNER_EVIDENCE_FILES or total > MAX_RUNNER_EVIDENCE_BYTES:
                raise RunnerError("Runner evidence tree exceeds its bounded manifest limits")
        if len(directories) > MAX_RUNNER_EVIDENCE_DIRECTORIES:
            raise RunnerError("Runner evidence tree has too many directories")
    return dict(sorted(files.items())), directories


def atomic_write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_no_reparse_ancestors(path.parent, require_exists=True)
    if os.path.lexists(path):
        strict_regular_file(path, "atomic JSON destination")
    temp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with temp.open("xb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def write_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, default=str, allow_nan=False).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def reject_json_constant(value: str) -> Any:
    raise RunnerError(f"Non-finite JSON constant is not allowed: {value}")


def read_json_object(path: Path, label: str, *, max_bytes: int = MAX_RUNNER_MANIFEST_BYTES) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RunnerError(f"Duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            strict_read_bytes(path, label, max_bytes=max_bytes).decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_json_constant,
        )
    except RunnerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Invalid {label}: {path}") from exc
    if not isinstance(value, dict):
        raise RunnerError(f"{label} must be a JSON object: {path}")
    return value


def runner_ledger_path(config: RunnerConfig) -> Path:
    return config.artifacts_root / "runner_ledger.jsonl"


def runner_terminal_path(config: RunnerConfig) -> Path:
    return config.artifacts_root / "latest" / f"{config.name}_terminal.json"


def runner_publication_wal_path(config: RunnerConfig) -> Path:
    return config.artifacts_root / "runner_publication_wal.json"


def runner_name_binding_ledger_path(config: RunnerConfig) -> Path:
    return config.artifacts_root / "runner_name_binding_ledger.jsonl"


def runner_record_id(config: RunnerConfig, run_identifier: str) -> str:
    identity = canonical_json({"runner_name": config.name, "target": str(config.target), "run_id": run_identifier})
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@dataclass
class RunnerLedgerLock:
    path: Path
    handle: Any

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None


def acquire_kernel_file_lock(
    lock_path: Path,
    payload: dict[str, Any],
    *,
    timeout_seconds: float,
    busy_message: str,
) -> RunnerLedgerLock:
    validate_no_reparse_ancestors(lock_path.parent, require_exists=True)
    if os.name != "nt" and os.path.lexists(lock_path):
        strict_regular_file(lock_path, "kernel lock")
    deadline = time.monotonic() + timeout_seconds
    handle: Any = None
    while handle is None:
        if os.name == "nt":
            import msvcrt
            from ctypes import wintypes

            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            raw_handle = create_file(
                str(lock_path),
                0x80000000 | 0x40000000,
                0,
                None,
                4,
                0x80 | 0x00200000,
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if raw_handle == invalid:
                error = ctypes.windll.kernel32.GetLastError()
                if error in {5, 32, 33} and time.monotonic() < deadline:
                    time.sleep(0.05)
                    continue
                if error in {5, 32, 33}:
                    raise RunnerError(busy_message)
                raise OSError(error, "CreateFileW failed for kernel lock", str(lock_path))
            try:
                descriptor = msvcrt.open_osfhandle(int(raw_handle), os.O_RDWR | os.O_BINARY)
                handle = os.fdopen(descriptor, "r+b", buffering=0)
            except Exception:
                ctypes.windll.kernel32.CloseHandle(raw_handle)
                raise
        else:  # pragma: no cover - supported production target is Windows
            import errno
            import fcntl

            candidate = lock_path.open("a+b", buffering=0)
            try:
                fcntl.flock(candidate.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                handle = candidate
            except OSError as exc:
                candidate.close()
                if exc.errno in {errno.EACCES, errno.EAGAIN} and time.monotonic() < deadline:
                    time.sleep(0.05)
                    continue
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise RunnerError(busy_message) from exc
                raise
    info = os.fstat(handle.fileno())
    attributes = getattr(info, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    ):
        handle.close()
        raise RunnerError(f"Kernel-owned lock is unsafe: {lock_path}")
    encoded_payload = canonical_json(payload).encode("utf-8") + b"\n"
    handle.seek(0)
    handle.truncate(0)
    handle.write(encoded_payload)
    handle.flush()
    os.fsync(handle.fileno())
    return RunnerLedgerLock(lock_path, handle)


def acquire_runner_ledger_lock(config: RunnerConfig) -> RunnerLedgerLock:
    return acquire_kernel_file_lock(
        config.artifacts_root / "runner_ledger.lock",
        {"pid": os.getpid(), "created_at": iso_now(), "target": str(config.target)},
        timeout_seconds=RUNNER_LEDGER_LOCK_TIMEOUT_SECONDS,
        busy_message="Timed out waiting for the kernel-owned runner evidence ledger lock",
    )


def read_runner_ledger(config: RunnerConfig) -> list[dict[str, Any]]:
    path = runner_ledger_path(config)
    if not os.path.lexists(path):
        return []
    try:
        lines = strict_read_bytes(path, "runner evidence ledger", max_bytes=MAX_RUNNER_LEDGER_BYTES).decode("utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RunnerError(f"Runner evidence ledger is unreadable: {path}") from exc
    rows: list[dict[str, Any]] = []
    previous = "0" * 64
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        if not line:
            raise RunnerError(f"Runner evidence ledger contains a blank line at {number}")

        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise RunnerError(f"Runner evidence ledger has a duplicate key at line {number}: {key}")
                result[key] = value
            return result

        try:
            row = json.loads(line, object_pairs_hook=unique_pairs, parse_constant=reject_json_constant)
        except RunnerError:
            raise
        except json.JSONDecodeError as exc:
            raise RunnerError(f"Runner evidence ledger contains invalid JSON at line {number}") from exc
        if not isinstance(row, dict):
            raise RunnerError(f"Runner evidence ledger line {number} is not an object")
        if set(row) != RUNNER_LEDGER_KEYS:
            raise RunnerError(f"Runner evidence ledger field set mismatch at line {number}")
        supplied = row.get("ledger_hash")
        unsigned = dict(row)
        unsigned.pop("ledger_hash", None)
        if (
            not isinstance(row.get("sequence"), int)
            or isinstance(row.get("sequence"), bool)
            or row.get("sequence") != number
            or row.get("previous_ledger_hash") != previous
            or not isinstance(supplied, str)
            or not LOWER_HEX_64_RE.fullmatch(supplied)
            or supplied != json_sha256(unsigned)
        ):
            raise RunnerError(f"Runner evidence ledger chain mismatch at line {number}")
        if row.get("schema_version") != "codex-light-runner.ledger.v1":
            raise RunnerError(f"Runner evidence ledger schema mismatch at line {number}")
        record_id = row.get("record_id")
        if not isinstance(record_id, str) or len(record_id) != 64 or record_id in seen:
            raise RunnerError(f"Runner evidence ledger has an invalid or duplicate record ID at line {number}")
        identity = {
            "runner_name": row.get("runner_name"),
            "target": row.get("target"),
            "run_id": row.get("run_id"),
        }
        if (
            not all(isinstance(identity[key], str) and identity[key] for key in identity)
            or row.get("status") not in RUNNER_TERMINAL_STATUSES
            or not isinstance(row.get("recorded_at"), str)
            or not LOWER_HEX_64_RE.fullmatch(str(row.get("name_binding_hash", "")))
            or not LOWER_HEX_64_RE.fullmatch(str(row.get("manifest_sha256", "")))
            or not LOWER_HEX_64_RE.fullmatch(str(row.get("state_sha256", "")))
            or not LOWER_HEX_64_RE.fullmatch(str(row.get("previous_ledger_hash", "")))
        ):
            raise RunnerError(f"Runner evidence ledger value type mismatch at line {number}")
        if record_id != hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest():
            raise RunnerError(f"Runner evidence ledger record identity mismatch at line {number}")
        seen.add(record_id)
        rows.append(row)
        previous = str(supplied)
    return rows


def read_runner_name_binding_ledger(config: RunnerConfig) -> list[dict[str, Any]]:
    path = runner_name_binding_ledger_path(config)
    if not os.path.lexists(path):
        return []
    try:
        lines = strict_read_bytes(path, "runner name-binding ledger", max_bytes=MAX_RUNNER_LEDGER_BYTES).decode("utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RunnerError(f"Runner name-binding ledger is unreadable: {path}") from exc
    rows: list[dict[str, Any]] = []
    previous = "0" * 64
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        if not line:
            raise RunnerError(f"Runner name-binding ledger contains a blank line at {number}")

        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise RunnerError(f"Runner name-binding ledger has a duplicate key at line {number}: {key}")
                result[key] = value
            return result

        try:
            row = json.loads(line, object_pairs_hook=unique_pairs, parse_constant=reject_json_constant)
        except RunnerError:
            raise
        except json.JSONDecodeError as exc:
            raise RunnerError(f"Runner name-binding ledger contains invalid JSON at line {number}") from exc
        if not isinstance(row, dict) or set(row) != RUNNER_NAME_BINDING_LEDGER_KEYS:
            raise RunnerError(f"Runner name-binding ledger field set mismatch at line {number}")
        supplied = row.get("binding_hash")
        unsigned = dict(row)
        unsigned.pop("binding_hash", None)
        if (
            row.get("schema_version") != "codex-light-runner.name-binding-ledger.v1"
            or not isinstance(row.get("sequence"), int)
            or isinstance(row.get("sequence"), bool)
            or row.get("sequence") != number
            or row.get("previous_binding_hash") != previous
            or not LOWER_HEX_64_RE.fullmatch(str(row.get("previous_binding_hash", "")))
            or not LOWER_HEX_64_RE.fullmatch(str(supplied or ""))
            or supplied != json_sha256(unsigned)
            or not isinstance(row.get("runner_name"), str)
            or not RUNNER_NAME_RE.fullmatch(row["runner_name"])
            or not isinstance(row.get("target"), str)
            or not Path(row["target"]).is_absolute()
            or not isinstance(row.get("recorded_at"), str)
            or row["runner_name"].casefold() in seen
        ):
            raise RunnerError(f"Runner name-binding ledger chain or value mismatch at line {number}")
        rows.append(row)
        seen.add(row["runner_name"].casefold())
        previous = str(supplied)
    return rows


def read_runner_publication_wal(config: RunnerConfig) -> Optional[dict[str, Any]]:
    path = runner_publication_wal_path(config)
    if not os.path.lexists(path):
        return None
    value = read_json_object(path, "runner publication WAL")
    if set(value) != RUNNER_PUBLICATION_WAL_KEYS or value.get("schema_version") != "codex-light-runner.publication-wal.v1":
        raise RunnerError("Runner publication WAL schema is invalid")
    if value.get("phase") not in RUNNER_PUBLICATION_PHASES:
        raise RunnerError("Runner publication WAL phase is invalid")
    record = value.get("record")
    pointer = value.get("pointer")
    if not isinstance(record, dict) or set(record) != RUNNER_LEDGER_KEYS:
        raise RunnerError("Runner publication WAL ledger record is invalid")
    if not isinstance(pointer, dict) or set(pointer) != RUNNER_POINTER_KEYS:
        raise RunnerError("Runner publication WAL terminal pointer is invalid")
    unsigned = dict(record)
    supplied = unsigned.pop("ledger_hash", None)
    identity = {
        "runner_name": record.get("runner_name"),
        "target": record.get("target"),
        "run_id": record.get("run_id"),
    }
    if (
        record.get("schema_version") != "codex-light-runner.ledger.v1"
        or not isinstance(record.get("sequence"), int)
        or isinstance(record.get("sequence"), bool)
        or not all(isinstance(identity[key], str) and identity[key] for key in identity)
        or not RUNNER_NAME_RE.fullmatch(str(record.get("runner_name", "")))
        or not RUNNER_ID_RE.fullmatch(str(record.get("run_id", "")))
        or not Path(str(record.get("target", ""))).is_absolute()
        or record.get("status") not in RUNNER_TERMINAL_STATUSES
        or not isinstance(record.get("recorded_at"), str)
        or not LOWER_HEX_64_RE.fullmatch(str(record.get("name_binding_hash", "")))
        or not LOWER_HEX_64_RE.fullmatch(str(record.get("record_id", "")))
        or not LOWER_HEX_64_RE.fullmatch(str(record.get("previous_ledger_hash", "")))
        or not LOWER_HEX_64_RE.fullmatch(str(record.get("manifest_sha256", "")))
        or not LOWER_HEX_64_RE.fullmatch(str(record.get("state_sha256", "")))
        or not LOWER_HEX_64_RE.fullmatch(str(supplied or ""))
        or supplied != json_sha256(unsigned)
        or record.get("record_id") != hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    ):
        raise RunnerError("Runner publication WAL ledger record values are invalid")
    expected_pointer = {
        "schema_version": "codex-light-runner.terminal-pointer.v1",
        "record_id": record["record_id"],
        "runner_name": record["runner_name"],
        "run_id": record["run_id"],
        "status": record["status"],
        "target": record["target"],
        "manifest_sha256": record["manifest_sha256"],
        "state_sha256": record["state_sha256"],
        "ledger_hash": record["ledger_hash"],
    }
    if pointer != expected_pointer or not isinstance(value.get("created_at"), str) or not isinstance(value.get("updated_at"), str):
        raise RunnerError("Runner publication WAL pointer binding is invalid")
    return value


def update_runner_publication_wal(config: RunnerConfig, value: dict[str, Any], phase: str) -> dict[str, Any]:
    updated = {**value, "phase": phase, "updated_at": iso_now()}
    write_json(runner_publication_wal_path(config), updated)
    return updated


def complete_runner_publication_wal(config: RunnerConfig, wal: dict[str, Any]) -> dict[str, Any]:
    record = wal["record"]
    wal_config = replace(config, target=Path(record["target"]), name=record["runner_name"])
    run_dir = wal_config.artifacts_root / "runs" / wal_config.name / record["run_id"]
    manifest_path = run_dir / "sha256_manifest.json"
    state_path = run_dir / "state.json"
    if (
        strict_file_record(manifest_path, "WAL-bound runner manifest")["sha256"] != record["manifest_sha256"]
        or strict_file_record(state_path, "WAL-bound runner state")["sha256"] != record["state_sha256"]
    ):
        raise RunnerError("Runner publication WAL hashes disagree with the retained run")
    binding_matches = [
        row
        for row in read_runner_name_binding_ledger(config)
        if row.get("runner_name") == record["runner_name"] and row.get("target") == record["target"]
    ]
    if len(binding_matches) != 1 or binding_matches[0].get("binding_hash") != record.get("name_binding_hash"):
        raise RunnerError("Runner publication WAL name binding is missing or inconsistent")
    rows = read_runner_ledger(config)
    matches = [row for row in rows if row.get("record_id") == record["record_id"]]
    if not matches:
        previous = rows[-1]["ledger_hash"] if rows else "0" * 64
        if record["sequence"] != len(rows) + 1 or record["previous_ledger_hash"] != previous:
            raise RunnerError("Runner publication WAL no longer extends the exact ledger tip")
        ledger_path = runner_ledger_path(config)
        if os.path.lexists(ledger_path):
            strict_regular_file(ledger_path, "runner evidence ledger")
        with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        rows = read_runner_ledger(config)
        matches = [row for row in rows if row.get("record_id") == record["record_id"]]
    if len(matches) != 1 or canonical_json(matches[0]) != canonical_json(record):
        raise RunnerError("Runner publication WAL conflicts with its ledger anchor")
    if wal["phase"] == "INTENT_FSYNCED":
        wal = update_runner_publication_wal(config, wal, "LEDGER_ANCHORED")
    write_json(runner_terminal_path(wal_config), wal["pointer"])
    copy_latest(wal_config, state_path)
    if wal["phase"] != "POINTER_PUBLISHED":
        wal = update_runner_publication_wal(config, wal, "POINTER_PUBLISHED")
    verify_runner_record(
        wal_config,
        record["run_id"],
        require_latest=True,
        _ledger_lock_held=True,
        _allow_publication_wal=True,
    )
    wal_path = runner_publication_wal_path(config)
    strict_regular_file(wal_path, "completed runner publication WAL")
    wal_path.unlink()
    return wal["pointer"]


def recover_runner_publication(config: RunnerConfig, *, _ledger_lock_held: bool = False) -> Optional[dict[str, Any]]:
    if not _ledger_lock_held:
        lock = acquire_runner_ledger_lock(config)
        try:
            return recover_runner_publication(config, _ledger_lock_held=True)
        finally:
            lock.close()
    wal = read_runner_publication_wal(config)
    if wal is None:
        return None
    record = wal["record"]
    wal_config = replace(config, target=Path(record["target"]), name=record["runner_name"])
    terminal_path = runner_terminal_path(wal_config)
    latest_state_path = wal_config.artifacts_root / "latest" / f"{wal_config.name}_state.json"
    prior_terminal = (
        strict_read_bytes(terminal_path, "pre-recovery runner terminal pointer", max_bytes=MAX_RUNNER_MANIFEST_BYTES)
        if os.path.lexists(terminal_path)
        else None
    )
    prior_latest_state = (
        strict_read_bytes(latest_state_path, "pre-recovery runner latest state", max_bytes=MAX_RUNNER_MANIFEST_BYTES)
        if os.path.lexists(latest_state_path)
        else None
    )
    try:
        return complete_runner_publication_wal(config, wal)
    except BaseException:
        if prior_terminal is None:
            if os.path.lexists(terminal_path):
                strict_regular_file(terminal_path, "failed recovered runner terminal pointer")
                terminal_path.unlink()
        else:
            atomic_write_bytes(terminal_path, prior_terminal)
        if prior_latest_state is None:
            if os.path.lexists(latest_state_path):
                strict_regular_file(latest_state_path, "failed recovered runner latest state")
                latest_state_path.unlink()
        else:
            atomic_write_bytes(latest_state_path, prior_latest_state)
        raise


def prepare_runner_publication(config: RunnerConfig) -> None:
    lock = acquire_runner_ledger_lock(config)
    try:
        recover_runner_publication(config, _ledger_lock_held=True)
        path = runner_name_binding_ledger_path(config)
        binding_rows = read_runner_name_binding_ledger(config)
        bindings = {
            row["runner_name"].casefold(): (row["runner_name"], row["target"], row["binding_hash"])
            for row in binding_rows
        }
        for row in read_runner_ledger(config):
            expected = (row["runner_name"], row["target"], row["name_binding_hash"])
            if bindings.get(row["runner_name"].casefold()) != expected:
                raise RunnerError("Runner name-binding ledger disagrees with terminal evidence history")
        key = config.name.casefold()
        bound = bindings.get(key)
        if bound is not None and bound[:2] != (config.name, str(config.target)):
            raise RunnerError("Runner name is already bound to a different target")
        if bound is None:
            previous = binding_rows[-1]["binding_hash"] if binding_rows else "0" * 64
            unsigned = {
                "schema_version": "codex-light-runner.name-binding-ledger.v1",
                "sequence": len(binding_rows) + 1,
                "previous_binding_hash": previous,
                "runner_name": config.name,
                "target": str(config.target),
                "recorded_at": iso_now(),
            }
            row = {**unsigned, "binding_hash": json_sha256(unsigned)}
            if os.path.lexists(path):
                strict_regular_file(path, "runner name-binding ledger")
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(canonical_json(row) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            retained = read_runner_name_binding_ledger(config)
            if not retained or canonical_json(retained[-1]) != canonical_json(row):
                raise RunnerError("Runner name binding was not durably recorded")
    finally:
        lock.close()


def verify_runner_record(
    config: RunnerConfig,
    run_identifier: str,
    *,
    require_latest: bool = False,
    _ledger_lock_held: bool = False,
    _allow_publication_wal: bool = False,
) -> dict[str, Any]:
    if not isinstance(run_identifier, str) or not RUNNER_ID_RE.fullmatch(run_identifier) or Path(run_identifier).name != run_identifier:
        raise RunnerError("Runner record selector is not one safe run ID")
    if not _ledger_lock_held:
        lock = acquire_runner_ledger_lock(config)
        try:
            return verify_runner_record(
                config,
                run_identifier,
                require_latest=require_latest,
                _ledger_lock_held=True,
                _allow_publication_wal=_allow_publication_wal,
            )
        finally:
            lock.close()
    if os.path.lexists(runner_publication_wal_path(config)) and not _allow_publication_wal:
        raise RunnerError("Runner publication recovery is pending; terminal evidence is not yet publish-complete")
    run_parent = validate_no_reparse_ancestors(config.artifacts_root / "runs" / config.name, require_exists=True)
    run_dir = validate_no_reparse_ancestors(run_parent / run_identifier, require_exists=True)
    if run_dir.parent != run_parent or not run_dir.is_dir() or is_reparse(run_dir):
        raise RunnerError("Runner record path is outside its exact evidence parent")
    manifest_path = run_dir / "sha256_manifest.json"
    state_path = run_dir / "state.json"
    manifest = read_json_object(manifest_path, "runner evidence manifest")
    state = read_json_object(state_path, "runner terminal state")
    if set(manifest) != RUNNER_MANIFEST_KEYS or manifest.get("schema_version") != "codex-light-runner.manifest.v2":
        raise RunnerError("Runner evidence manifest schema is not v2")
    if set(state) != RUNNER_STATE_KEYS or state.get("version") != VERSION:
        raise RunnerError("Runner terminal state schema or version is invalid")
    if manifest.get("run_id") != run_identifier or state.get("run_id") != run_identifier:
        raise RunnerError("Runner run ID disagrees across state and manifest")
    if (
        state.get("status") not in RUNNER_TERMINAL_STATUSES
        or manifest.get("status") != state.get("status")
        or manifest.get("target") != state.get("target")
        or state.get("target") != str(config.target)
        or state.get("artifacts_dir") != str(run_dir)
    ):
        raise RunnerError("Runner status or target disagrees across state and manifest")

    entries = manifest.get("files")
    directories = manifest.get("directories")
    if not isinstance(entries, list) or not isinstance(directories, list):
        raise RunnerError("Runner evidence manifest files and directories must be lists")
    if directories != sorted(directories) or len(directories) != len(set(directories)):
        raise RunnerError("Runner evidence manifest directory list is duplicated or unsorted")
    for relative in directories:
        if not isinstance(relative, str):
            raise RunnerError("Runner evidence manifest contains an invalid directory")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts or pure.as_posix() != relative:
            raise RunnerError(f"Runner evidence manifest contains an unsafe directory: {relative}")
    expected: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != RUNNER_MANIFEST_FILE_KEYS:
            raise RunnerError("Runner evidence manifest contains a non-object entry")
        relative = entry.get("path")
        byte_count = entry.get("bytes")
        file_hash = entry.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or byte_count < 0
            or not isinstance(file_hash, str)
            or not LOWER_HEX_64_RE.fullmatch(file_hash)
        ):
            raise RunnerError("Runner evidence manifest contains an invalid path")
        pure = PurePosixPath(relative)
        if (
            pure.is_absolute()
            or not pure.parts
            or ".." in pure.parts
            or pure.as_posix() != relative
            or relative == "sha256_manifest.json"
            or relative in expected
        ):
            raise RunnerError(f"Runner evidence manifest contains an unsafe or duplicate path: {relative}")
        expected[relative] = {"bytes": byte_count, "sha256": file_hash}
    if list(expected) != sorted(expected):
        raise RunnerError("Runner evidence manifest file list is unsorted")
    actual, actual_directories = strict_tree_snapshot(run_dir, exclude_root_files={"sha256_manifest.json"})
    if actual != expected or actual_directories != set(directories):
        raise RunnerError("Runner evidence manifest file set is incomplete or contains extras")

    record_id = runner_record_id(config, run_identifier)
    ledger_rows = read_runner_ledger(config)
    matches = [row for row in ledger_rows if row.get("record_id") == record_id]
    if len(matches) != 1:
        raise RunnerError("Runner record is not uniquely anchored in the evidence ledger")
    row = matches[0]
    if (
        row.get("runner_name") != config.name
        or row.get("target") != str(config.target)
        or row.get("status") != state.get("status")
        or row.get("manifest_sha256") != strict_file_record(manifest_path, "runner manifest")["sha256"]
        or row.get("state_sha256") != strict_file_record(state_path, "runner terminal state")["sha256"]
    ):
        raise RunnerError("Runner evidence ledger record disagrees with the sealed run")
    binding_matches = [
        binding
        for binding in read_runner_name_binding_ledger(config)
        if binding.get("runner_name") == config.name and binding.get("target") == str(config.target)
    ]
    if len(binding_matches) != 1 or binding_matches[0].get("binding_hash") != row.get("name_binding_hash"):
        raise RunnerError("Runner evidence record disagrees with its name-binding ledger")

    if require_latest:
        latest = read_json_object(runner_terminal_path(config), "runner terminal pointer")
        if set(latest) != RUNNER_POINTER_KEYS or latest.get("schema_version") != "codex-light-runner.terminal-pointer.v1":
            raise RunnerError("Runner terminal pointer schema is invalid")
        required = {
            "record_id": record_id,
            "runner_name": config.name,
            "run_id": run_identifier,
            "status": state.get("status"),
            "target": str(config.target),
            "manifest_sha256": strict_file_record(manifest_path, "runner manifest")["sha256"],
            "state_sha256": strict_file_record(state_path, "runner terminal state")["sha256"],
            "ledger_hash": row.get("ledger_hash"),
        }
        if any(latest.get(key) != value for key, value in required.items()):
            raise RunnerError("Runner terminal pointer disagrees with the sealed ledger record")
        target_rows = [
            candidate
            for candidate in ledger_rows
            if candidate.get("runner_name") == config.name and candidate.get("target") == str(config.target)
        ]
        if not target_rows or target_rows[-1].get("record_id") != record_id:
            raise RunnerError("Runner terminal pointer does not identify the latest ledger record for this target")
    return row


def publish_runner_record(config: RunnerConfig, run_dir: Path, state: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    lock = acquire_runner_ledger_lock(config)
    try:
        recover_runner_publication(config, _ledger_lock_held=True)
        rows = read_runner_ledger(config)
        conflicting = [
            row
            for row in rows
            if row.get("runner_name") == config.name and row.get("target") != str(config.target)
        ]
        if conflicting:
            raise RunnerError("Runner name is already ledger-bound to a different target")
        binding_matches = [
            row
            for row in read_runner_name_binding_ledger(config)
            if row.get("runner_name") == config.name and row.get("target") == str(config.target)
        ]
        if len(binding_matches) != 1:
            raise RunnerError("Runner name binding is missing or ambiguous")
        name_binding_hash = binding_matches[0]["binding_hash"]
        manifest_hash = str(strict_file_record(manifest_path, "runner evidence manifest")["sha256"])
        state_hash = str(strict_file_record(run_dir / "state.json", "runner terminal state")["sha256"])
        terminal_path = runner_terminal_path(config)
        latest_state_path = config.artifacts_root / "latest" / f"{config.name}_state.json"
        previous_terminal = (
            strict_read_bytes(terminal_path, "prior runner terminal pointer", max_bytes=MAX_RUNNER_MANIFEST_BYTES)
            if os.path.lexists(terminal_path)
            else None
        )
        previous_latest_state = (
            strict_read_bytes(latest_state_path, "prior runner latest state", max_bytes=MAX_RUNNER_MANIFEST_BYTES)
            if os.path.lexists(latest_state_path)
            else None
        )
        record_id = runner_record_id(config, state["run_id"])
        matches = [row for row in rows if row.get("record_id") == record_id]
        if matches:
            row = matches[0]
            if (
                row.get("runner_name") != config.name
                or row.get("target") != str(config.target)
                or row.get("name_binding_hash") != name_binding_hash
                or row.get("status") != state["status"]
                or row.get("manifest_sha256") != manifest_hash
                or row.get("state_sha256") != state_hash
            ):
                raise RunnerError("Existing runner ledger record disagrees with the terminal evidence")
        else:
            previous = rows[-1]["ledger_hash"] if rows else "0" * 64
            unsigned = {
                "schema_version": "codex-light-runner.ledger.v1",
                "sequence": len(rows) + 1,
                "previous_ledger_hash": previous,
                "record_id": record_id,
                "runner_name": config.name,
                "run_id": state["run_id"],
                "status": state["status"],
                "target": str(config.target),
                "name_binding_hash": name_binding_hash,
                "manifest_sha256": manifest_hash,
                "state_sha256": state_hash,
                "recorded_at": iso_now(),
            }
            row = {**unsigned, "ledger_hash": json_sha256(unsigned)}

        pointer = {
            "schema_version": "codex-light-runner.terminal-pointer.v1",
            "record_id": record_id,
            "runner_name": config.name,
            "run_id": state["run_id"],
            "status": state["status"],
            "target": str(config.target),
            "manifest_sha256": manifest_hash,
            "state_sha256": state_hash,
            "ledger_hash": row["ledger_hash"],
        }
        now = iso_now()
        wal = {
            "schema_version": "codex-light-runner.publication-wal.v1",
            "phase": "INTENT_FSYNCED",
            "record": row,
            "pointer": pointer,
            "created_at": now,
            "updated_at": now,
        }
        write_json(runner_publication_wal_path(config), wal)
        try:
            return complete_runner_publication_wal(config, wal)
        except BaseException:
            if previous_terminal is None:
                if os.path.lexists(terminal_path):
                    strict_regular_file(terminal_path, "failed runner terminal pointer")
                    terminal_path.unlink()
            else:
                atomic_write_bytes(terminal_path, previous_terminal)
            if previous_latest_state is None:
                if os.path.lexists(latest_state_path):
                    strict_regular_file(latest_state_path, "failed runner latest state")
                    latest_state_path.unlink()
            else:
                atomic_write_bytes(latest_state_path, previous_latest_state)
            raise
    finally:
        lock.close()


def copy_latest(config: RunnerConfig, state_path: Path) -> None:
    latest_path = config.artifacts_root / "latest" / f"{config.name}_state.json"
    write_json(latest_path, read_json_object(state_path, "runner terminal state"))


def write_manifest(run_dir: Path, state: dict[str, Any]) -> Path:
    file_records, directories = strict_tree_snapshot(run_dir)
    entries = [{"path": path, **record} for path, record in file_records.items()]
    manifest = run_dir / "sha256_manifest.json"
    write_json(manifest, {"schema_version": "codex-light-runner.manifest.v2",
                          "run_id": state["run_id"], "status": state["status"],
                          "target": state["target"], "created_at": iso_now(),
                          "directories": sorted(directories), "files": entries})
    return manifest


def finalize_runner_state(config: RunnerConfig, run_dir: Path, state: dict[str, Any]) -> dict[str, Any]:
    state_path = run_dir / "state.json"
    running_path = run_dir / "running_state.json"
    manifest_path = run_dir / "sha256_manifest.json"
    if os.path.lexists(manifest_path):
        retained_state = read_json_object(state_path, "retained runner terminal state")
        if canonical_json(retained_state) != canonical_json(state):
            raise RunnerError("A sealed runner state cannot be rewritten with a different terminal outcome")
        read_json_object(manifest_path, "retained runner evidence manifest")
    else:
        write_json(state_path, state)
        if os.path.lexists(running_path):
            strict_regular_file(running_path, "runner live state")
            running_path.unlink()
        manifest_path = write_manifest(run_dir, state)
    pointer = publish_runner_record(config, run_dir, state, manifest_path)
    return pointer


def print_human_summary(state: dict[str, Any]) -> None:
    print("\n=== CodexLightRunner v3 Summary ===")
    print(f"status:       {state['status']}")
    print(f"reason:       {state['reason']}")
    print(f"target:       {state['target']}")
    print(f"artifacts:    {state['artifacts_dir']}")
    print(f"classification: {state['deterministic_classification']['classification']}")
    if state.get("ollama_classification"):
        ollama = state["ollama_classification"]
        endpoint = ollama.get("endpoint", {})
        used = endpoint.get("base_url", "none")
        print(f"ollama:       {ollama.get('classification')} via {used}")
    if state.get("codex_prompt"):
        print(f"codex prompt: {state['codex_prompt']}")


def run(config: RunnerConfig) -> int:
    rid = run_id()
    run_dir = ensure_dirs(config, rid)
    prepare_runner_publication(config)
    lock_path = acquire_lock(config, run_dir)
    started_at = iso_now()
    run_dir_created = False
    terminalized = False
    terminal_state: Optional[dict[str, Any]] = None
    preflight_result: Optional[CommandResult] = None
    attempts: list[CommandResult] = []
    final_result: Optional[CommandResult] = None
    deterministic = {"classification": "UNKNOWN", "summary": "not run", "codex_needed": False}
    ollama_decision: Optional[dict[str, Any]] = None
    codex_prompt_path: Optional[Path] = None

    def make_state(status: str, reason: str, return_code: Optional[int]) -> dict[str, Any]:
        classification = deterministic
        if status == "INTERRUPTED":
            classification = {"classification": "INTERRUPTED", "summary": reason, "codex_needed": False}
        elif final_result is None:
            classification = {"classification": "RUNNER_ERROR", "summary": reason, "codex_needed": True}
        return {
            "version": VERSION,
            "run_id": rid,
            "target": str(config.target),
            "target_args": redact(config.target_args),
            "python": str(config.python),
            "cwd": str(config.cwd),
            "command": redact(config.target_command),
            "status": status,
            "reason": reason,
            "return_code": return_code,
            "started_at": started_at,
            "ended_at": iso_now(),
            "artifacts_dir": str(run_dir),
            "preflight": asdict(preflight_result) if preflight_result else None,
            "attempts": [asdict(item) for item in attempts],
            "deterministic_classification": classification,
            "ollama_classification": ollama_decision,
            "codex_prompt": str(codex_prompt_path) if codex_prompt_path else None,
            "kill_switch": str(config.kill_switch_path),
        }

    try:
        if config.kill_switch_path.exists():
            raise RunnerError(f"Stale kill switch exists before launch: {config.kill_switch_path}")
        run_dir.mkdir(parents=False, exist_ok=False)
        run_dir_created = True
        metadata = execution_metadata(config)
        write_json(
            run_dir / "effective_command.json",
            {
                "version": VERSION,
                "target": str(config.target),
                "target_args": redact(config.target_args),
                "python": str(config.python),
                "cwd": str(config.cwd),
                "command": redact(config.target_command),
                "ollama_enabled": config.ollama_enabled,
                "ollama_endpoints": list(DEFAULT_OLLAMA_ENDPOINTS) if config.ollama_enabled else [],
                "execution_metadata": metadata,
            },
        )
        running_state={"status":"RUNNING","run_id":rid,"pid":os.getpid(),"started_at":started_at,"artifacts_dir":str(run_dir)}
        write_json(run_dir / "running_state.json",running_state)
        write_json(config.artifacts_root / "latest" / f"{config.name}_state.json",running_state)

        if config.preflight:
            preflight_result = run_preflight(config, run_dir)
            if preflight_result and preflight_result.status != "SUCCESS":
                final_result = preflight_result
                final_result.status = "FAILED"
                final_result.reason = "py_compile preflight failed"

        if final_result is None:
            for attempt in range(1, config.retries + 2):
                result = run_target_once(config, run_dir, attempt)
                attempts.append(result)
                final_result = result
                if result.status == "SUCCESS":
                    break
                if attempt <= config.retries and result.status in RETRYABLE_STATUSES:
                    time.sleep(config.retry_delay_seconds)

        assert final_result is not None
        deterministic = classify_failure(final_result)

        evidence = ""
        if final_result.status != "SUCCESS":
            evidence = build_failure_evidence(config, final_result, deterministic)
            (run_dir / "failure_evidence.md").write_text(evidence, encoding="utf-8")
            if config.ollama_enabled:
                ollama_decision = query_ollama(config, evidence)
                write_json(run_dir / "ollama_advisory.json", ollama_decision)
            if config.codex_prompt:
                codex_prompt_path = write_codex_prompt(config, run_dir, evidence, deterministic, ollama_decision)

        terminal_state = make_state(final_result.status, final_result.reason, final_result.return_code)
        finalize_runner_state(config, run_dir, terminal_state)
        terminalized = True

        if config.json_stdout:
            print(json.dumps(terminal_state, indent=2, default=str))
        else:
            print_human_summary(terminal_state)

        return 0 if final_result.status == "SUCCESS" else 2
    except KeyboardInterrupt as exc:
        if run_dir_created and not terminalized:
            if terminal_state is None:
                terminal_state = make_state("INTERRUPTED", "operator keyboard interrupt", None)
            try:
                finalize_runner_state(config, run_dir, terminal_state)
                terminalized = True
            except BaseException as finalization_error:
                exc.add_note(f"runner evidence finalization also failed: {type(finalization_error).__name__}: {finalization_error}")
        raise
    except BaseException as exc:
        if run_dir_created and not terminalized:
            if terminal_state is None:
                detail = " ".join(str(exc).split())[:1000] or "unspecified runner failure"
                terminal_state = make_state("FAILED", f"{type(exc).__name__}: {detail}", None)
            try:
                finalize_runner_state(config, run_dir, terminal_state)
                terminalized = True
            except BaseException as finalization_error:
                exc.add_note(f"runner evidence finalization also failed: {type(finalization_error).__name__}: {finalization_error}")
        if isinstance(exc, RunnerError):
            raise
        detail = " ".join(str(exc).split())[:1000] or "unspecified runner failure"
        raise RunnerError(f"{type(exc).__name__}: {detail}") from exc
    finally:
        release_lock(lock_path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        config = make_config(argv)
        if config is None:
            return 0
        if config.dry_run:
            print(json.dumps({
                "version": VERSION,
                "target": str(config.target),
                "target_args": config.target_args,
                "python": str(config.python),
                "cwd": str(config.cwd),
                "command": config.target_command,
                "artifacts_root": str(config.artifacts_root),
                "kill_switch": str(config.kill_switch_path),
                "ollama_enabled": config.ollama_enabled,
                "ollama_model": config.ollama_model,
                "ollama_endpoints": list(DEFAULT_OLLAMA_ENDPOINTS) if config.ollama_enabled else [],
                "environment_policy": "minimal" if config.minimal_env else "inherited",
            }, indent=2))
            return 0
        return run(config)
    except KeyboardInterrupt:
        print("Interrupted by operator.", file=sys.stderr)
        return 130
    except RunnerError as exc:
        print(f"[runner error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
