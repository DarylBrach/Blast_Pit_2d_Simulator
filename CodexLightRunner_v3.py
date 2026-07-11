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
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Iterable, Optional, Sequence

VERSION = "3.0.0"
DEFAULT_ROOT = Path(os.path.expanduser("~")) / ".codex_light_runner"
DEFAULT_TAIL_LINES = 300
DEFAULT_TIMEOUT_SECONDS = 3600
DEFAULT_STALL_SECONDS = 600
DEFAULT_GRACE_SECONDS = 8
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 15
DEFAULT_KILL_SWITCH = ".supervisor_stop"

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
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


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
    run_dir = config.artifacts_root / "runs" / config.name / rid
    run_dir.mkdir(parents=True, exist_ok=True)
    (config.artifacts_root / "locks").mkdir(parents=True, exist_ok=True)
    (config.artifacts_root / "latest").mkdir(parents=True, exist_ok=True)
    return run_dir


def lock_key(config: RunnerConfig) -> str:
    payload = json.dumps(
        {"target": str(config.target), "cwd": str(config.cwd), "args": config.target_args},
        sort_keys=True,
    )
    return f"{config.name}_{short_hash(payload)}"


def acquire_lock(config: RunnerConfig, run_dir: Path) -> Optional[Path]:
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

    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            existing = json.loads(lock_path.read_text(encoding="utf-8"))
            pid = int(existing.get("pid", 0))
        except Exception:
            pid = 0
        if pid and process_alive(pid):
            raise RunnerError(f"A matching run is already active under PID {pid}. Use --allow-parallel to override.")
        lock_path.unlink(missing_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)

    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return lock_path


def release_lock(lock_path: Optional[Path]) -> None:
    if lock_path:
        lock_path.unlink(missing_ok=True)


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
                print(text, end="", file=output, flush=True)


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
                write_json(attempt_dir / "heartbeat.json", {"status": "RUNNING", "pid": proc.pid,
                           "updated_at": iso_now(), "elapsed_seconds": round(elapsed, 2),
                           "idle_seconds": round(activity.idle_seconds(), 2)})
                last_heartbeat = elapsed
            time.sleep(0.5)
    except KeyboardInterrupt:
        terminate_process_tree(proc)
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


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def copy_latest(config: RunnerConfig, state_path: Path) -> None:
    latest_path = config.artifacts_root / "latest" / f"{config.name}_state.json"
    write_json(latest_path, json.loads(state_path.read_text(encoding="utf-8")))


def write_manifest(run_dir: Path) -> Path:
    entries = []
    for path in sorted(run_dir.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_file() and path.name != "sha256_manifest.json" and not path.name.endswith(".tmp"):
            entries.append({"path": path.relative_to(run_dir).as_posix(), "bytes": path.stat().st_size,
                            "sha256": sha256_file(path)})
    manifest = run_dir / "sha256_manifest.json"
    write_json(manifest, {"schema_version": "codex-light-runner.manifest.v1",
                          "created_at": iso_now(), "files": entries})
    return manifest


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
    lock_path = acquire_lock(config, run_dir)
    started_at = iso_now()
    preflight_result: Optional[CommandResult] = None
    attempts: list[CommandResult] = []
    final_result: Optional[CommandResult] = None
    deterministic = {"classification": "UNKNOWN", "summary": "not run", "codex_needed": False}
    ollama_decision: Optional[dict[str, Any]] = None
    codex_prompt_path: Optional[Path] = None

    try:
        if config.kill_switch_path.exists():
            raise RunnerError(f"Stale kill switch exists before launch: {config.kill_switch_path}")
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
        write_json(run_dir / "running_state.json", {"status": "RUNNING", "run_id": rid,
                   "pid": os.getpid(), "started_at": started_at})

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

        ended_at = iso_now()
        state = {
            "version": VERSION,
            "run_id": rid,
            "target": str(config.target),
            "target_args": redact(config.target_args),
            "python": str(config.python),
            "cwd": str(config.cwd),
            "command": redact(config.target_command),
            "status": final_result.status,
            "reason": final_result.reason,
            "return_code": final_result.return_code,
            "started_at": started_at,
            "ended_at": ended_at,
            "artifacts_dir": str(run_dir),
            "preflight": asdict(preflight_result) if preflight_result else None,
            "attempts": [asdict(item) for item in attempts],
            "deterministic_classification": deterministic,
            "ollama_classification": ollama_decision,
            "codex_prompt": str(codex_prompt_path) if codex_prompt_path else None,
            "kill_switch": str(config.kill_switch_path),
        }
        state_path = run_dir / "state.json"
        write_json(state_path, state)
        (run_dir / "running_state.json").unlink(missing_ok=True)
        copy_latest(config, state_path)
        write_manifest(run_dir)

        if config.json_stdout:
            print(json.dumps(state, indent=2, default=str))
        else:
            print_human_summary(state)

        return 0 if final_result.status == "SUCCESS" else 2
    except KeyboardInterrupt:
        interrupted = {
            "version": VERSION, "run_id": rid, "status": "INTERRUPTED",
            "reason": "operator keyboard interrupt", "target": str(config.target),
            "command": redact(config.target_command), "started_at": started_at,
            "ended_at": iso_now(), "artifacts_dir": str(run_dir),
        }
        write_json(run_dir / "state.json", interrupted)
        (run_dir / "running_state.json").unlink(missing_ok=True)
        copy_latest(config, run_dir / "state.json")
        write_manifest(run_dir)
        raise
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
