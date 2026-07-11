from __future__ import annotations

"""Security and process primitives for the governed v2 improvement harness."""

import hashlib
import json
import os
import re
import base64
import shutil
import stat
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import quote

import CodexImprovementController_v1 as legacy


ROLE_POLICY_VERSION = "tool-less-roles-candidate-sandbox-v2"
RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
PATCH_HEADER_RE = re.compile(r"^diff --git a/([^\s]+) b/([^\s]+)$")
PATCH_INDEX_RE = re.compile(r"^index [a-f0-9]+\.\.[a-f0-9]+(?: [0-7]{6})?$")
PATCH_HUNK_RE = re.compile(r"^@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@(?: .*)?$")
MAX_ROLE_STREAM_BYTES = 8_000_000
MAX_PROCESS_STREAM_BYTES = 8_000_000
FORBIDDEN_PATCH_METADATA = (
    "GIT binary patch",
    "Binary files ",
    "new file mode ",
    "deleted file mode ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Submodule ",
)


class RuntimeFailure(RuntimeError):
    pass


class RuntimeTimeout(RuntimeFailure):
    pass


@dataclass(frozen=True)
class ProcessResult:
    command: list[str]
    cwd: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class _WindowsJob:
    """Kill-on-close Job Object assigned before a suspended child can execute."""

    def __init__(self, process: subprocess.Popen[str]):
        import ctypes
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimit),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._ntdll = ctypes.WinDLL("ntdll")
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        self._ntdll.NtResumeProcess.restype = ctypes.c_long
        self._lock = threading.Lock()
        self._closed = False
        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise RuntimeFailure(f"CreateJobObjectW failed: {ctypes.get_last_error()}")
        try:
            information = ExtendedLimit()
            information.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self._kernel32.SetInformationJobObject(
                self._handle, 9, ctypes.byref(information), ctypes.sizeof(information)
            ):
                raise RuntimeFailure(f"SetInformationJobObject failed: {ctypes.get_last_error()}")
            if not self._kernel32.AssignProcessToJobObject(self._handle, int(process._handle)):
                raise RuntimeFailure(f"AssignProcessToJobObject failed: {ctypes.get_last_error()}")
            status = int(self._ntdll.NtResumeProcess(int(process._handle)))
            if status != 0:
                raise RuntimeFailure(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
        except Exception:
            self.terminate_and_close(require_success=False)
            raise

    def terminate_and_close(self, *, require_success: bool = True) -> None:
        import ctypes

        with self._lock:
            if self._closed:
                return
            terminated = bool(self._kernel32.TerminateJobObject(self._handle, 1))
            closed = bool(self._kernel32.CloseHandle(self._handle))
            self._closed = True
            if require_success and (not terminated or not closed):
                raise RuntimeFailure(
                    f"Windows Job Object termination failed: terminate={terminated}, close={closed}, error={ctypes.get_last_error()}"
                )


def _spawn_process(command: Sequence[str], **kwargs: Any) -> tuple[subprocess.Popen[str], _WindowsJob | None]:
    creationflags = kwargs.pop("creationflags", 0)
    if sys.platform == "win32":
        creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004  # CREATE_SUSPENDED
    process = subprocess.Popen(
        list(command),
        creationflags=creationflags,
        start_new_session=sys.platform != "win32",
        **kwargs,
    )
    if sys.platform != "win32":
        return process, None
    try:
        return process, _WindowsJob(process)
    except Exception:
        process.kill()
        process.wait(timeout=15)
        raise


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    legacy.atomic_json(path, value)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def validate_no_reparse_ancestors(path: Path, *, require_exists: bool = False) -> Path:
    absolute = lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists():
            break
        if is_reparse(current):
            raise RuntimeFailure(f"symlink or reparse-point path is forbidden: {current}")
    if require_exists and not absolute.exists():
        raise RuntimeFailure(f"required path does not exist: {absolute}")
    return absolute.resolve(strict=require_exists)


def require_strict_descendant(path: Path, root: Path, label: str) -> Path:
    resolved_root = validate_no_reparse_ancestors(root, require_exists=True)
    resolved = validate_no_reparse_ancestors(path, require_exists=False)
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise RuntimeFailure(f"{label} is outside its authorized root: {resolved}")
    return resolved


def roots_are_disjoint(paths: Sequence[Path]) -> bool:
    resolved = [lexical_absolute(path).resolve(strict=False) for path in paths]
    for index, left in enumerate(resolved):
        for right in resolved[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                return False
    return True


def safe_remove_tree(root: Path, authorized_root: Path) -> None:
    resolved = require_strict_descendant(root, authorized_root, "cleanup target")
    if not resolved.exists():
        return
    files: list[Path] = []
    directories: list[Path] = [resolved]
    for current, names, filenames in os.walk(resolved, topdown=True, followlinks=False):
        current_path = Path(current)
        if is_reparse(current_path):
            raise RuntimeFailure(f"unsafe cleanup root quarantined: {current_path}")
        for name in names:
            target = current_path / name
            if is_reparse(target):
                raise RuntimeFailure(f"unsafe cleanup entry quarantined: {target}")
            directories.append(target)
        for name in filenames:
            target = current_path / name
            if is_reparse(target) or not target.is_file() or target.stat(follow_symlinks=False).st_nlink != 1:
                raise RuntimeFailure(f"unsafe cleanup entry quarantined: {target}")
            files.append(target)
    for target in files:
        os.unlink(target)
    for target in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        os.rmdir(target)


def strict_manifest(root: Path, *, max_files: int = 20_000, max_bytes: int = 256_000_000) -> dict[str, dict[str, Any]]:
    root = validate_no_reparse_ancestors(root, require_exists=True)
    rows: dict[str, dict[str, Any]] = {}
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            candidate = current_path / name
            if is_reparse(candidate):
                raise RuntimeFailure(f"reparse directory is forbidden: {candidate}")
        for name in files:
            candidate = current_path / name
            if is_reparse(candidate) or not candidate.is_file():
                raise RuntimeFailure(f"non-regular file is forbidden: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            before = candidate.stat(follow_symlinks=False)
            if before.st_nlink != 1:
                raise RuntimeFailure(f"hard-linked file is forbidden: {candidate}")
            size = before.st_size
            total += size
            file_hash = legacy.sha256_file(candidate)
            after = candidate.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise RuntimeFailure(f"file changed while manifesting: {candidate}")
            rows[relative] = {
                "kind": "file",
                "bytes": size,
                "sha256": file_hash,
            }
            if len(rows) > max_files or total > max_bytes:
                raise RuntimeFailure("bounded tree manifest limit exceeded")
    return dict(sorted(rows.items()))


def copy_regular_tree(source: Path, target: Path) -> str:
    source_manifest = strict_manifest(source, max_files=5_000, max_bytes=32_000_000)
    validate_no_reparse_ancestors(target.parent, require_exists=False)
    if target.exists():
        raise RuntimeFailure(f"copy target already exists: {target}")
    target.mkdir(parents=True, exist_ok=False)
    for relative in source_manifest:
        source_file = source / relative
        target_file = target / relative
        target_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target_file)
    copied_manifest = strict_manifest(target, max_files=5_000, max_bytes=32_000_000)
    if copied_manifest != source_manifest:
        raise RuntimeFailure("trusted cache copy verification failed")
    return sha256_json(copied_manifest)


def secret_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in secret_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in secret_strings(child)]
    return [value] if isinstance(value, str) and len(value) >= 8 else []


def secret_variants(values: Sequence[str]) -> list[str]:
    variants: set[str] = set()
    for value in values:
        if not value:
            continue
        variants.add(value)
        variants.add(quote(value, safe=""))
        variants.add(base64.b64encode(value.encode("utf-8")).decode("ascii"))
        variants.add(value.encode("utf-8").hex())
        escaped = json.dumps(value, ensure_ascii=True)[1:-1]
        if escaped:
            variants.add(escaped)
    return sorted((item for item in variants if len(item) >= 8), key=len, reverse=True)


def redact(value: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret:
            value = value.replace(secret, "<redacted>")
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1<redacted>", value)
    return re.sub(
        r"(?i)((?:api[_-]?key|authorization|credential|password|secret|token)\s*[:=]\s*)[^\s,;]{12,}",
        r"\1<redacted>",
        value,
    )


def reject_secret_value(value: Any, secrets: Sequence[str]) -> None:
    encoded = canonical(value)
    if any(secret and secret in encoded for secret in secrets):
        raise RuntimeFailure("structured output contained authentication material")


def _minimal_environment(temp: Path, codex_home: Path | None = None) -> dict[str, str]:
    allowed = {
        "APPDATA",
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update({"TEMP": str(temp), "TMP": str(temp), "PYTHONNOUSERSITE": "1", "PYTHONPATH": ""})
    if codex_home is not None:
        environment["CODEX_HOME"] = str(codex_home)
    return environment


def prepare_toolless_role_environment(isolation: Path, real_codex_home: Path) -> tuple[dict[str, str], list[str], str, Path]:
    isolation.mkdir(parents=True, exist_ok=False)
    home = isolation / "codex_home"
    temp = isolation / "temp"
    cwd = isolation / "empty_workspace"
    home.mkdir()
    temp.mkdir()
    cwd.mkdir()
    real_auth = validate_no_reparse_ancestors(real_codex_home / "auth.json", require_exists=True)
    real_auth_info = real_auth.stat(follow_symlinks=False)
    if not real_auth.is_file() or real_auth_info.st_size > 1_000_000 or real_auth_info.st_nlink != 1:
        raise RuntimeFailure("real Codex authentication file is invalid")
    try:
        auth_record = json.loads(real_auth.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeFailure("real Codex authentication is not valid JSON") from exc
    secrets = secret_variants(secret_strings(auth_record))
    shutil.copy2(real_auth, home / "auth.json")
    copied_auth = home / "auth.json"
    if copied_auth.stat(follow_symlinks=False).st_nlink != 1 or is_reparse(copied_auth):
        raise RuntimeFailure("isolated Codex authentication copy is unsafe")
    plugin_policy_evidence = "plugins-disabled-by-policy"
    config = """default_permissions = "reviewer"
approval_policy = "never"
web_search = "disabled"
check_for_update_on_startup = false

[analytics]
enabled = false

[apps._default]
enabled = false
open_world_enabled = false
destructive_enabled = false

[features]
shell_tool = false
shell_snapshot = false
plugins = false
apps = false
browser_use = false
computer_use = false
image_generation = false
in_app_browser = false
multi_agent = false
tool_search = false
tool_suggest = false
codex_hooks = false
tool_call_mcp_elicitation = false
workspace_dependencies = false
remote_plugin = false
skill_mcp_dependency_install = false

[tools]
web_search = false
view_image = false

[permissions.reviewer.filesystem]
":minimal" = "read"

[permissions.reviewer.network]
enabled = false
"""
    atomic_text(home / "config.toml", config)
    environment = _minimal_environment(temp, home)
    return environment, secrets, plugin_policy_evidence, cwd


def _terminate_process_tree(process: subprocess.Popen[str], job: _WindowsJob | None = None) -> None:
    if sys.platform == "win32":
        if job is not None:
            job.terminate_and_close()
        elif process.poll() is None:
            completed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode != 0:
                raise RuntimeFailure(f"taskkill failed for process tree {process.pid}: {completed.returncode}")
    else:
        if process.poll() is None:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        raise RuntimeFailure(f"process tree {process.pid} did not terminate")


def _event_item_type(record: dict[str, Any]) -> str | None:
    item = record.get("item")
    return item.get("type") if isinstance(item, dict) else None


def streamed_toolless_codex(
    args: Sequence[str | Path],
    prompt: str,
    cwd: Path,
    timeout: int,
    events_path: Path,
    stderr_path: Path,
    environment: dict[str, str],
    secrets: Sequence[str],
    auth_path: Path,
    lifecycle_path: Path | None = None,
) -> ProcessResult:
    command = [str(value) for value in args]
    process, job = _spawn_process(
        command,
        cwd=str(cwd),
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    process.stdin.write(prompt)
    process.stdin.close()
    stdout_rows: list[str] = []
    stderr_rows: list[str] = []
    violations: list[str] = []
    auth_info = auth_path.stat(follow_symlinks=False) if auth_path.is_file() else None
    lifecycle: dict[str, Any] = {
        "schema_version": "blast-pit.codex-auth-lifecycle.v1",
        "thread": False,
        "turn": False,
        "auth_deleted": False,
        "isolated_auth_path_sha256": hashlib.sha256(str(auth_path).encode("utf-8")).hexdigest(),
        "auth_initial_bytes": auth_info.st_size if auth_info else None,
        "auth_initial_nlink": auth_info.st_nlink if auth_info else None,
        "auth_initial_file_id": [auth_info.st_dev, auth_info.st_ino] if auth_info else None,
        "thread_event_line": None,
        "turn_event_line": None,
        "auth_deleted_at_utc": None,
        "post_run_auth_absent": False,
    }
    lifecycle_lock = threading.Lock()
    output_bytes = 0
    line_number = 0

    allowed_event_types = {
        "thread.started",
        "turn.started",
        "turn.completed",
        "turn.failed",
        "error",
        "item.started",
        "item.updated",
        "item.completed",
    }
    allowed_item_types = {None, "agent_message", "reasoning", "error"}

    def stdout_reader() -> None:
        nonlocal output_bytes, line_number
        for line in process.stdout:
            encoded_size = len(line.encode("utf-8", errors="replace"))
            output_bytes += encoded_size
            line_number += 1
            if output_bytes > MAX_ROLE_STREAM_BYTES:
                violations.append("Codex role stdout exceeded retained-output bound")
                _terminate_process_tree(process, job)
                break
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                violations.append(f"malformed Codex JSONL event at line {line_number}")
                record = {}
            event_type = record.get("type")
            with lifecycle_lock:
                if event_type not in allowed_event_types:
                    violations.append(f"unexpected Codex event type: {event_type!r}")
                if event_type == "thread.started":
                    if lifecycle["thread"]:
                        violations.append("duplicate thread.started")
                    lifecycle["thread"] = True
                    lifecycle["thread_event_line"] = line_number
                    try:
                        auth_path.unlink()
                    except OSError as exc:
                        violations.append(f"auth deletion failed: {type(exc).__name__}")
                    lifecycle["auth_deleted"] = not auth_path.exists()
                    if lifecycle["auth_deleted"]:
                        from datetime import datetime, timezone

                        lifecycle["auth_deleted_at_utc"] = datetime.now(timezone.utc).isoformat()
                elif event_type == "turn.started":
                    if lifecycle["turn"]:
                        violations.append("duplicate turn.started")
                    lifecycle["turn"] = True
                    lifecycle["turn_event_line"] = line_number
                    if not lifecycle["thread"] or not lifecycle["auth_deleted"] or auth_path.exists():
                        violations.append("turn.started preceded proven auth deletion")
                item_type = _event_item_type(record)
                if item_type not in allowed_item_types:
                    violations.append(f"tool-less role attempted or emitted unexpected item type: {item_type!r}")
            stdout_rows.append(redact(line, secrets))

    def stderr_reader() -> None:
        nonlocal output_bytes
        for line in process.stderr:
            output_bytes += len(line.encode("utf-8", errors="replace"))
            if output_bytes > MAX_ROLE_STREAM_BYTES:
                violations.append("Codex role combined output exceeded retained-output bound")
                _terminate_process_tree(process, job)
                break
            lowered = line.lower()
            if "plugins-clone" in lowered or "startup_sync" in lowered or "github http" in lowered:
                violations.append("unexpected plugin/catalog synchronization")
            stderr_rows.append(redact(line, secrets))

    readers = [threading.Thread(target=stdout_reader, daemon=True), threading.Thread(target=stderr_reader, daemon=True)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(process, job)
    else:
        if job is not None:
            job.terminate_and_close()
    finally:
        for reader in readers:
            reader.join(timeout=10)
    if any(reader.is_alive() for reader in readers):
        raise RuntimeFailure("Codex role output reader remained alive after process-tree termination")
    stdout = "".join(stdout_rows)
    stderr = "".join(stderr_rows)
    atomic_text(events_path, stdout)
    atomic_text(stderr_path, stderr)
    if timed_out:
        lifecycle["post_run_auth_absent"] = not auth_path.exists()
        if lifecycle_path is not None:
            atomic_json(lifecycle_path, {**lifecycle, "violations": sorted(set(violations)), "timed_out": True})
        raise RuntimeTimeout("tool-less Codex role timed out")
    if auth_path.exists():
        violations.append("isolated authentication reappeared")
    if not lifecycle["thread"] or not lifecycle["turn"] or not lifecycle["auth_deleted"]:
        violations.append("incomplete Codex auth lifecycle evidence")
    lifecycle["post_run_auth_absent"] = not auth_path.exists()
    if lifecycle_path is not None:
        atomic_json(lifecycle_path, {**lifecycle, "violations": sorted(set(violations)), "timed_out": False})
    if violations:
        raise RuntimeFailure("; ".join(sorted(set(violations))))
    return ProcessResult(command, str(cwd), int(process.returncode), stdout, stderr)


def run_toolless_codex_role(
    *,
    codex: Path,
    model: str,
    schema: Path,
    prompt: str,
    role: str,
    evidence_dir: Path,
    isolation: Path,
    isolation_root: Path,
    real_codex_home: Path,
    timeout: int,
) -> dict[str, Any]:
    evidence_dir.mkdir(parents=True, exist_ok=False)
    environment: dict[str, str] | None = None
    secrets: list[str] = []
    plugin_policy_evidence = ""
    try:
        environment, secrets, plugin_policy_evidence, cwd = prepare_toolless_role_environment(isolation, real_codex_home)
        output = evidence_dir / "final.json"
        args = [
            codex,
            "exec",
            "--cd",
            cwd,
            "--skip-git-repo-check",
            "--model",
            model,
            "--ephemeral",
            "--ignore-rules",
            "--json",
            "--output-schema",
            schema,
            "--output-last-message",
            output,
            "-",
        ]
        atomic_json(
            evidence_dir / "prompt_meta.json",
            {
                "role": role,
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "prompt_bytes": len(prompt.encode("utf-8")),
                "schema": str(schema),
                "schema_sha256": legacy.canonical_text_sha256(schema),
                "tool_policy": ROLE_POLICY_VERSION,
                "plugin_policy_evidence": plugin_policy_evidence,
                "prompt_via": "stdin",
            },
        )
        result = streamed_toolless_codex(
            args,
            prompt,
            cwd,
            timeout,
            evidence_dir / "events.jsonl",
            evidence_dir / "stderr.log",
            environment,
            secrets,
            Path(environment["CODEX_HOME"]) / "auth.json",
            evidence_dir / "auth_lifecycle.json",
        )
        atomic_json(evidence_dir / "command.json", {**asdict(result), "prompt": "<stdin>"})
        if result.return_code != 0:
            raise RuntimeFailure(f"tool-less Codex role {role} failed with exit {result.return_code}")
        if not output.is_file() or output.is_symlink() or output.stat().st_size > 500_000:
            raise RuntimeFailure(f"tool-less Codex role {role} produced unsafe output")
        raw = output.read_text(encoding="utf-8")
        if any(secret and secret in raw for secret in secrets):
            for secret in secrets:
                raw = raw.replace(secret, "<redacted>")
            atomic_text(output, raw)
            raise RuntimeFailure("structured role output contained authentication material")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeFailure("structured role output must be an object")
        reject_secret_value(value, secrets)
        return value
    finally:
        if isolation.exists():
            safe_remove_tree(isolation, isolation_root)


def sandbox_config_text(profile: str, write_roots: Sequence[Path], implementation: str = "unelevated") -> str:
    if implementation != "unelevated":
        raise RuntimeFailure("governed candidate execution requires the qualified unelevated Windows sandbox")
    if not roots_are_disjoint(write_roots):
        raise RuntimeFailure("sandbox write roots must be pairwise non-nested")
    lines = [
        f'default_permissions = "{profile}"',
        'approval_policy = "never"',
        "",
        "[windows]",
        f'sandbox = "{implementation}"',
        "sandbox_private_desktop = true",
        "",
        f"[permissions.{profile}.filesystem]",
        '":minimal" = "read"',
    ]
    for path in write_roots:
        escaped = str(path.resolve()).replace("\\", "\\\\")
        lines.append(f'"{escaped}" = "write"')
    lines.extend(["", f"[permissions.{profile}.network]", "enabled = false", ""])
    return "\n".join(lines)


def prepare_candidate_sandbox(
    isolation: Path,
    isolation_root: Path,
    write_roots: Sequence[Path],
    *,
    profile: str = "candidate",
    implementation: str = "unelevated",
) -> tuple[dict[str, str], Path]:
    require_strict_descendant(isolation, isolation_root, "sandbox isolation")
    isolation.mkdir(parents=True, exist_ok=False)
    home = isolation / "codex_home"
    temp = isolation / "temp"
    home.mkdir()
    temp.mkdir()
    all_roots = [*write_roots, temp]
    for root in all_roots:
        if not root.exists():
            raise RuntimeFailure(f"sandbox write root must be pre-created by the controller: {root}")
        if not root.is_dir():
            raise RuntimeFailure(f"sandbox write root is not a directory: {root}")
        validate_no_reparse_ancestors(root, require_exists=True)
    atomic_text(home / "config.toml", sandbox_config_text(profile, all_roots, implementation))
    return _minimal_environment(temp, home), temp


def run_process(
    args: Sequence[str | Path],
    cwd: Path,
    timeout: int,
    *,
    environment: dict[str, str] | None = None,
    secrets: Sequence[str] = (),
    evidence: Path | None = None,
) -> ProcessResult:
    command = [str(value) for value in args]
    process, job = _spawn_process(
        command,
        cwd=str(cwd),
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_rows: list[str] = []
    stderr_rows: list[str] = []
    output_bytes = 0
    overflow = False
    output_lock = threading.Lock()

    def reader(stream: Any, rows: list[str]) -> None:
        nonlocal output_bytes, overflow
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            with output_lock:
                size = len(chunk.encode("utf-8", errors="replace"))
                if output_bytes + size > MAX_PROCESS_STREAM_BYTES:
                    remaining = max(0, MAX_PROCESS_STREAM_BYTES - output_bytes)
                    if remaining:
                        rows.append(chunk.encode("utf-8", errors="replace")[:remaining].decode("utf-8", errors="replace"))
                    overflow = True
                    _terminate_process_tree(process, job)
                    break
                output_bytes += size
                rows.append(chunk)

    assert process.stdout is not None and process.stderr is not None
    readers = [threading.Thread(target=reader, args=(process.stdout, stdout_rows), daemon=True), threading.Thread(target=reader, args=(process.stderr, stderr_rows), daemon=True)]
    for thread in readers:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(process, job)
    else:
        if job is not None:
            job.terminate_and_close()
    for thread in readers:
        thread.join(timeout=15)
    if any(thread.is_alive() for thread in readers):
        _terminate_process_tree(process, job)
        raise RuntimeFailure("process output pipe did not close after tree termination")
    stdout = "".join(stdout_rows)
    stderr = "".join(stderr_rows)
    if overflow:
        stderr += "\n<output-limit-exceeded>\n"
    result = ProcessResult(
        command,
        str(cwd),
        int(process.returncode),
        redact(stdout or "", secrets),
        redact(stderr or "", secrets),
        timed_out,
    )
    if evidence is not None:
        atomic_json(evidence, asdict(result))
    if timed_out:
        raise RuntimeTimeout(f"command timed out after {timeout} seconds")
    if overflow:
        raise RuntimeFailure("command output exceeded retained-output bound")
    return result


def run_sandboxed(
    *,
    codex: Path,
    profile: str,
    cwd: Path,
    command: Sequence[str | Path],
    timeout: int,
    environment: dict[str, str],
    evidence: Path,
    secrets: Sequence[str] = (),
) -> ProcessResult:
    args = [codex, "sandbox", "windows", "--permissions-profile", profile, "-C", cwd, "--", *command]
    result = run_process(args, cwd, timeout, environment=environment, secrets=secrets, evidence=evidence)
    if result.return_code != 0:
        raise RuntimeFailure(f"sandboxed command failed with exit {result.return_code}: {result.stderr[-1000:]}")
    return result


def qualify_candidate_sandbox(
    *,
    codex: Path,
    python: Path,
    canary_source: Path,
    profile: str,
    cwd: Path,
    allowed: Sequence[Path],
    forbidden: Sequence[Path],
    timeout: int,
    environment: dict[str, str],
    scratch: Path,
    evidence_dir: Path,
    token: str,
) -> dict[str, Any]:
    if not roots_are_disjoint([*allowed, *forbidden]):
        raise RuntimeFailure("canary roots must be pairwise non-nested")
    canary_copy = scratch / "improvement_sandbox_canary.py"
    shutil.copy2(canary_source, canary_copy)
    command: list[str | Path] = [python, canary_copy]
    for path in allowed:
        command.extend(["--allowed", path])
    for path in forbidden:
        command.extend(["--forbidden", path])
    command.extend(["--token", token])
    result = run_sandboxed(
        codex=codex,
        profile=profile,
        cwd=cwd,
        command=command,
        timeout=timeout,
        environment=environment,
        evidence=evidence_dir / "sandbox_canary_command.json",
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    try:
        if len(lines) != 1:
            raise ValueError("canary must emit exactly one JSON line")
        value = json.loads(lines[0])
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeFailure("sandbox canary returned invalid JSON") from exc
    atomic_json(evidence_dir / "sandbox_canary.json", value)
    expected_operations = {"file_create_fsync_unlink", "directory_create_rmdir", "file_create_rename_cleanup"}

    def validate_rows(kind: str, expected_paths: Sequence[Path]) -> bool:
        rows = value.get(kind)
        if not isinstance(rows, list) or len(rows) != len(expected_paths):
            return False
        expected = [str(path.resolve()) for path in expected_paths]
        if [row.get("path") if isinstance(row, dict) else None for row in rows] != expected:
            return False
        for row in rows:
            operations = row.get("operations")
            if not isinstance(operations, list) or {item.get("operation") for item in operations if isinstance(item, dict)} != expected_operations:
                return False
            if row.get("pass") is not True:
                return False
            for item in operations:
                if set(item) != {"operation", "succeeded", "permission_denied", "breach", "cleanup_ok", "error"}:
                    return False
                if kind == "allowed":
                    if item.get("succeeded") is not True or item.get("cleanup_ok") is not True:
                        return False
                elif item.get("succeeded") is not False or item.get("permission_denied") is not True or item.get("breach") is not False or item.get("cleanup_ok") is not True:
                    return False
        return True

    if (
        set(value) != {"schema_version", "token", "allowed", "forbidden", "pass"}
        or value.get("schema_version") != "blast-pit.sandbox-canary.v1"
        or value.get("token") != token
        or value.get("pass") is not True
        or not validate_rows("allowed", allowed)
        or not validate_rows("forbidden", forbidden)
    ):
        raise RuntimeFailure("sandbox canary did not pass")
    return value


def parse_patch_paths(patch: str, allowed_files: set[str], max_bytes: int) -> list[str]:
    if "\x00" in patch or len(patch.encode("utf-8")) > max_bytes:
        raise RuntimeFailure("proposed patch is empty, binary, or exceeds the byte limit")
    if not patch.strip():
        return []
    if not patch.endswith("\n"):
        raise RuntimeFailure("proposed patch must end with a newline")
    if any(marker in patch for marker in FORBIDDEN_PATCH_METADATA):
        raise RuntimeFailure("proposed patch contains forbidden file metadata")
    if "\r" in patch:
        raise RuntimeFailure("proposed patch must use canonical LF line endings")
    lines = patch.splitlines()
    paths: list[str] = []
    index = 0
    while index < len(lines):
        header = PATCH_HEADER_RE.fullmatch(lines[index])
        if header is None:
            raise RuntimeFailure(f"unexpected patch content outside a validated file section at line {index + 1}")
        left, right = header.groups()
        if (
            left != right
            or left not in allowed_files
            or Path(left).is_absolute()
            or ".." in Path(left).parts
            or "\\" in left
        ):
            raise RuntimeFailure(f"proposed patch path is outside the allowlist: {left!r}, {right!r}")
        if left in paths:
            raise RuntimeFailure(f"proposed patch repeats a file section: {left}")
        paths.append(left)
        index += 1
        if index < len(lines) and PATCH_INDEX_RE.fullmatch(lines[index]):
            index += 1
        if index >= len(lines) or lines[index] != f"--- a/{left}":
            raise RuntimeFailure(f"validated patch section has no exact old-file marker: {left}")
        index += 1
        if index >= len(lines) or lines[index] != f"+++ b/{left}":
            raise RuntimeFailure(f"validated patch section has no exact new-file marker: {left}")
        index += 1
        saw_hunk = False
        while index < len(lines) and not lines[index].startswith("diff --git "):
            line = lines[index]
            if PATCH_HUNK_RE.fullmatch(line):
                saw_hunk = True
            elif line.startswith(("--- ", "+++ ", "diff ")):
                raise RuntimeFailure(f"unexpected file or diff header inside section for {left}")
            elif not saw_hunk or (line and line[0] not in {" ", "+", "-", "\\"}):
                raise RuntimeFailure(f"unexpected patch line inside section for {left}: {index + 1}")
            index += 1
        if not saw_hunk:
            raise RuntimeFailure(f"validated patch section has no hunk: {left}")
    return sorted(paths)


def apply_patch_in_sandbox(
    *,
    patch: str,
    declared_files: Sequence[str],
    allowed_files: set[str],
    max_bytes: int,
    worktree: Path,
    scratch: Path,
    codex: Path,
    profile: str,
    environment: dict[str, str],
    timeout: int,
    evidence_dir: Path,
) -> list[str]:
    paths = parse_patch_paths(patch, allowed_files, max_bytes)
    if paths != sorted(set(declared_files)):
        raise RuntimeFailure("declared changed_files do not match proposed patch paths")
    patch_path = scratch / f"proposal-{hashlib.sha256(patch.encode('utf-8')).hexdigest()[:16]}.patch"
    atomic_text(patch_path, patch)
    safe_directory = f"safe.directory={worktree.resolve()}"
    base = ["git", "-c", safe_directory, "-C", worktree, "apply", "--recount", "--whitespace=error-all"]
    run_sandboxed(
        codex=codex,
        profile=profile,
        cwd=worktree,
        command=[*base, "--check", patch_path],
        timeout=timeout,
        environment=environment,
        evidence=evidence_dir / "git_apply_check.json",
    )
    run_sandboxed(
        codex=codex,
        profile=profile,
        cwd=worktree,
        command=[*base, patch_path],
        timeout=timeout,
        environment=environment,
        evidence=evidence_dir / "git_apply.json",
    )
    return paths
