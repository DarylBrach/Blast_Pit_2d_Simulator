from __future__ import annotations

"""Security and process primitives for the governed v2 improvement harness."""

import hashlib
import json
import os
import re
import base64
import binascii
import errno
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import quote

import CodexImprovementController_v1 as legacy


ROLE_POLICY_VERSION = "tool-less-roles-container-isolation-v3"
CONTAINER_RUNTIME_VERSION = "docker-candidate-runtime-v1"
CONTAINER_RECORD_SCHEMA = "blast-pit.candidate-container-lifecycle.v1"
CONTAINER_LABEL = "com.adlerbaer.blastpit.governed-candidate"
RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
PATCH_HEADER_RE = re.compile(r"^diff --git a/([^\s]+) b/([^\s]+)$")
PATCH_INDEX_RE = re.compile(r"^index [a-f0-9]+\.\.[a-f0-9]+(?: [0-7]{6})?$")
PATCH_HUNK_RE = re.compile(r"^@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@(?: .*)?$")
MAX_ROLE_STREAM_BYTES = 8_000_000
MAX_PROCESS_STREAM_BYTES = 8_000_000
ACL_LEASE_SCHEMA = "blast-pit.acl-lease.v1"
ACL_LEASE_STATES = {
    "SNAPSHOT_FSYNCED",
    "MATERIALIZED",
    "SID_DISCOVERED",
    "APPLYING",
    "ACTIVE",
    "CANARY_PASS",
    "RESTORING",
    "RECOVERY_REQUIRED",
    "RESTORED",
    "RESTORED_RECOVERY",
}
ACL_RESTORED_STATES = {"RESTORED", "RESTORED_RECOVERY"}
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


@dataclass
class AclLease:
    path: Path
    root: Path
    authorized_parent: Path
    helper: Path
    control_dir: Path
    evidence_dir: Path
    record: dict[str, Any]


@dataclass(frozen=True)
class ContainerPolicy:
    path: Path
    value: dict[str, Any]

    @property
    def workspace_destination(self) -> str:
        return str(self.value["workspace_destination"])


class ControllerLock:
    """Kernel-owned single-controller lock; a stale pathname is harmless."""

    def __init__(self, path: Path, metadata: dict[str, Any]):
        self.path = path
        self.metadata = metadata
        self._handle: Any = None

    def __enter__(self) -> "ControllerLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        validate_no_reparse_ancestors(self.path.parent, require_exists=True)
        if self.path.exists() and (
            is_reparse(self.path)
            or not self.path.is_file()
            or self.path.stat(follow_symlinks=False).st_nlink != 1
        ):
            raise RuntimeFailure(f"unsafe controller lock path: {self.path}")
        if os.name == "nt":
            import ctypes
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
            handle = create_file(
                str(self.path),
                0x80000000 | 0x40000000,
                0,
                None,
                4,
                0x80,
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if handle == invalid:
                error = ctypes.windll.kernel32.GetLastError()
                if error in {5, 32, 33}:
                    raise RuntimeFailure("another governed controller owns the exclusive worktree lock")
                raise OSError(error, "CreateFileW failed for controller lock", str(self.path))
            try:
                descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDWR | os.O_BINARY)
                self._handle = os.fdopen(descriptor, "r+b", buffering=0)
            except Exception:
                ctypes.windll.kernel32.CloseHandle(handle)
                raise
        else:  # pragma: no cover - the governed production target is Windows
            import fcntl

            self._handle = self.path.open("a+b", buffering=0)
            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                self._handle.close()
                self._handle = None
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise RuntimeFailure("another governed controller owns the exclusive worktree lock") from exc
                raise
        payload = canonical({"schema_version": "blast-pit.controller-lock.v1", **self.metadata}).encode("utf-8")
        self._handle.seek(0)
        self._handle.truncate(0)
        self._handle.write(payload)
        self._handle.flush()
        os.fsync(self._handle.fileno())
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


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


def copy_strict_tree(source: Path, destination: Path, *, max_files: int = 2_000, max_bytes: int = 128_000_000) -> dict[str, dict[str, Any]]:
    source = validate_no_reparse_ancestors(source, require_exists=True)
    if destination.exists() or destination.is_symlink():
        raise RuntimeFailure(f"retained destination already exists: {destination}")
    source_manifest = strict_manifest(source, max_files=max_files, max_bytes=max_bytes)
    destination.mkdir(parents=True, exist_ok=False)
    try:
        for relative, evidence in source_manifest.items():
            source_file = source / Path(relative)
            target = destination / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            before = source_file.stat(follow_symlinks=False)
            if is_reparse(source_file) or not source_file.is_file() or before.st_nlink != 1:
                raise RuntimeFailure(f"unsafe source changed during retained copy: {source_file}")
            shutil.copyfile(source_file, target, follow_symlinks=False)
            with target.open("rb+") as handle:
                os.fsync(handle.fileno())
            after = source_file.stat(follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise RuntimeFailure(f"source changed during retained copy: {source_file}")
            if target.stat(follow_symlinks=False).st_nlink != 1 or legacy.sha256_file(target) != evidence["sha256"]:
                raise RuntimeFailure(f"retained copy hash or link mismatch: {target}")
        retained = strict_manifest(destination, max_files=max_files, max_bytes=max_bytes)
        if retained != source_manifest:
            raise RuntimeFailure("retained tree does not match its sandbox source")
        return retained
    except Exception:
        if destination.exists():
            safe_remove_tree(destination, destination.parent)
        raise


def materialize_candidate_output_bundle(
    stdout: str,
    destination: Path,
    *,
    prefix: str = "GOVERNED_OUTPUT_BUNDLE=",
    max_files: int = 128,
    max_bytes: int = 4_000_000,
) -> dict[str, dict[str, Any]]:
    destination = validate_no_reparse_ancestors(destination, require_exists=True)
    if not destination.is_dir() or not _directory_is_empty(destination):
        raise RuntimeFailure("candidate output destination must be a pre-created empty directory")
    destination_identity = directory_identity(destination)
    matches = [line[len(prefix) :] for line in stdout.splitlines() if line.startswith(prefix)]
    if len(matches) != 1 or not stdout.splitlines() or not stdout.splitlines()[-1].startswith(prefix):
        raise RuntimeFailure("candidate output exporter did not emit one final bounded bundle")
    value = _strict_json_value(matches[0], "candidate output bundle")
    if not isinstance(value, dict) or set(value) != {"schema_version", "file_count", "total_bytes", "files"}:
        raise RuntimeFailure("candidate output bundle contract mismatch")
    files = value.get("files")
    if value.get("schema_version") != "blast-pit.candidate-output-bundle.v1" or not isinstance(files, list):
        raise RuntimeFailure("candidate output bundle schema mismatch")
    if value.get("file_count") != len(files) or len(files) > max_files:
        raise RuntimeFailure("candidate output bundle file count is invalid")
    expected: dict[str, dict[str, Any]] = {}
    decoded: list[tuple[str, bytes]] = []
    total = 0
    previous = ""
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256", "base64"}:
            raise RuntimeFailure("candidate output bundle file descriptor is invalid")
        relative = item.get("path")
        if (
            not isinstance(relative, str)
            or not relative
            or relative <= previous
            or relative.startswith("/")
            or "\\" in relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise RuntimeFailure("candidate output bundle path is invalid or unsorted")
        previous = relative
        encoded = item.get("base64")
        if not isinstance(encoded, str) or len(encoded) > max_bytes * 2:
            raise RuntimeFailure("candidate output bundle encoding is invalid")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeFailure("candidate output bundle contains invalid base64") from exc
        size = item.get("bytes")
        digest_value = item.get("sha256")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size != len(data)
            or not isinstance(digest_value, str)
            or hashlib.sha256(data).hexdigest() != digest_value
        ):
            raise RuntimeFailure("candidate output bundle size or hash mismatch")
        total += size
        if total > max_bytes:
            raise RuntimeFailure("candidate output bundle exceeds its byte limit")
        expected[relative] = {"kind": "file", "bytes": size, "sha256": digest_value}
        decoded.append((relative, data))
    if value.get("total_bytes") != total:
        raise RuntimeFailure("candidate output bundle total byte count mismatch")
    try:
        for relative, data in decoded:
            target = destination / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        actual = strict_manifest(destination, max_files=max_files, max_bytes=max_bytes)
        _assert_directory_identity(destination, destination_identity)
        if actual != expected:
            raise RuntimeFailure("materialized candidate output disagrees with its bundle")
        return actual
    except Exception:
        empty_directory_contents(destination, destination.parent, expected_identity=destination_identity)
        raise


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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def directory_identity(path: Path) -> dict[str, int]:
    resolved = validate_no_reparse_ancestors(path, require_exists=True)
    if not resolved.is_dir():
        raise RuntimeFailure(f"ACL lease root is not a directory: {resolved}")
    info = resolved.stat(follow_symlinks=False)
    return {"st_dev": int(info.st_dev), "st_ino": int(info.st_ino), "st_ctime_ns": int(info.st_ctime_ns)}


def _assert_directory_identity(path: Path, expected: dict[str, Any]) -> None:
    if set(expected) != {"st_dev", "st_ino", "st_ctime_ns"} or directory_identity(path) != expected:
        raise RuntimeFailure("ACL lease root identity changed")


def _directory_is_empty(path: Path) -> bool:
    with os.scandir(path) as entries:
        return next(entries, None) is None


def empty_directory_contents(
    root: Path,
    authorized_parent: Path,
    *,
    expected_identity: dict[str, Any] | None = None,
) -> None:
    resolved = require_strict_descendant(root, authorized_parent, "ACL lease root")
    identity = expected_identity or directory_identity(resolved)
    _assert_directory_identity(resolved, identity)
    for child in list(resolved.iterdir()):
        _assert_directory_identity(resolved, identity)
        if is_reparse(child):
            raise RuntimeFailure(f"reparse entry blocks ACL lease cleanup: {child}")
        if child.is_dir():
            safe_remove_tree(child, resolved)
        elif child.is_file() and child.stat(follow_symlinks=False).st_nlink == 1:
            child.unlink()
        else:
            raise RuntimeFailure(f"unsafe entry blocks ACL lease cleanup: {child}")
    if not _directory_is_empty(resolved):
        raise RuntimeFailure("ACL lease root is not empty after cleanup")
    _assert_directory_identity(resolved, identity)


def _powershell_path() -> Path:
    system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    path = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not path.is_file() or path.is_symlink():
        raise RuntimeFailure("trusted Windows PowerShell launcher is unavailable")
    return path.resolve()


def _acl_contract(lease: AclLease, operation: str) -> dict[str, Any]:
    return {
        "schema_version": "blast-pit.acl-lease-contract.v1",
        "operation": operation,
        "lease_id": lease.record["lease_id"],
        "root": str(lease.root),
        "authorized_parent": str(lease.authorized_parent),
        "control_dir": str(lease.control_dir),
        "snapshot": lease.record.get("snapshot"),
        "restricted_sid": lease.record.get("restricted_sid") if operation in {"upgrade", "restore", "verify"} else None,
    }


def _invoke_acl_helper(lease: AclLease, operation: str, timeout: int) -> dict[str, Any]:
    if legacy.sha256_file(lease.helper) != lease.record.get("helper_sha256"):
        raise RuntimeFailure("authorization-bound ACL helper hash changed")
    contract_path = lease.control_dir / f"acl_contract_{operation}.json"
    result_path = lease.evidence_dir / f"acl_{operation}_result.json"
    command_path = lease.evidence_dir / f"acl_{operation}_command.json"
    atomic_json(contract_path, _acl_contract(lease, operation))
    result = run_process(
        [
            _powershell_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            lease.helper,
            "-Contract",
            contract_path,
        ],
        lease.control_dir,
        timeout,
        environment=_minimal_environment(lease.control_dir, lease.control_dir),
        evidence=command_path,
    )
    if result.return_code != 0:
        raise RuntimeFailure(f"ACL helper {operation} failed with exit {result.return_code}: {result.stderr[-1000:]}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1 or len(lines[0].encode("utf-8")) > 1_000_000:
        raise RuntimeFailure(f"ACL helper {operation} returned invalid bounded output")
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise RuntimeFailure(f"ACL helper {operation} returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "blast-pit.acl-helper-result.v1"
        or value.get("operation") != operation
        or value.get("lease_id") != lease.record["lease_id"]
        or value.get("pass") is not True
    ):
        raise RuntimeFailure(f"ACL helper {operation} result contract mismatch")
    expected_fields = {
        "snapshot": {"schema_version", "operation", "lease_id", "pass", "snapshot", "restricted_sid"},
        "discover": {"schema_version", "operation", "lease_id", "pass", "snapshot", "restricted_sid", "materialized_delta"},
        "upgrade": {
            "schema_version",
            "operation",
            "lease_id",
            "pass",
            "snapshot",
            "restricted_sid",
            "materialized_delta",
            "upgraded_sddl_sha256",
        },
        "restore": {"schema_version", "operation", "lease_id", "pass", "snapshot", "restricted_sid"},
        "verify": {"schema_version", "operation", "lease_id", "pass", "snapshot", "restricted_sid"},
    }
    if set(value) != expected_fields.get(operation, set()):
        raise RuntimeFailure(f"ACL helper {operation} returned unexpected evidence fields")
    atomic_json(result_path, value)
    return value


def _write_acl_lease(lease: AclLease, state: str, **updates: Any) -> None:
    if state not in ACL_LEASE_STATES:
        raise RuntimeFailure(f"invalid ACL lease state: {state}")
    lease.record.update(updates)
    lease.record["state"] = state
    history = lease.record.setdefault("history", [])
    history.append({"state": state, "recorded_at": _utc_now()})
    atomic_json(lease.path, lease.record)
    atomic_json(lease.evidence_dir / "acl_lease_live.json", lease.record)


def start_candidate_acl_lease(
    *,
    lease_path: Path,
    root: Path,
    authorized_parent: Path,
    helper: Path,
    control_dir: Path,
    evidence_dir: Path,
    authorization_sha256: str,
    worktree_path: Path,
    codex: Path,
    python: Path,
    profile: str,
    environment: dict[str, str],
    canary_source: Path,
    forbidden: Sequence[Path],
    timeout: int,
    token: str,
    registry: list[AclLease] | None = None,
) -> AclLease:
    root = require_strict_descendant(root, authorized_parent, "ACL lease root")
    if not _directory_is_empty(root):
        raise RuntimeFailure("ACL lease root must start empty")
    helper = validate_no_reparse_ancestors(helper, require_exists=True)
    if not helper.is_file() or helper.suffix.lower() != ".ps1":
        raise RuntimeFailure("ACL helper is missing or unsafe")
    helper_sha256 = legacy.sha256_file(helper)
    recovery_helper = authorized_parent.resolve() / f".acl-recovery-helper-{helper_sha256}.ps1"
    if recovery_helper.exists():
        if (
            is_reparse(recovery_helper)
            or not recovery_helper.is_file()
            or recovery_helper.stat(follow_symlinks=False).st_nlink != 1
            or legacy.sha256_file(recovery_helper) != helper_sha256
        ):
            raise RuntimeFailure("persisted ACL recovery helper archive is unsafe")
    else:
        shutil.copyfile(helper, recovery_helper, follow_symlinks=False)
        with recovery_helper.open("rb+") as handle:
            os.fsync(handle.fileno())
        if recovery_helper.stat(follow_symlinks=False).st_nlink != 1 or legacy.sha256_file(recovery_helper) != helper_sha256:
            raise RuntimeFailure("persisted ACL recovery helper archive verification failed")
    control_dir = require_strict_descendant(control_dir, authorized_parent, "ACL control directory")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    lease = AclLease(
        path=lease_path,
        root=root,
        authorized_parent=authorized_parent.resolve(),
        helper=helper,
        control_dir=control_dir,
        evidence_dir=evidence_dir,
        record={
            "schema_version": ACL_LEASE_SCHEMA,
            "lease_id": token,
            "state": "INITIALIZING",
            "root": str(root),
            "authorized_parent": str(authorized_parent.resolve()),
            "root_identity": directory_identity(root),
            "helper_path": str(helper),
            "helper_sha256": helper_sha256,
            "recovery_helper_path": str(recovery_helper),
            "recovery_helper_sha256": helper_sha256,
            "authorization_sha256": authorization_sha256,
            "controller_pid": os.getpid(),
            "worktree_path": str(worktree_path),
            "control_dir": str(control_dir),
            "evidence_dir": str(evidence_dir.resolve()),
            "snapshot": None,
            "restricted_sid": None,
            "history": [],
        },
    )
    snapshot_result = _invoke_acl_helper(lease, "snapshot", timeout)
    snapshot = snapshot_result.get("snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("root") != str(root):
        raise RuntimeFailure("ACL helper snapshot did not bind the lease root")
    _write_acl_lease(lease, "SNAPSHOT_FSYNCED", snapshot=snapshot)
    if registry is not None:
        registry.append(lease)
    try:
        run_sandboxed(
            codex=codex,
            profile=profile,
            cwd=root,
            command=[python, "-c", "pass"],
            timeout=timeout,
            environment=environment,
            evidence=evidence_dir / "acl_materialize_command.json",
        )
        _assert_directory_identity(root, lease.record["root_identity"])
        if not _directory_is_empty(root):
            raise RuntimeFailure("ACL materialization changed the empty lease root")
        _write_acl_lease(lease, "MATERIALIZED")
        discovery = _invoke_acl_helper(lease, "discover", timeout)
        restricted_sid = discovery.get("restricted_sid")
        if not isinstance(restricted_sid, str):
            raise RuntimeFailure("ACL helper did not return a restricted SID")
        _write_acl_lease(
            lease,
            "SID_DISCOVERED",
            restricted_sid=restricted_sid,
            materialized_delta_sha256=sha256_json(discovery.get("materialized_delta")),
        )
        _write_acl_lease(lease, "APPLYING")
        upgrade = _invoke_acl_helper(lease, "upgrade", timeout)
        if upgrade.get("restricted_sid") != restricted_sid:
            raise RuntimeFailure("ACL helper upgrade changed the restricted SID identity")
        _write_acl_lease(lease, "ACTIVE", upgraded_sddl_sha256=upgrade.get("upgraded_sddl_sha256"))
        scratch = root / "temp"
        scratch.mkdir()
        environment["TEMP"] = environment["TMP"] = str(scratch)
        qualify_candidate_sandbox(
            codex=codex,
            python=python,
            canary_source=canary_source,
            profile=profile,
            cwd=root,
            allowed=[root],
            forbidden=forbidden,
            timeout=timeout,
            environment=environment,
            scratch=scratch,
            evidence_dir=evidence_dir,
            token=token,
        )
        _assert_directory_identity(root, lease.record["root_identity"])
        _write_acl_lease(lease, "CANARY_PASS")
        return lease
    except Exception as exc:
        try:
            restore_candidate_acl_lease(lease, timeout=timeout, cleanup=True, recovered=True)
            if registry is not None and lease in registry:
                registry.remove(lease)
        except Exception as restore_exc:
            _write_acl_lease(lease, "RECOVERY_REQUIRED", recovery_error=f"{type(restore_exc).__name__}: {restore_exc}")
            raise RuntimeFailure(f"ACL lease setup failed and restoration is required: {exc}; restore: {restore_exc}") from exc
        raise


def restore_candidate_acl_lease(
    lease: AclLease,
    *,
    timeout: int,
    cleanup: bool,
    recovered: bool = False,
) -> dict[str, Any]:
    _write_acl_lease(lease, "RESTORING", recovery_attempt=recovered)
    try:
        _assert_directory_identity(lease.root, lease.record["root_identity"])
        if cleanup:
            empty_directory_contents(
                lease.root,
                lease.authorized_parent,
                expected_identity=lease.record["root_identity"],
            )
        if not _directory_is_empty(lease.root):
            raise RuntimeFailure("ACL lease root must be empty before restoration")
        result = _invoke_acl_helper(lease, "restore", timeout)
        _assert_directory_identity(lease.root, lease.record["root_identity"])
        verification = _invoke_acl_helper(lease, "verify", timeout)
        for value in (result, verification):
            snapshot = value.get("snapshot")
            if (
                not isinstance(snapshot, dict)
                or snapshot.get("sddl") != lease.record["snapshot"].get("sddl")
                or snapshot.get("sddl_sha256") != lease.record["snapshot"].get("sddl_sha256")
                or snapshot.get("root") != str(lease.root)
            ):
                raise RuntimeFailure("ACL helper restoration evidence does not match the durable snapshot")
        _assert_directory_identity(lease.root, lease.record["root_identity"])
        state = "RESTORED_RECOVERY" if recovered else "RESTORED"
        _write_acl_lease(
            lease,
            state,
            restored_result_sha256=sha256_json(result),
            verified_result_sha256=sha256_json(verification),
        )
        return verification
    except Exception as exc:
        _write_acl_lease(lease, "RECOVERY_REQUIRED", recovery_error=f"{type(exc).__name__}: {exc}")
        raise


def discover_acl_lease_paths(worktree_root: Path, run_id: str | None = None) -> list[Path]:
    root = validate_no_reparse_ancestors(worktree_root, require_exists=True)
    paths: list[Path] = []
    for workspace in sorted(root.iterdir()):
        if is_reparse(workspace):
            raise RuntimeFailure(f"reparse workspace blocks ACL lease discovery: {workspace}")
        if not workspace.is_dir():
            continue
        records = sorted(workspace.glob("acl_lease*.json"))
        if not records:
            continue
        if not RUN_ID_RE.fullmatch(workspace.name):
            raise RuntimeFailure(f"ACL lease record exists under an invalid workspace: {workspace}")
        if run_id is not None and workspace.name != run_id:
            continue
        for record in records:
            if not re.fullmatch(r"acl_lease_(?:dry_run|cycle_[0-9]{3})\.json", record.name):
                raise RuntimeFailure(f"unexpected ACL lease record name: {record}")
            if is_reparse(record) or not record.is_file() or record.stat(follow_symlinks=False).st_nlink != 1:
                raise RuntimeFailure(f"unsafe ACL lease record: {record}")
            paths.append(record)
            if len(paths) > 32:
                raise RuntimeFailure("ACL lease discovery exceeded the bounded record count")
    return paths


def _load_strict_acl_json(path: Path) -> dict[str, Any]:
    if path.stat(follow_symlinks=False).st_size > 1_000_000:
        raise RuntimeFailure(f"ACL lease record is oversized: {path}")

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise RuntimeFailure(f"duplicate ACL lease JSON key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeFailure(f"invalid ACL lease JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeFailure("ACL lease record must be an object")
    return value


def load_acl_lease(
    lease_path: Path,
    *,
    worktree_root: Path,
    helper: Path,
    recovery_control_dir: Path,
    recovery_evidence_dir: Path,
) -> AclLease:
    worktree_root = validate_no_reparse_ancestors(worktree_root, require_exists=True)
    lease_path = validate_no_reparse_ancestors(lease_path, require_exists=True)
    workspace = require_strict_descendant(lease_path.parent, worktree_root, "ACL lease workspace")
    if workspace.parent != worktree_root or not RUN_ID_RE.fullmatch(workspace.name):
        raise RuntimeFailure("ACL lease workspace identity is invalid")
    if not re.fullmatch(r"acl_lease_(?:dry_run|cycle_[0-9]{3})\.json", lease_path.name):
        raise RuntimeFailure("ACL lease record name is invalid")
    record = _load_strict_acl_json(lease_path)
    required = {
        "schema_version",
        "lease_id",
        "state",
        "root",
        "authorized_parent",
        "root_identity",
        "helper_path",
        "helper_sha256",
        "recovery_helper_path",
        "recovery_helper_sha256",
        "authorization_sha256",
        "controller_pid",
        "worktree_path",
        "control_dir",
        "evidence_dir",
        "snapshot",
        "restricted_sid",
        "history",
    }
    allowed = required | {
        "materialized_delta_sha256",
        "upgraded_sddl_sha256",
        "recovery_attempt",
        "restored_result_sha256",
        "verified_result_sha256",
        "recovery_error",
    }
    if not required.issubset(record) or not set(record).issubset(allowed):
        raise RuntimeFailure("ACL lease record properties do not match the fixed schema")
    if record.get("schema_version") != ACL_LEASE_SCHEMA or record.get("state") not in ACL_LEASE_STATES:
        raise RuntimeFailure("ACL lease schema or state is invalid")
    lease_id = record.get("lease_id")
    if not isinstance(lease_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", lease_id):
        raise RuntimeFailure("ACL lease identifier is invalid")
    history = record.get("history")
    if not isinstance(history, list) or not history or history[-1].get("state") != record["state"]:
        raise RuntimeFailure("ACL lease history does not end at its declared state")
    authorization_sha256 = record.get("authorization_sha256")
    if not isinstance(authorization_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", authorization_sha256):
        raise RuntimeFailure("ACL lease authorization identity is invalid")
    identity = record.get("root_identity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"st_dev", "st_ino", "st_ctime_ns"}
        or any(isinstance(identity[key], bool) or not isinstance(identity[key], int) for key in identity)
    ):
        raise RuntimeFailure("ACL lease root identity record is invalid")
    if Path(str(record.get("authorized_parent"))) != workspace:
        raise RuntimeFailure("ACL lease authorized-parent binding is invalid")
    root = require_strict_descendant(Path(str(record.get("root"))), workspace, "ACL lease root")
    if root.parent != workspace or not re.fullmatch(r"(?:dry_candidate_lease|cycle_[0-9]{3}_candidate_lease)", root.name):
        raise RuntimeFailure("ACL lease root name or location is invalid")
    if not root.exists():
        if record["state"] not in ACL_RESTORED_STATES:
            raise RuntimeFailure("non-restored ACL lease root is missing")
    else:
        _assert_directory_identity(root, identity)
    worktree_path = lexical_absolute(Path(str(record.get("worktree_path"))))
    if worktree_path.parent != root or worktree_path.name not in {"worktree", "worktree-not-created"}:
        raise RuntimeFailure("ACL lease worktree path is invalid")
    expected_helper = lexical_absolute(helper)
    if Path(str(record.get("helper_path"))) != expected_helper:
        raise RuntimeFailure("ACL lease original helper path binding changed")
    recovery_helper = require_strict_descendant(
        Path(str(record.get("recovery_helper_path"))), workspace, "persisted ACL recovery helper"
    )
    if (
        recovery_helper.parent != workspace
        or recovery_helper.name != f".acl-recovery-helper-{record.get('helper_sha256')}.ps1"
        or is_reparse(recovery_helper)
        or not recovery_helper.is_file()
        or recovery_helper.stat(follow_symlinks=False).st_nlink != 1
        or record.get("recovery_helper_sha256") != record.get("helper_sha256")
        or legacy.sha256_file(recovery_helper) != record.get("helper_sha256")
    ):
        raise RuntimeFailure("persisted ACL recovery helper archive hash or path is invalid")
    snapshot = record.get("snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("root") != str(root) or snapshot.get("authorized_parent") != str(workspace):
        raise RuntimeFailure("ACL lease snapshot path binding is invalid")
    sddl = snapshot.get("sddl")
    if not isinstance(sddl, str) or hashlib.sha256(sddl.encode("utf-8")).hexdigest() != snapshot.get("sddl_sha256"):
        raise RuntimeFailure("ACL lease snapshot hash is invalid")
    restricted_sid = record.get("restricted_sid")
    if restricted_sid is not None and (
        not isinstance(restricted_sid, str)
        or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", restricted_sid)
    ):
        raise RuntimeFailure("ACL lease restricted SID is invalid")
    recovery_control_dir = require_strict_descendant(recovery_control_dir, workspace, "ACL recovery control directory")
    recovery_evidence_dir = validate_no_reparse_ancestors(recovery_evidence_dir, require_exists=True)
    return AclLease(
        path=lease_path,
        root=root,
        authorized_parent=workspace,
        helper=recovery_helper,
        control_dir=recovery_control_dir,
        evidence_dir=recovery_evidence_dir,
        record=record,
    )


def prepare_candidate_sandbox(
    isolation: Path,
    isolation_root: Path,
    write_roots: Sequence[Path],
    *,
    scratch: Path | None = None,
    profile: str = "candidate",
    implementation: str = "unelevated",
) -> tuple[dict[str, str], Path]:
    require_strict_descendant(isolation, isolation_root, "sandbox isolation")
    isolation.mkdir(parents=True, exist_ok=False)
    home = isolation / "codex_home"
    home.mkdir()
    if scratch is None:
        temp = isolation / "temp"
        temp.mkdir()
        all_roots = [*write_roots, temp]
    else:
        if len(write_roots) != 1:
            raise RuntimeFailure("an external sandbox scratch requires one lease root")
        temp = require_strict_descendant(scratch, write_roots[0], "sandbox scratch")
        if temp.exists():
            raise RuntimeFailure("leased sandbox scratch must not exist before ACL activation")
        all_roots = list(write_roots)
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
    require_success: bool = True,
) -> ProcessResult:
    args = [codex, "sandbox", "windows", "--permissions-profile", profile, "-C", cwd, "--", *command]
    result = run_process(args, cwd, timeout, environment=environment, secrets=secrets, evidence=evidence)
    if require_success and result.return_code != 0:
        raise RuntimeFailure(f"sandboxed command failed with exit {result.return_code}: {result.stderr[-1000:]}")
    return result


def _strict_json_value(text: str, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise RuntimeFailure(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(RuntimeFailure(f"non-finite JSON in {label}: {item}")),
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimeFailure(f"invalid JSON from {label}") from exc


def load_container_policy(path: Path) -> ContainerPolicy:
    path = validate_no_reparse_ancestors(path, require_exists=True)
    if not path.is_file() or path.stat(follow_symlinks=False).st_nlink != 1 or path.stat().st_size > 64_000:
        raise RuntimeFailure("candidate container policy is missing or unsafe")
    value = _strict_json_value(path.read_text(encoding="utf-8"), path.name)
    exact = {
        "schema_version",
        "runtime_version",
        "platform",
        "user",
        "network_mode",
        "read_only_rootfs",
        "cap_drop",
        "security_opt",
        "cgroupns_mode",
        "ipc_mode",
        "pids_limit",
        "memory_bytes",
        "memory_swap_bytes",
        "nano_cpus",
        "nofile_soft",
        "nofile_hard",
        "tmpfs",
        "workspace_destination",
        "workspace_mode",
        "workspace_propagation",
        "max_output_bytes",
        "pull_policy",
    }
    required = {
        "schema_version": "blast-pit.candidate-container-policy.v1",
        "runtime_version": CONTAINER_RUNTIME_VERSION,
        "platform": "linux/amd64",
        "user": "65532:65532",
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true", "seccomp=builtin"],
        "cgroupns_mode": "private",
        "ipc_mode": "private",
        "pids_limit": 128,
        "memory_bytes": 2_147_483_648,
        "memory_swap_bytes": 2_147_483_648,
        "nano_cpus": 2_000_000_000,
        "nofile_soft": 1024,
        "nofile_hard": 1024,
        "tmpfs": {
            "/tmp": "rw,nosuid,nodev,size=268435456,mode=1777",
            "/output": "rw,nosuid,nodev,size=268435456,mode=1777",
        },
        "workspace_destination": "/workspace",
        "workspace_mode": "ro",
        "workspace_propagation": "rprivate",
        "max_output_bytes": MAX_PROCESS_STREAM_BYTES,
        "pull_policy": "never",
    }
    if not isinstance(value, dict) or set(value) != exact or any(value.get(key) != expected for key, expected in required.items()):
        raise RuntimeFailure("candidate container policy does not match the fixed runtime contract")
    return ContainerPolicy(path=path, value=value)


def _docker_command(
    docker: Path,
    arguments: Sequence[str | Path],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence: Path | None = None,
    require_success: bool = True,
) -> ProcessResult:
    docker = validate_no_reparse_ancestors(docker, require_exists=True)
    if not docker.is_file() or docker.suffix.lower() != ".exe":
        raise RuntimeFailure("Docker CLI path is missing or unsafe")
    result = run_process([docker, *arguments], cwd, timeout, environment=environment, evidence=evidence)
    if require_success and result.return_code != 0:
        raise RuntimeFailure(f"Docker command failed with exit {result.return_code}: {result.stderr[-1000:]}")
    return result


def docker_host_identity(
    *, docker: Path, cwd: Path, environment: dict[str, str], timeout: int, image_id: str
) -> dict[str, Any]:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise RuntimeFailure("authorized candidate image ID is invalid")
    version_result = _docker_command(
        docker,
        ["version", "--format", "{{json .}}"],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )
    version = _strict_json_value(version_result.stdout.strip(), "docker version")
    info_result = _docker_command(
        docker,
        ["info", "--format", "{{json .SecurityOptions}}"],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )
    security_options = _strict_json_value(info_result.stdout.strip(), "docker security options")
    image_result = _docker_command(
        docker,
        ["image", "inspect", image_id],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )
    images = _strict_json_value(image_result.stdout, "docker image inspect")
    if not isinstance(version, dict) or not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
        raise RuntimeFailure("Docker identity output contract mismatch")
    client = version.get("Client")
    server = version.get("Server")
    image = images[0]
    if not isinstance(client, dict) or not isinstance(server, dict) or not isinstance(security_options, list):
        raise RuntimeFailure("Docker client/server identity is incomplete")
    if server.get("Os") != "linux" or server.get("Arch") != "amd64":
        raise RuntimeFailure("candidate isolation requires the Linux amd64 Docker engine")
    required_security = {"name=seccomp,profile=builtin", "name=cgroupns"}
    if not required_security.issubset(set(security_options)):
        raise RuntimeFailure("Docker engine is missing required seccomp or cgroup namespace security")
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        image.get("Id") != image_id
        or image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
        or not isinstance(config, dict)
        or config.get("User") != "65532:65532"
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.version") != "2.2.0"
    ):
        raise RuntimeFailure("candidate image identity or non-root configuration mismatch")
    return {
        "schema_version": "blast-pit.docker-host-identity.v1",
        "client_version": client.get("Version"),
        "client_api_version": client.get("ApiVersion"),
        "server_version": server.get("Version"),
        "server_api_version": server.get("ApiVersion"),
        "server_os": server.get("Os"),
        "server_arch": server.get("Arch"),
        "server_security_options": security_options,
        "image_id": image.get("Id"),
        "image_repo_digests": image.get("RepoDigests") or [],
        "image_config_user": config.get("User"),
        "image_version_label": labels.get("org.opencontainers.image.version"),
    }


def verify_candidate_container_host(
    *,
    docker: Path,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    image_id: str,
    expected_identity: dict[str, Any],
    policy_path: Path,
    evidence: Path,
) -> dict[str, Any]:
    policy = load_container_policy(policy_path)
    actual = docker_host_identity(
        docker=docker,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        image_id=image_id,
    )
    expected_keys = {
        "client_version",
        "client_api_version",
        "server_version",
        "server_api_version",
        "server_os",
        "server_arch",
        "server_security_options",
        "image_id",
        "image_repo_digests",
        "image_config_user",
        "image_version_label",
    }
    if set(expected_identity) != expected_keys or any(actual.get(key) != value for key, value in expected_identity.items()):
        raise RuntimeFailure("Docker host or candidate image drifted from the authorization")
    record = {
        **actual,
        "schema_version": "blast-pit.candidate-container-host-preflight.v1",
        "runtime_version": CONTAINER_RUNTIME_VERSION,
        "policy_sha256": legacy.canonical_text_sha256(policy.path),
        "pass": True,
    }
    atomic_json(evidence, record)
    return record


def container_path(workspace_root: Path, host_path: Path) -> str:
    root = validate_no_reparse_ancestors(workspace_root, require_exists=True)
    path = validate_no_reparse_ancestors(host_path, require_exists=False)
    if path != root and root not in path.parents:
        raise RuntimeFailure(f"container path is outside the disposable workspace: {path}")
    relative = path.relative_to(root).as_posix()
    return "/workspace" if relative == "." else f"/workspace/{relative}"


def _validate_container_tree(root: Path) -> None:
    root = validate_no_reparse_ancestors(root, require_exists=True)
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        if is_reparse(current_path):
            raise RuntimeFailure(f"candidate container mount contains a reparse directory: {current_path}")
        for name in directories:
            path = current_path / name
            if is_reparse(path) or not path.is_dir():
                raise RuntimeFailure(f"candidate container mount contains an unsafe directory: {path}")
        for name in files:
            path = current_path / name
            if is_reparse(path) or not path.is_file() or path.stat(follow_symlinks=False).st_nlink != 1:
                raise RuntimeFailure(f"candidate container mount contains a non-regular or linked file: {path}")


def _write_container_record(path: Path, retained: Path, record: dict[str, Any], state: str, **updates: Any) -> None:
    record.update(updates)
    record["state"] = state
    record.setdefault("history", []).append({"state": state, "recorded_at": _utc_now()})
    atomic_json(path, record)
    atomic_json(retained, record)


def _inspect_container(
    docker: Path,
    container_id: str,
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence: Path | None = None,
) -> dict[str, Any]:
    result = _docker_command(
        docker,
        ["container", "inspect", container_id],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        evidence=evidence,
    )
    value = _strict_json_value(result.stdout, "docker container inspect")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeFailure("Docker container inspection contract mismatch")
    return value[0]


def _assert_container_policy(
    value: dict[str, Any],
    *,
    policy: ContainerPolicy,
    image_id: str,
    workspace_root: Path,
    name: str,
    labels: dict[str, str],
    expected_workdir: str,
    expected_command: Sequence[str],
) -> dict[str, Any]:
    config = value.get("Config")
    host = value.get("HostConfig")
    mounts = value.get("Mounts")
    state = value.get("State")
    if not all(isinstance(item, dict) for item in (config, host, state)) or not isinstance(mounts, list):
        raise RuntimeFailure("Docker inspect is missing container policy fields")
    security = set(host.get("SecurityOpt") or [])
    cap_drop = host.get("CapDrop") or []
    required = policy.value
    expected_tmpfs = required["tmpfs"]
    actual_labels = config.get("Labels")
    if (
        value.get("Image") != image_id
        or value.get("Name") != f"/{name}"
        or config.get("Image") != image_id
        or config.get("Entrypoint") not in (None, [])
        or config.get("Cmd") != list(expected_command)
        or config.get("User") != required["user"]
        or config.get("WorkingDir") != expected_workdir
        or host.get("NetworkMode") != required["network_mode"]
        or host.get("ReadonlyRootfs") is not True
        or cap_drop != required["cap_drop"]
        or set(required["security_opt"]) != security
        or host.get("Privileged") is not False
        or host.get("PidMode") not in {"", None}
        or host.get("IpcMode") != required["ipc_mode"]
        or host.get("CgroupnsMode") != required["cgroupns_mode"]
        or host.get("PidsLimit") != required["pids_limit"]
        or host.get("Memory") != required["memory_bytes"]
        or host.get("MemorySwap") != required["memory_swap_bytes"]
        or host.get("NanoCpus") != required["nano_cpus"]
        or host.get("Tmpfs") != expected_tmpfs
        or host.get("AutoRemove") is not False
        or host.get("Devices") not in (None, [])
        or not isinstance(actual_labels, dict)
        or any(actual_labels.get(key) != item for key, item in labels.items())
    ):
        raise RuntimeFailure("created candidate container does not match the fixed security policy")
    ulimits = host.get("Ulimits")
    if not isinstance(ulimits, list) or not any(
        item.get("Name") == "nofile"
        and item.get("Soft") == required["nofile_soft"]
        and item.get("Hard") == required["nofile_hard"]
        for item in ulimits
        if isinstance(item, dict)
    ):
        raise RuntimeFailure("candidate container nofile limit is missing")
    if len(mounts) != 1 or not isinstance(mounts[0], dict):
        raise RuntimeFailure("candidate container must have exactly one bind mount")
    mount = mounts[0]
    expected_source = str(workspace_root.resolve())
    actual_source = str(mount.get("Source", ""))
    if (
        mount.get("Type") != "bind"
        or os.path.normcase(actual_source) != os.path.normcase(expected_source)
        or mount.get("Destination") != required["workspace_destination"]
        or mount.get("RW") != (required["workspace_mode"] == "rw")
        or mount.get("Propagation") != required["workspace_propagation"]
    ):
        raise RuntimeFailure("candidate container bind mount escaped the disposable workspace")
    return {
        "container_id": value.get("Id"),
        "image_id": value.get("Image"),
        "name": value.get("Name"),
        "user": config.get("User"),
        "working_dir": config.get("WorkingDir"),
        "command": config.get("Cmd"),
        "entrypoint": config.get("Entrypoint"),
        "network_mode": host.get("NetworkMode"),
        "read_only_rootfs": host.get("ReadonlyRootfs"),
        "cap_drop": cap_drop,
        "security_opt": sorted(security),
        "pids_limit": host.get("PidsLimit"),
        "memory": host.get("Memory"),
        "memory_swap": host.get("MemorySwap"),
        "nano_cpus": host.get("NanoCpus"),
        "ipc_mode": host.get("IpcMode"),
        "cgroupns_mode": host.get("CgroupnsMode"),
        "mount": mount,
    }


def _remove_container(
    docker: Path,
    container_id: str,
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence_prefix: Path,
) -> dict[str, Any]:
    before = _inspect_container(
        docker,
        container_id,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        evidence=evidence_prefix.with_name(evidence_prefix.name + "_inspect_before_cleanup.json"),
    )
    running = bool((before.get("State") or {}).get("Running"))
    if running:
        _docker_command(
            docker,
            ["container", "kill", container_id],
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence=evidence_prefix.with_name(evidence_prefix.name + "_kill.json"),
        )
    _docker_command(
        docker,
        ["container", "rm", "--force", container_id],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        evidence=evidence_prefix.with_name(evidence_prefix.name + "_remove.json"),
    )
    verification = _docker_command(
        docker,
        ["container", "inspect", container_id],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        evidence=evidence_prefix.with_name(evidence_prefix.name + "_absence.json"),
        require_success=False,
    )
    if verification.return_code == 0 or "no such" not in verification.stderr.lower():
        raise RuntimeFailure("candidate container removal could not be independently verified")
    return {"container_id": container_id, "was_running": running, "removed": True, "absence_verified": True}


def run_candidate_container(
    *,
    docker: Path,
    image_id: str,
    policy_path: Path,
    workspace_root: Path,
    workdir: str,
    command: Sequence[str],
    run_id: str,
    cycle: int,
    command_id: str,
    authorization_sha256: str,
    registry_dir: Path,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence: Path,
    require_success: bool = True,
) -> ProcessResult:
    policy = load_container_policy(policy_path)
    workspace_root = validate_no_reparse_ancestors(workspace_root, require_exists=True)
    registry_dir = validate_no_reparse_ancestors(registry_dir, require_exists=True)
    if workspace_root == registry_dir or workspace_root in registry_dir.parents:
        raise RuntimeFailure("container lifecycle registry must be outside the candidate mount")
    _validate_container_tree(workspace_root)
    if not RUN_ID_RE.fullmatch(run_id) or not (0 <= cycle <= 10) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", command_id):
        raise RuntimeFailure("candidate container run identity is invalid")
    if not re.fullmatch(r"[a-f0-9]{64}", authorization_sha256) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise RuntimeFailure("candidate container authorization or image identity is invalid")
    if not command or any(not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096 for item in command):
        raise RuntimeFailure("candidate container command is invalid")
    normalized_workdir = workdir.strip("/")
    if workdir.startswith("/") or ".." in Path(normalized_workdir).parts or "\\" in workdir:
        raise RuntimeFailure("candidate container workdir is outside the workspace")
    token = secrets.token_hex(8)
    name = f"blastpit-{run_id.lower()}-c{cycle:03d}-{token}"[:63]
    labels = {
        CONTAINER_LABEL: "true",
        f"{CONTAINER_LABEL}.run-id": run_id,
        f"{CONTAINER_LABEL}.cycle": str(cycle),
        f"{CONTAINER_LABEL}.record-token": token,
        f"{CONTAINER_LABEL}.authorization": authorization_sha256,
        f"{CONTAINER_LABEL}.command": command_id,
    }
    record_path = registry_dir / f"container-{token}.json"
    retained_record = evidence.with_name(evidence.stem + "_container_lifecycle.json")
    if record_path.exists() or retained_record.exists():
        raise RuntimeFailure("candidate container lifecycle record already exists")
    record: dict[str, Any] = {
        "schema_version": CONTAINER_RECORD_SCHEMA,
        "runtime_version": CONTAINER_RUNTIME_VERSION,
        "record_token": token,
        "name": name,
        "container_id": None,
        "run_id": run_id,
        "cycle": cycle,
        "command_id": command_id,
        "authorization_sha256": authorization_sha256,
        "image_id": image_id,
        "workspace_root": str(workspace_root),
        "workspace_identity": directory_identity(workspace_root),
        "policy_sha256": legacy.canonical_text_sha256(policy.path),
        "command": list(command),
        "history": [],
    }
    _write_container_record(record_path, retained_record, record, "INTENT_FSYNCED")
    expected_workdir = policy.workspace_destination + (f"/{normalized_workdir}" if normalized_workdir and normalized_workdir != "." else "")
    mount = (
        f"type=bind,src={workspace_root},dst={policy.workspace_destination},"
        f"readonly,bind-propagation={policy.value['workspace_propagation']}"
    )
    create_args: list[str | Path] = [
        "container",
        "create",
        "--pull",
        policy.value["pull_policy"],
        "--platform",
        policy.value["platform"],
        "--name",
        name,
        "--network",
        policy.value["network_mode"],
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--security-opt",
        "seccomp=builtin",
        "--user",
        policy.value["user"],
        "--cgroupns",
        policy.value["cgroupns_mode"],
        "--ipc",
        policy.value["ipc_mode"],
        "--pids-limit",
        str(policy.value["pids_limit"]),
        "--memory",
        str(policy.value["memory_bytes"]),
        "--memory-swap",
        str(policy.value["memory_swap_bytes"]),
        "--cpus",
        str(policy.value["nano_cpus"] / 1_000_000_000),
        "--ulimit",
        f"nofile={policy.value['nofile_soft']}:{policy.value['nofile_hard']}",
        "--tmpfs",
        f"/tmp:{policy.value['tmpfs']['/tmp']}",
        "--tmpfs",
        f"/output:{policy.value['tmpfs']['/output']}",
        "--mount",
        mount,
        "--workdir",
        expected_workdir,
        "--env",
        "HOME=/tmp",
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "PYTHONNOUSERSITE=1",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONPYCACHEPREFIX=/tmp/pycache",
        "--env",
        "PYTHONPATH=",
        "--env",
        "PYGAME_HIDE_SUPPORT_PROMPT=1",
        "--env",
        "SDL_VIDEODRIVER=dummy",
        "--env",
        "SDL_AUDIODRIVER=dummy",
    ]
    for key, value in labels.items():
        create_args.extend(["--label", f"{key}={value}"])
    create_args.extend([image_id, *command])
    container_id: str | None = None
    result: ProcessResult | None = None
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        created = _docker_command(
            docker,
            create_args,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence=evidence.with_name(evidence.stem + "_container_create.json"),
        )
        container_id = created.stdout.strip()
        if not re.fullmatch(r"[a-f0-9]{64}", container_id):
            raise RuntimeFailure("Docker create returned an invalid container ID")
        _write_container_record(record_path, retained_record, record, "CREATED", container_id=container_id)
        inspected = _inspect_container(
            docker,
            container_id,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence=evidence.with_name(evidence.stem + "_container_inspect.json"),
        )
        policy_evidence = _assert_container_policy(
            inspected,
            policy=policy,
            image_id=image_id,
            workspace_root=workspace_root,
            name=name,
            labels=labels,
            expected_workdir=expected_workdir,
            expected_command=command,
        )
        atomic_json(evidence.with_name(evidence.stem + "_container_policy.json"), {"pass": True, **policy_evidence})
        _write_container_record(record_path, retained_record, record, "INSPECTED_QUALIFIED")
        _write_container_record(record_path, retained_record, record, "RUNNING")
        result = _docker_command(
            docker,
            ["container", "start", "--attach", container_id],
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence=evidence,
            require_success=False,
        )
        final = _inspect_container(
            docker,
            container_id,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence=evidence.with_name(evidence.stem + "_container_exit_inspect.json"),
        )
        state = final.get("State")
        if not isinstance(state, dict) or state.get("Running") is not False or state.get("ExitCode") != result.return_code:
            raise RuntimeFailure("candidate container exit state disagrees with attached process result")
        if state.get("OOMKilled") is not False:
            raise RuntimeFailure("candidate container was OOM-killed")
        _write_container_record(
            record_path,
            retained_record,
            record,
            "EXITED",
            exit_code=result.return_code,
            oom_killed=state.get("OOMKilled"),
        )
    except BaseException as exc:
        primary_error = exc
    finally:
        if container_id is not None:
            try:
                cleanup = _remove_container(
                    docker,
                    container_id,
                    cwd=cwd,
                    environment=environment,
                    timeout=min(120, max(15, timeout)),
                    evidence_prefix=evidence.with_name(evidence.stem + "_container_cleanup"),
                )
                _write_container_record(record_path, retained_record, record, "REMOVED", cleanup=cleanup)
            except BaseException as exc:
                cleanup_error = exc
                _write_container_record(
                    record_path,
                    retained_record,
                    record,
                    "RECOVERY_REQUIRED",
                    cleanup_error=f"{type(exc).__name__}: {exc}"[:1000],
                )
    if cleanup_error is not None:
        raise RuntimeFailure(f"candidate container cleanup requires recovery: {cleanup_error}") from cleanup_error
    if primary_error is not None:
        raise primary_error
    assert result is not None
    if require_success and result.return_code != 0:
        raise RuntimeFailure(f"candidate container command failed with exit {result.return_code}: {result.stderr[-1000:]}")
    return result


def list_governed_containers(
    *, docker: Path, cwd: Path, environment: dict[str, str], timeout: int
) -> list[str]:
    result = _docker_command(
        docker,
        ["container", "ls", "--all", "--no-trunc", "--filter", f"label={CONTAINER_LABEL}=true", "--format", "{{.ID}}"],
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )
    values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(values) > 64 or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in values) or len(values) != len(set(values)):
        raise RuntimeFailure("governed candidate container discovery returned invalid identities")
    return values


def recover_governed_containers(
    *,
    docker: Path,
    worktree_root: Path,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence_dir: Path,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    worktree_root = validate_no_reparse_ancestors(worktree_root, require_exists=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for container_id in list_governed_containers(docker=docker, cwd=cwd, environment=environment, timeout=timeout):
        inspected = _inspect_container(docker, container_id, cwd=cwd, environment=environment, timeout=timeout)
        labels = ((inspected.get("Config") or {}).get("Labels") or {})
        found_run_id = labels.get(f"{CONTAINER_LABEL}.run-id")
        token = labels.get(f"{CONTAINER_LABEL}.record-token")
        name = str(inspected.get("Name", "")).lstrip("/")
        if run_id is not None and found_run_id != run_id:
            continue
        if (
            not isinstance(labels, dict)
            or not isinstance(found_run_id, str)
            or not RUN_ID_RE.fullmatch(found_run_id)
            or not isinstance(token, str)
            or not re.fullmatch(r"[a-f0-9]{16}", token)
            or not name.startswith(f"blastpit-{found_run_id.lower()}-")
        ):
            raise RuntimeFailure(f"ambiguous governed container identity requires manual quarantine: {container_id}")
        workspace = require_strict_descendant(worktree_root / found_run_id, worktree_root, "container recovery workspace")
        record_path = workspace / f"container-{token}.json"
        if not record_path.is_file() or is_reparse(record_path) or record_path.stat(follow_symlinks=False).st_nlink != 1:
            raise RuntimeFailure(f"governed container has no safe durable lifecycle record: {container_id}")
        record = _strict_json_value(record_path.read_text(encoding="utf-8"), record_path.name)
        if (
            not isinstance(record, dict)
            or record.get("schema_version") != CONTAINER_RECORD_SCHEMA
            or record.get("record_token") != token
            or record.get("run_id") != found_run_id
            or record.get("name") != name
            or record.get("container_id") not in {None, container_id}
            or record.get("image_id") != inspected.get("Image")
            or record.get("authorization_sha256") != labels.get(f"{CONTAINER_LABEL}.authorization")
        ):
            raise RuntimeFailure(f"governed container lifecycle binding mismatch: {container_id}")
        cleanup = _remove_container(
            docker,
            container_id,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence_prefix=evidence_dir / f"{found_run_id}-{token}",
        )
        record["container_id"] = container_id
        record["state"] = "REMOVED_RECOVERY"
        record.setdefault("history", []).append({"state": "REMOVED_RECOVERY", "recorded_at": _utc_now()})
        record["cleanup"] = cleanup
        atomic_json(record_path, record)
        row = {"run_id": found_run_id, "record_token": token, "container_id": container_id, "removed": True}
        atomic_json(evidence_dir / f"{found_run_id}-{token}-outcome.json", {"pass": True, **row})
        rows.append(row)
    remaining = list_governed_containers(docker=docker, cwd=cwd, environment=environment, timeout=timeout)
    if run_id is None and remaining:
        raise RuntimeFailure(f"governed candidate containers remain after recovery: {remaining}")
    if run_id is not None:
        for container_id in remaining:
            inspected = _inspect_container(docker, container_id, cwd=cwd, environment=environment, timeout=timeout)
            labels = ((inspected.get("Config") or {}).get("Labels") or {})
            if labels.get(f"{CONTAINER_LABEL}.run-id") == run_id:
                raise RuntimeFailure(f"run-scoped candidate container remains after recovery: {container_id}")
    workspaces = [worktree_root / run_id] if run_id is not None else sorted(path for path in worktree_root.iterdir() if path.is_dir())
    remaining_set = set(remaining)
    for workspace in workspaces:
        if not workspace.exists() or not RUN_ID_RE.fullmatch(workspace.name):
            continue
        for record_path in sorted(workspace.glob("container-*.json")):
            if is_reparse(record_path) or not record_path.is_file() or record_path.stat(follow_symlinks=False).st_nlink != 1:
                raise RuntimeFailure(f"unsafe candidate container lifecycle record: {record_path}")
            record = _strict_json_value(record_path.read_text(encoding="utf-8"), record_path.name)
            if not isinstance(record, dict) or record.get("schema_version") != CONTAINER_RECORD_SCHEMA:
                raise RuntimeFailure(f"invalid candidate container lifecycle record: {record_path}")
            state = record.get("state")
            container_id = record.get("container_id")
            if state in {"REMOVED", "REMOVED_RECOVERY", "REMOVED_RECOVERY_ABSENT"}:
                continue
            if container_id is not None and container_id in remaining_set:
                raise RuntimeFailure(f"candidate container record remains active after recovery: {record_path}")
            record["state"] = "REMOVED_RECOVERY_ABSENT"
            record.setdefault("history", []).append({"state": "REMOVED_RECOVERY_ABSENT", "recorded_at": _utc_now()})
            record["cleanup"] = {"container_id": container_id, "removed": True, "absence_verified": True}
            atomic_json(record_path, record)
            outcome = {
                "run_id": workspace.name,
                "record_token": record.get("record_token"),
                "container_id": container_id,
                "removed": True,
                "already_absent": True,
            }
            atomic_json(evidence_dir / f"{workspace.name}-{record.get('record_token')}-absent-outcome.json", {"pass": True, **outcome})
            rows.append(outcome)
    atomic_json(
        evidence_dir / "recovery_operations_summary.json",
        {
            "schema_version": "blast-pit.container-recovery-operations.v1",
            "pass": True,
            "run_id": run_id,
            "recovered": rows,
        },
    )
    return rows


def assert_governed_containers_quiescent(
    *,
    docker: Path,
    worktree_root: Path,
    run_id: str,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence: Path,
) -> dict[str, Any]:
    if not RUN_ID_RE.fullmatch(run_id):
        raise RuntimeFailure("container quiescence run ID is invalid")
    active: list[str] = []
    for container_id in list_governed_containers(docker=docker, cwd=cwd, environment=environment, timeout=timeout):
        inspected = _inspect_container(docker, container_id, cwd=cwd, environment=environment, timeout=timeout)
        labels = ((inspected.get("Config") or {}).get("Labels") or {})
        if labels.get(f"{CONTAINER_LABEL}.run-id") == run_id:
            active.append(container_id)
    if active:
        raise RuntimeFailure(f"candidate containers are still active for the run: {active}")
    workspace = worktree_root / run_id
    records: list[dict[str, Any]] = []
    if workspace.exists():
        validate_no_reparse_ancestors(workspace, require_exists=True)
        for path in sorted(workspace.glob("container-*.json")):
            if is_reparse(path) or not path.is_file() or path.stat(follow_symlinks=False).st_nlink != 1:
                raise RuntimeFailure(f"unsafe candidate container lifecycle record: {path}")
            value = _strict_json_value(path.read_text(encoding="utf-8"), path.name)
            if (
                not isinstance(value, dict)
                or value.get("schema_version") != CONTAINER_RECORD_SCHEMA
                or value.get("run_id") != run_id
                or value.get("state") not in {"REMOVED", "REMOVED_RECOVERY", "REMOVED_RECOVERY_ABSENT"}
            ):
                raise RuntimeFailure(f"candidate container lifecycle is not terminal: {path}")
            records.append({"path": str(path), "state": value["state"], "sha256": legacy.sha256_file(path)})
    result = {
        "schema_version": "blast-pit.candidate-container-quiescence.v1",
        "pass": True,
        "active_containers": [],
        "terminal_records": records,
    }
    atomic_json(evidence, result)
    return result


def qualify_candidate_container(
    *,
    docker: Path,
    image_id: str,
    policy_path: Path,
    workspace_root: Path,
    canary_source: Path,
    run_id: str,
    cycle: int,
    authorization_sha256: str,
    registry_dir: Path,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    evidence_dir: Path,
    token: str,
) -> dict[str, Any]:
    source = validate_no_reparse_ancestors(canary_source, require_exists=True)
    if source.name != "improvement_container_canary.py" or not source.is_file():
        raise RuntimeFailure("candidate container canary source is missing or unsafe")
    canary = workspace_root / "improvement_container_canary.py"
    if canary.exists():
        raise RuntimeFailure("candidate container canary destination already exists")
    shutil.copyfile(source, canary, follow_symlinks=False)
    with canary.open("rb+") as handle:
        os.fsync(handle.fileno())
    if legacy.sha256_file(canary) != legacy.sha256_file(source):
        raise RuntimeFailure("candidate container canary copy hash mismatch")
    host_sentinel = registry_dir / "host-sentinel"
    atomic_text(host_sentinel, token)
    before = legacy.sha256_file(host_sentinel)
    try:
        result = run_candidate_container(
            docker=docker,
            image_id=image_id,
            policy_path=policy_path,
            workspace_root=workspace_root,
            workdir=".",
            command=["python", "/workspace/improvement_container_canary.py", "--token", token],
            run_id=run_id,
            cycle=cycle,
            command_id="isolation-canary",
            authorization_sha256=authorization_sha256,
            registry_dir=registry_dir,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            evidence=evidence_dir / "container_canary_command.json",
        )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise RuntimeFailure("candidate container canary must emit exactly one JSON line")
        value = _strict_json_value(lines[0], "candidate container canary")
        expected_success = {"output_write_cycle", "tmp_write", "native_process_contained"}
        probes = value.get("probes") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "token", "uid", "gid", "workspace", "probes", "pass"}
            or value.get("schema_version") != "blast-pit.candidate-container-canary.v1"
            or value.get("token") != token
            or value.get("uid") != 65532
            or value.get("gid") != 65532
            or value.get("workspace") != "/workspace"
            or value.get("pass") is not True
            or not isinstance(probes, list)
            or len(probes) != 18
            or {row.get("label") for row in probes if isinstance(row, dict)}
            != (
                expected_success
                | {"workspace_write_cycle", "readonly_root_write", "python_socket", "native_socket", "raw_socket", "native_mount", "numpy_fromfile_host", "numpy_memmap_host", "ctypes_open_host"}
                | {f"forbidden_path_{index}" for index in range(6)}
            )
        ):
            raise RuntimeFailure("candidate container canary output contract mismatch")
        for row in probes:
            if not isinstance(row, dict) or set(row) != {"label", "succeeded", "error", "detail"}:
                raise RuntimeFailure("candidate container probe contract mismatch")
            if (row["label"] in expected_success) != bool(row["succeeded"]):
                raise RuntimeFailure(f"candidate container adversarial probe failed: {row['label']}")
        if not host_sentinel.is_file() or legacy.sha256_file(host_sentinel) != before:
            raise RuntimeFailure("candidate container changed the external host sentinel")
        qualification = {
            "schema_version": "blast-pit.candidate-container-qualification.v1",
            "pass": True,
            "runtime_version": CONTAINER_RUNTIME_VERSION,
            "image_id": image_id,
            "network_isolation": "docker-network-none",
            "host_filesystem_mounts": ["disposable-workspace-read-only"],
            "writable_filesystems": ["bounded-tmpfs:/tmp", "bounded-tmpfs:/output"],
            "native_extension_escape_probes": "PASS",
            "python_audit_hook_security_boundary": False,
            "container_canary_sha256": legacy.sha256_file(source),
            "canary_evidence": "container_canary.json",
        }
        atomic_json(evidence_dir / "container_canary.json", value)
        atomic_json(evidence_dir / "container_qualification.json", qualification)
        return qualification
    finally:
        canary.unlink(missing_ok=True)
        host_sentinel.unlink(missing_ok=True)


def guarded_python_script_command(
    *,
    python: Path,
    guard: Path,
    root: Path,
    script: Path,
    arguments: Sequence[str | Path],
) -> list[str | Path]:
    guard = validate_no_reparse_ancestors(guard, require_exists=True)
    script = validate_no_reparse_ancestors(script, require_exists=True)
    root = validate_no_reparse_ancestors(root, require_exists=True)
    if not guard.is_file() or guard.name != "improvement_candidate_guard.py" or not script.is_file() or root not in script.parents:
        raise RuntimeFailure("guarded Python script command has an unsafe fixed target")
    return [
        python,
        guard,
        "--root",
        root,
        "--script",
        script,
        "--target-sha256",
        legacy.sha256_file(script),
        "--",
        *arguments,
    ]


def guarded_python_module_command(
    *,
    python: Path,
    guard: Path,
    root: Path,
    module: str,
    arguments: Sequence[str | Path],
) -> list[str | Path]:
    guard = validate_no_reparse_ancestors(guard, require_exists=True)
    root = validate_no_reparse_ancestors(root, require_exists=True)
    if not guard.is_file() or guard.name != "improvement_candidate_guard.py" or module not in {"py_compile", "pytest"}:
        raise RuntimeFailure("guarded Python module command is outside the fixed allowlist")
    return [python, guard, "--root", root, "--module", module, "--", *arguments]


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
    base_arguments: list[str | Path] = []
    for path in allowed:
        base_arguments.extend(["--allowed", path])
    for path in forbidden:
        base_arguments.extend(["--forbidden", path])
    route_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        route_probe.connect(("192.0.2.1", 9))
        bind_host = route_probe.getsockname()[0]
    finally:
        route_probe.close()
    if bind_host.startswith("127.") or bind_host == "0.0.0.0":
        raise RuntimeFailure("a non-loopback interface is required for the network capability canary")

    def run_probe(label: str, guarded: bool) -> tuple[dict[str, Any], ProcessResult, str, int]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_host, 0))
        listener.listen(1)
        network_host, network_port = listener.getsockname()
        arguments = [
            *base_arguments,
            "--protected-file",
            canary_source.parent / "tmp_2d_simulator_v37.py",
            "--network-host",
            network_host,
            "--network-port",
            str(network_port),
            "--token",
            f"{token}-{label}",
        ]
        command: list[str | Path]
        if guarded:
            command = guarded_python_script_command(
                python=python,
                guard=canary_source.parent / "improvement_candidate_guard.py",
                root=allowed[0],
                script=canary_copy,
                arguments=arguments,
            )
        else:
            command = [python, canary_copy, *arguments]
        try:
            result = run_sandboxed(
                codex=codex,
                profile=profile,
                cwd=cwd,
                command=command,
                timeout=timeout,
                environment=environment,
                evidence=evidence_dir / f"{label}_sandbox_canary_command.json",
                require_success=False,
            )
        finally:
            listener.close()
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        try:
            if len(lines) != 1:
                raise ValueError("canary must emit exactly one JSON line")
            value = json.loads(lines[0])
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeFailure(f"{label} sandbox canary returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeFailure(f"{label} sandbox canary output must be an object")
        atomic_json(evidence_dir / f"{label}_sandbox_canary.json", value)
        return value, result, network_host, network_port

    raw_value, raw_result, raw_host, raw_port = run_probe("raw", False)
    guarded_value, guarded_result, guarded_host, guarded_port = run_probe("guarded", True)
    expected_operations = {
        "file_create_fsync_unlink",
        "directory_create_rmdir",
        "directory_create_rename_rmdir",
        "file_create_rename_cleanup",
    }

    def validate_rows(value: dict[str, Any], kind: str, expected_paths: Sequence[Path]) -> bool:
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

    expected_guards = {
        "root_delete_handle",
        "root_write_dac_handle",
        "root_write_owner_handle",
        "root_rename",
        "hardlink_protected_file",
        "symlink_forbidden_directory",
    }
    raw_guards = raw_value.get("boundary_guards")
    raw_guard_pass = (
        isinstance(raw_guards, list)
        and {item.get("operation") for item in raw_guards if isinstance(item, dict)} == expected_guards
        and all(
            set(item) == {"operation", "succeeded", "permission_denied", "breach", "cleanup_ok", "error"}
            and item.get("succeeded") is False
            and item.get("permission_denied") is True
            and item.get("breach") is False
            and item.get("cleanup_ok") is True
            for item in raw_guards
        )
    )

    exact_fields = {
        "schema_version", "token", "allowed", "forbidden", "boundary_guards", "network_observation",
        "protected_read_observation", "process_observation", "filesystem_pass", "pass",
    }

    def observation(value: dict[str, Any], name: str, fields: set[str]) -> dict[str, Any]:
        row = value.get(name)
        if not isinstance(row, dict) or set(row) != fields:
            raise RuntimeFailure(f"sandbox canary {name} contract mismatch")
        return row

    for label, value, result, host, port in (
        ("raw", raw_value, raw_result, raw_host, raw_port),
        ("guarded", guarded_value, guarded_result, guarded_host, guarded_port),
    ):
        if (
            set(value) != exact_fields
            or value.get("schema_version") != "blast-pit.sandbox-canary.v4"
            or value.get("token") != f"{token}-{label}"
            or value.get("pass") is not True
            or value.get("filesystem_pass") is not True
            or not validate_rows(value, "allowed", allowed)
            or not validate_rows(value, "forbidden", forbidden)
            or result.return_code != 0
        ):
            raise RuntimeFailure(f"{label} sandbox filesystem canary did not pass")
        network = observation(value, "network_observation", {"host", "port", "succeeded", "permission_denied", "breach", "error"})
        if network.get("host") != host or network.get("port") != port:
            raise RuntimeFailure(f"{label} network observation endpoint mismatch")
        observation(value, "protected_read_observation", {"path", "succeeded", "permission_denied", "error"})
        observation(value, "process_observation", {"succeeded", "permission_denied", "error"})

    raw_network = raw_value["network_observation"]
    raw_network_valid = (
        raw_network.get("succeeded") is True
        and raw_network.get("permission_denied") is False
        and raw_network.get("breach") is True
        and raw_network.get("error") is None
    ) or (
        raw_network.get("succeeded") is False
        and raw_network.get("permission_denied") is True
        and raw_network.get("breach") is False
    )
    raw_read = raw_value["protected_read_observation"]
    raw_process = raw_value["process_observation"]
    raw_capabilities_valid = all(
        (row.get("succeeded") is True and row.get("permission_denied") is False and row.get("error") is None)
        or (row.get("succeeded") is False and row.get("permission_denied") is True)
        for row in (raw_read, raw_process)
    )
    if raw_read.get("path") != str((canary_source.parent / "tmp_2d_simulator_v37.py").resolve()):
        raw_capabilities_valid = False
    guarded_network = guarded_value["network_observation"]
    guarded_read = guarded_value["protected_read_observation"]
    guarded_process = guarded_value["process_observation"]
    guarded_policy_pass = all(
        row.get("succeeded") is False and row.get("permission_denied") is True
        for row in (guarded_network, guarded_read, guarded_process)
    )
    if not raw_guard_pass or not raw_network_valid or not raw_capabilities_valid or not guarded_policy_pass:
        detail = canonical(
            {
                "raw_guard_pass": raw_guard_pass,
                "raw_network": raw_network,
                "raw_read": raw_read,
                "raw_process": raw_process,
                "guarded_network": guarded_network,
                "guarded_read": guarded_read,
                "guarded_process": guarded_process,
            }
        )
        raise RuntimeFailure(f"Windows patch boundary or defense-in-depth audit-guard smoke test did not pass: {detail[:2000]}")
    qualification = {
        "schema_version": "blast-pit.windows-patch-boundary-qualification.v2",
        "pass": True,
        "windows_patch_filesystem_boundary_pass": True,
        "raw_os_network_isolated": raw_network.get("permission_denied") is True,
        "audit_guard_smoke_pass": True,
        "candidate_execution_security_boundary": False,
        "candidate_execution_boundary": "authorization-bound Docker container, qualified separately",
        "raw_evidence": "raw_sandbox_canary.json",
        "guarded_evidence": "guarded_sandbox_canary.json",
    }
    atomic_json(evidence_dir / "sandbox_canary.json", qualification)
    atomic_json(evidence_dir / "sandbox_qualification.json", qualification)
    return qualification


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
