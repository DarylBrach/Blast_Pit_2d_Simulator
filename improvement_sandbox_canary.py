from __future__ import annotations

"""Fail-closed write-boundary canary for governed improvement workers."""

import argparse
import ctypes
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Sequence


MAX_PATHS = 32
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class CanaryError(ValueError):
    pass


def is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def lexical_ancestors(path: Path) -> list[Path]:
    absolute = path.absolute()
    return [absolute, *absolute.parents]


def validate_directory(raw: str) -> Path:
    path = Path(raw).expanduser()
    for ancestor in lexical_ancestors(path):
        if ancestor.exists() and (ancestor.is_symlink() or is_reparse_point(ancestor)):
            raise CanaryError(f"symlink or reparse-point ancestor is forbidden: {ancestor}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CanaryError(f"path does not resolve to an existing directory: {raw}") from exc
    if not resolved.is_dir():
        raise CanaryError(f"path is not a directory: {raw}")
    if resolved == Path(resolved.anchor):
        raise CanaryError(f"filesystem root is forbidden: {raw}")
    return resolved


def paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_inputs(allowed: Sequence[str], forbidden: Sequence[str], token: str) -> tuple[list[Path], list[Path]]:
    if not TOKEN_RE.fullmatch(token):
        raise CanaryError("token must contain 1-64 safe filename characters")
    if not allowed or not forbidden:
        raise CanaryError("at least one --allowed and one --forbidden path are required")
    if len(allowed) + len(forbidden) > MAX_PATHS:
        raise CanaryError(f"path count exceeds {MAX_PATHS}")
    allowed_paths = [validate_directory(value) for value in allowed]
    forbidden_paths = [validate_directory(value) for value in forbidden]
    combined = allowed_paths + forbidden_paths
    for index, left in enumerate(combined):
        for right in combined[index + 1:]:
            if paths_overlap(left, right):
                raise CanaryError(f"duplicate or nested path roots are forbidden: {left} and {right}")
    return allowed_paths, forbidden_paths


def operation_targets(directory: Path, token: str) -> dict[str, tuple[Path, ...]]:
    prefix = f".codex-sandbox-canary-{token}"
    return {
        "file_create_fsync_unlink": (directory / f"{prefix}.file",),
        "directory_create_rmdir": (directory / f"{prefix}.dir",),
        "directory_create_rename_rmdir": (directory / f"{prefix}.dir-src", directory / f"{prefix}.dir-dst"),
        "file_create_rename_cleanup": (directory / f"{prefix}.rename-src", directory / f"{prefix}.rename-dst"),
    }


def validate_targets_absent(paths: Sequence[Path]) -> None:
    for path in paths:
        if path.exists() or path.is_symlink() or is_reparse_point(path):
            raise CanaryError(f"pre-existing canary target is forbidden: {path}")


def permission_denied(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 1314}


def probe_operation(directory: Path, token: str, operation: str) -> dict[str, object]:
    targets = operation_targets(directory, token)[operation]
    validate_targets_absent(targets)
    created: list[tuple[Path, str]] = []
    succeeded = False
    denied = False
    error = None
    try:
        if operation == "file_create_fsync_unlink":
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(targets[0], flags, 0o600); created.append((targets[0], "file"))
            try:
                os.write(descriptor, token.encode("ascii")); os.fsync(descriptor)
            finally:
                os.close(descriptor)
        elif operation == "directory_create_rmdir":
            targets[0].mkdir(); created.append((targets[0], "directory"))
        elif operation == "directory_create_rename_rmdir":
            targets[0].mkdir(); created.append((targets[0], "directory"))
            os.rename(targets[0], targets[1]); created[-1] = (targets[1], "directory")
        elif operation == "file_create_rename_cleanup":
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(targets[0], flags, 0o600); created.append((targets[0], "file"))
            try:
                os.write(descriptor, token.encode("ascii")); os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(targets[0], targets[1]); created[-1] = (targets[1], "file")
        succeeded = True
    except OSError as exc:
        denied = permission_denied(exc)
        error = f"{type(exc).__name__}: {exc}"
    cleanup_ok = True
    for path, kind in reversed(created):
        try:
            if kind == "file":
                if path.is_file() and not path.is_symlink() and not is_reparse_point(path): path.unlink()
                else: cleanup_ok = False
            else:
                if path.is_dir() and not path.is_symlink() and not is_reparse_point(path): path.rmdir()
                else: cleanup_ok = False
        except OSError as exc:
            cleanup_ok = False; error = error or f"cleanup {type(exc).__name__}: {exc}"
    return {"operation": operation, "succeeded": succeeded, "permission_denied": denied,
            "breach": bool(created), "cleanup_ok": cleanup_ok, "error": error}


def probe_root_access(root: Path, operation: str, desired_access: int) -> dict[str, object]:
    succeeded = False
    denied = False
    error = None
    handle = None
    if os.name != "nt":
        error = "CanaryError: Windows root-access probe is unavailable"
    else:
        create_file = ctypes.windll.kernel32.CreateFileW
        create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        create_file.restype = ctypes.c_void_p
        handle = create_file(str(root), desired_access, 0x1 | 0x2 | 0x4, None, 3, 0x02000000, None)
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            winerror = ctypes.windll.kernel32.GetLastError()
            denied = winerror == 5
            error = f"PermissionError: winerror={winerror}" if denied else f"OSError: winerror={winerror}"
        else:
            succeeded = True
            ctypes.windll.kernel32.CloseHandle(handle)
    return {"operation": operation, "succeeded": succeeded, "permission_denied": denied,
            "breach": succeeded, "cleanup_ok": True, "error": error}


def probe_boundary_operation(root: Path, forbidden: Path, protected_file: Path, token: str, operation: str) -> dict[str, object]:
    if operation == "root_delete_handle":
        return probe_root_access(root, operation, 0x00010000)
    if operation == "root_write_dac_handle":
        return probe_root_access(root, operation, 0x00040000)
    if operation == "root_write_owner_handle":
        return probe_root_access(root, operation, 0x00080000)
    target = root.parent / f".{root.name}.codex-root-rename-{token}" if operation == "root_rename" else root / f".codex-boundary-{operation}-{token}"
    validate_targets_absent([target])
    succeeded = False
    denied = False
    breach = False
    cleanup_ok = True
    error = None
    try:
        if operation == "root_rename":
            os.rename(root, target)
            succeeded = breach = True
            os.rename(target, root)
        elif operation == "hardlink_protected_file":
            os.link(protected_file, target)
            succeeded = breach = True
        elif operation == "symlink_forbidden_directory":
            os.symlink(forbidden, target, target_is_directory=True)
            succeeded = breach = True
        else:
            raise CanaryError(f"unsupported boundary operation: {operation}")
    except OSError as exc:
        denied = permission_denied(exc)
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if target.exists() or target.is_symlink() or is_reparse_point(target):
            try:
                if operation == "root_rename" and target.is_dir():
                    os.rename(target, root)
                else:
                    target.unlink()
            except OSError as exc:
                cleanup_ok = False
                error = error or f"cleanup {type(exc).__name__}: {exc}"
    return {"operation": operation, "succeeded": succeeded, "permission_denied": denied,
            "breach": breach, "cleanup_ok": cleanup_ok, "error": error}


def probe_network(host: str, port: int) -> dict[str, object]:
    succeeded = False
    denied = False
    error = None
    connection = None
    try:
        connection = socket.create_connection((host, port), timeout=3.0)
        succeeded = True
    except OSError as exc:
        denied = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {5, 10013}
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if connection is not None:
            connection.close()
    return {"host": host, "port": port, "succeeded": succeeded, "permission_denied": denied,
            "breach": succeeded, "error": error}


def probe_protected_read(path: Path) -> dict[str, object]:
    succeeded = False
    denied = False
    error = None
    try:
        with path.open("rb") as handle:
            handle.read(1)
        succeeded = True
    except OSError as exc:
        denied = permission_denied(exc)
        error = f"{type(exc).__name__}: {exc}"
    return {"path": str(path), "succeeded": succeeded, "permission_denied": denied, "error": error}


def probe_child_process() -> dict[str, object]:
    succeeded = False
    denied = False
    error = None
    try:
        result = subprocess.run([sys.executable, "-c", "pass"], timeout=10, check=False)
        succeeded = result.returncode == 0
        if not succeeded:
            error = f"child exit={result.returncode}"
    except OSError as exc:
        denied = permission_denied(exc)
        error = f"{type(exc).__name__}: {exc}"
    return {"succeeded": succeeded, "permission_denied": denied, "error": error}


def run_canary(
    allowed: Sequence[str],
    forbidden: Sequence[str],
    protected_file_raw: str,
    network_host: str,
    network_port: int,
    token: str,
) -> dict[str, object]:
    allowed_paths, forbidden_paths = validate_inputs(allowed, forbidden, token)
    protected_file = Path(protected_file_raw).resolve(strict=True)
    if not protected_file.is_file() or protected_file.is_symlink() or is_reparse_point(protected_file):
        raise CanaryError("protected hardlink source is missing or unsafe")
    if not any(path == protected_file.parent or path in protected_file.parents for path in forbidden_paths):
        raise CanaryError("protected hardlink source is outside the forbidden roots")
    operations = tuple(operation_targets(allowed_paths[0], token))
    for path in (*allowed_paths, *forbidden_paths):
        validate_targets_absent([target for targets in operation_targets(path, token).values() for target in targets])
    allowed_results = []
    forbidden_results = []
    for path in allowed_paths:
        rows = [probe_operation(path, token, operation) for operation in operations]
        allowed_results.append({"path": str(path), "operations": rows,
                                "pass": all(row["succeeded"] and row["cleanup_ok"] for row in rows)})
    for path in forbidden_paths:
        rows = [probe_operation(path, token, operation) for operation in operations]
        forbidden_results.append({"path": str(path), "operations": rows,
                                  "pass": all((not row["succeeded"]) and row["permission_denied"] and not row["breach"] for row in rows)})
    boundary_operations = (
        "root_delete_handle", "root_write_dac_handle", "root_write_owner_handle", "root_rename",
        "hardlink_protected_file", "symlink_forbidden_directory",
    )
    boundary_results = [probe_boundary_operation(allowed_paths[0], forbidden_paths[0], protected_file, token, item)
                        for item in boundary_operations]
    boundary_pass = all((not row["succeeded"]) and row["permission_denied"] and not row["breach"] and row["cleanup_ok"]
                        for row in boundary_results)
    try:
        network_address = ipaddress.ip_address(network_host)
    except ValueError as exc:
        raise CanaryError("network canary endpoint is invalid") from exc
    if (
        network_address.version != 4
        or network_address.is_loopback
        or network_address.is_unspecified
        or network_address.is_multicast
        or isinstance(network_port, bool)
        or not 1 <= network_port <= 65535
    ):
        raise CanaryError("network canary endpoint is invalid")
    network_result = probe_network(network_host, network_port)
    protected_read = probe_protected_read(protected_file)
    child_process = probe_child_process()
    passed = all(row["pass"] for row in allowed_results) and all(row["pass"] for row in forbidden_results) and boundary_pass
    return {"schema_version": "blast-pit.sandbox-canary.v4", "token": token,
            "allowed": allowed_results, "forbidden": forbidden_results, "boundary_guards": boundary_results,
            "network_observation": network_result, "protected_read_observation": protected_read,
            "process_observation": child_process, "filesystem_pass": passed, "pass": passed}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify allowed and forbidden sandbox write boundaries")
    parser.add_argument("--allowed", action="append", required=True)
    parser.add_argument("--forbidden", action="append", required=True)
    parser.add_argument("--protected-file", required=True)
    parser.add_argument("--network-host", required=True)
    parser.add_argument("--network-port", required=True, type=int)
    parser.add_argument("--token", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = run_canary(args.allowed, args.forbidden, args.protected_file, args.network_host, args.network_port, args.token)
    except (CanaryError, OSError) as exc:
        result = {"schema_version": "blast-pit.sandbox-canary.v4", "pass": False, "filesystem_pass": False,
                  "error": f"{type(exc).__name__}: {exc}", "allowed": [], "forbidden": [],
                  "boundary_guards": [], "network_observation": {}, "protected_read_observation": {},
                  "process_observation": {}}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
