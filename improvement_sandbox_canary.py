from __future__ import annotations

"""Fail-closed write-boundary canary for governed improvement workers."""

import argparse
import json
import os
import re
import stat
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
        "file_create_rename_cleanup": (directory / f"{prefix}.rename-src", directory / f"{prefix}.rename-dst"),
    }


def validate_targets_absent(paths: Sequence[Path]) -> None:
    for path in paths:
        if path.exists() or path.is_symlink() or is_reparse_point(path):
            raise CanaryError(f"pre-existing canary target is forbidden: {path}")


def permission_denied(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5


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


def run_canary(allowed: Sequence[str], forbidden: Sequence[str], token: str) -> dict[str, object]:
    allowed_paths, forbidden_paths = validate_inputs(allowed, forbidden, token)
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
    passed = all(row["pass"] for row in allowed_results) and all(row["pass"] for row in forbidden_results)
    return {"schema_version": "blast-pit.sandbox-canary.v1", "token": token,
            "allowed": allowed_results, "forbidden": forbidden_results, "pass": passed}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify allowed and forbidden sandbox write boundaries")
    parser.add_argument("--allowed", action="append", required=True)
    parser.add_argument("--forbidden", action="append", required=True)
    parser.add_argument("--token", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = run_canary(args.allowed, args.forbidden, args.token)
    except (CanaryError, OSError) as exc:
        result = {"schema_version": "blast-pit.sandbox-canary.v1", "pass": False,
                  "error": f"{type(exc).__name__}: {exc}", "allowed": [], "forbidden": []}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
