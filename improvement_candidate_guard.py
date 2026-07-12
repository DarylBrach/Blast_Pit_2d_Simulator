from __future__ import annotations

"""Fixed-interface Python audit guard for sandboxed candidate execution."""

import argparse
import hashlib
import os
import runpy
import site
import stat
import sys
from pathlib import Path
from typing import Sequence


ALLOWED_MODULES = {"py_compile", "pytest"}
DENIED_AUDIT_EVENTS = {
    "subprocess.Popen",
    "os.system",
    "os.startfile",
    "os.startfile/2",
    "os.posix_spawn",
    "os.spawn",
    "os.exec",
    "winreg.OpenKey",
    "winreg.OpenKey/result",
    "winreg.CreateKey",
    "winreg.DeleteKey",
    "winreg.SetValue",
}


class GuardError(ValueError):
    pass


def is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def validate_root(raw: str) -> Path:
    path = Path(raw).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if not current.exists() or is_reparse(current):
            raise GuardError(f"candidate guard root has a missing or reparse ancestor: {current}")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or resolved == Path(resolved.anchor):
        raise GuardError("candidate guard root is invalid")
    return resolved


def validate_script(raw: str, root: Path, expected_sha256: str) -> Path:
    if not expected_sha256 or len(expected_sha256) != 64 or any(character not in "0123456789abcdef" for character in expected_sha256):
        raise GuardError("candidate script hash is invalid")
    path = Path(raw).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if not current.exists() or is_reparse(current):
            raise GuardError(f"candidate script has a missing or reparse ancestor: {current}")
    resolved = path.resolve(strict=True)
    info = resolved.stat(follow_symlinks=False)
    if root not in resolved.parents or resolved.suffix.lower() != ".py" or not resolved.is_file() or info.st_nlink != 1:
        raise GuardError("candidate script is outside the fixed root or is unsafe")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise GuardError("candidate script hash changed before guarded execution")
    return resolved


def _library_read_roots() -> tuple[Path, ...]:
    candidates = [Path(sys.executable).resolve().parent, Path(os.__file__).resolve().parent]
    candidates.extend(
        path
        for value in site.getsitepackages()
        if (path := Path(value).resolve()).name.lower() == "site-packages"
    )
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        candidates.append(Path(system_root).resolve())
    return tuple(dict.fromkeys(path for path in candidates if path.is_dir()))


def install_audit_guard(root: Path) -> None:
    library_roots = _library_read_roots()

    def resolve_path(value: object) -> Path:
        if not isinstance(value, (str, bytes, os.PathLike)):
            raise PermissionError(13, "candidate guard denied non-path filesystem target")
        return Path(os.path.abspath(os.fsdecode(value))).resolve(strict=False)

    def inside(path: Path, roots: tuple[Path, ...]) -> bool:
        return any(path == item or item in path.parents for item in roots)

    def audit(event: str, args: tuple[object, ...]) -> None:
        if event.startswith("socket.") or event in DENIED_AUDIT_EVENTS:
            raise PermissionError(13, f"candidate guard denied audit event: {event}")
        if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            raw = os.fsdecode(args[0])
            normalized = raw.rstrip("\\/").upper()
            if normalized in {"NUL", r"\\.\NUL"}:
                return
            path = resolve_path(raw)
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            write_intent = isinstance(mode, str) and any(character in mode for character in "wax+")
            write_intent = write_intent or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            allowed = inside(path, (root,)) if write_intent else inside(path, (root, *library_roots))
            if not allowed:
                raise PermissionError(13, f"candidate guard denied file access outside fixed roots: {path}")
        single_path_events = {
            "os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.truncate", "os.utime", "os.chdir",
        }
        if event in single_path_events and args:
            if len(args) > 1 and event in {"os.remove", "os.rmdir", "os.mkdir"} and args[-1] not in {-1, None}:
                raise PermissionError(13, f"candidate guard denied dir_fd mutation: {event}")
            path = resolve_path(args[0])
            if not inside(path, (root,)):
                raise PermissionError(13, f"candidate guard denied path mutation outside candidate root: {event}: {path}")
        if event == "os.rename" and len(args) >= 2:
            if len(args) > 2 and any(value not in {-1, None} for value in args[2:]):
                raise PermissionError(13, "candidate guard denied dir_fd rename")
            paths = (resolve_path(args[0]), resolve_path(args[1]))
            if not all(inside(path, (root,)) for path in paths):
                raise PermissionError(13, f"candidate guard denied rename outside candidate root: {paths}")
        if event == "os.link" and len(args) >= 2:
            if len(args) > 2 and any(value not in {-1, None} for value in args[2:]):
                raise PermissionError(13, "candidate guard denied dir_fd hardlink")
            paths = (resolve_path(args[0]), resolve_path(args[1]))
            if not all(inside(path, (root,)) for path in paths):
                raise PermissionError(13, f"candidate guard denied hardlink outside candidate root: {paths}")
        if event == "os.symlink":
            raise PermissionError(13, "candidate guard denies all symbolic-link creation")
        if event in {"os.listdir", "os.scandir"} and args and args[0] is not None:
            path = resolve_path(args[0])
            if not inside(path, (root, *library_roots)):
                raise PermissionError(13, f"candidate guard denied directory enumeration outside fixed roots: {path}")
    sys.addaudithook(audit)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one authorized Python target under a fixed audit guard")
    parser.add_argument("--root", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--script")
    mode.add_argument("--module", choices=sorted(ALLOWED_MODULES))
    parser.add_argument("--target-sha256")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        options = build_parser().parse_args(argv)
        root = validate_root(options.root)
        arguments = list(options.args)
        if arguments[:1] == ["--"]:
            arguments.pop(0)
        if options.script:
            script = validate_script(options.script, root, options.target_sha256 or "")
            install_audit_guard(root)
            sys.path.insert(0, str(script.parent))
            sys.path.insert(0, os.getcwd())
            sys.argv = [str(script), *arguments]
            runpy.run_path(str(script), run_name="__main__")
        else:
            if options.target_sha256 is not None:
                raise GuardError("module mode does not accept a target hash")
            install_audit_guard(root)
            sys.path.insert(0, os.getcwd())
            sys.argv = [str(options.module), *arguments]
            runpy.run_module(str(options.module), run_name="__main__", alter_sys=True)
        return 0
    except GuardError as exc:
        print(f"candidate guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
