from __future__ import annotations

"""Adversarial, single-line qualification probe for the candidate container."""

import argparse
import ctypes
import errno
import json
import os
import socket
from pathlib import Path

import numpy as np


SCHEMA = "blast-pit.candidate-container-canary.v1"


def attempt(label: str, operation) -> dict[str, object]:
    try:
        value = operation()
        return {"label": label, "succeeded": True, "error": None, "detail": value}
    except BaseException as exc:  # the contract records denial without hiding the error class
        return {
            "label": label,
            "succeeded": False,
            "error": f"{type(exc).__name__}: {exc}"[:500],
            "detail": None,
        }


def write_cycle(root: Path) -> bool:
    directory = root / "canary-dir"
    first = directory / "first.bin"
    second = directory / "second.bin"
    directory.mkdir()
    with first.open("wb") as handle:
        handle.write(b"candidate-container-canary")
        handle.flush()
        os.fsync(handle.fileno())
    first.replace(second)
    second.unlink()
    directory.rmdir()
    return not directory.exists()


def native_open(path: str) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = int(libc.open(os.fsencode(path), os.O_RDONLY))
    if descriptor >= 0:
        libc.close(descriptor)
        return descriptor
    code = ctypes.get_errno()
    raise OSError(code, os.strerror(code), path)


def native_network() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = int(libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
    if descriptor < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    try:
        # NetworkMode=none has loopback only and no route to this metadata address.
        address = socket.inet_aton("169.254.169.254")
        raw = b"\x02\x00" + (80).to_bytes(2, "big") + address + (b"\x00" * 8)
        buffer = ctypes.create_string_buffer(raw)
        result = int(libc.connect(descriptor, ctypes.byref(buffer), len(raw)))
        if result == 0:
            return result
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    finally:
        libc.close(descriptor)


def native_mount() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = int(libc.mount(b"none", b"/tmp", b"tmpfs", 0, None))
    if result == 0:
        libc.umount2(b"/tmp", 0)
        return result
    code = ctypes.get_errno()
    raise OSError(code, os.strerror(code))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    options = parser.parse_args()
    workspace = Path("/workspace")
    native_process_target = Path("/tmp/native-process-contained")
    forbidden = [
        "/host_mnt",
        "/run/desktop/mnt/host",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/workspace/../candidate-control/host-sentinel",
        "/proc/1/root/run/desktop/mnt/host",
    ]
    probes: list[dict[str, object]] = []
    probes.append(attempt("workspace_write_cycle", lambda: write_cycle(workspace)))
    probes.append(attempt("output_write_cycle", lambda: write_cycle(Path("/output"))))
    probes.append(attempt("tmp_write", lambda: Path("/tmp/canary").write_text(options.token, encoding="utf-8")))
    probes.append(attempt("readonly_root_write", lambda: Path("/etc/candidate-breach").write_text(options.token, encoding="utf-8")))
    probes.append(attempt("python_socket", lambda: socket.create_connection(("169.254.169.254", 80), timeout=0.5)))
    probes.append(attempt("native_socket", native_network))
    probes.append(attempt("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)))
    probes.append(attempt("native_mount", native_mount))
    probes.append(attempt("numpy_fromfile_host", lambda: np.fromfile(forbidden[1], dtype=np.uint8)))
    probes.append(attempt("numpy_memmap_host", lambda: np.memmap(forbidden[1], dtype=np.uint8, mode="r")))
    probes.append(attempt("ctypes_open_host", lambda: native_open(forbidden[1])))
    for index, path in enumerate(forbidden):
        probes.append(attempt(f"forbidden_path_{index}", lambda path=path: Path(path).read_bytes()))
    libc = ctypes.CDLL(None, use_errno=True)
    process_result = int(libc.system(b"/usr/bin/touch /tmp/native-process-contained"))
    probes.append(
        {
            "label": "native_process_contained",
            "succeeded": process_result == 0 and native_process_target.is_file(),
            "error": None if process_result == 0 else f"system returned {process_result}",
            "detail": "container-only",
        }
    )
    expected_success = {"output_write_cycle", "tmp_write", "native_process_contained"}
    passed = all((row["label"] in expected_success) == bool(row["succeeded"]) for row in probes)
    record = {
        "schema_version": SCHEMA,
        "token": options.token,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "workspace": str(workspace),
        "probes": probes,
        "pass": passed and os.getuid() == 65532 and os.getgid() == 65532,
    }
    print(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    return 0 if record["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
