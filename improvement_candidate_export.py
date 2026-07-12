from __future__ import annotations

"""Trusted bounded stdout exporter for candidate-container training output."""

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


PREFIX = "GOVERNED_OUTPUT_BUNDLE="
MAX_FILES = 128
MAX_BYTES = 4_000_000


def build_bundle(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    files: list[dict[str, object]] = []
    total = 0
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            target = current_path / name
            if target.is_symlink() or not target.is_dir():
                raise ValueError(f"unsafe output directory: {target}")
        for name in names:
            target = current_path / name
            info = target.stat(follow_symlinks=False)
            if target.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError(f"unsafe output file: {target}")
            relative = target.relative_to(root).as_posix()
            if not relative or relative.startswith("/") or ".." in Path(relative).parts or "\\" in relative:
                raise ValueError(f"unsafe output path: {relative}")
            data = target.read_bytes()
            total += len(data)
            if len(files) >= MAX_FILES or total > MAX_BYTES:
                raise ValueError("candidate output exceeds the bounded exporter contract")
            files.append(
                {
                    "path": relative,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "base64": base64.b64encode(data).decode("ascii"),
                }
            )
    files.sort(key=lambda item: str(item["path"]))
    return {
        "schema_version": "blast-pit.candidate-output-bundle.v1",
        "file_count": len(files),
        "total_bytes": total,
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    driver = Path(options.driver).resolve(strict=True)
    cwd = Path.cwd().resolve(strict=True)
    if driver.parent != cwd or driver.name != "improvement_candidate_driver_v2.py" or not driver.is_file():
        raise ValueError("candidate exporter driver target is invalid")
    arguments = list(options.arguments)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    completed = subprocess.run([sys.executable, str(driver), *arguments], check=False)
    if completed.returncode != 0:
        return int(completed.returncode)
    bundle = build_bundle(Path("/output"))
    print(PREFIX + json.dumps(bundle, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
