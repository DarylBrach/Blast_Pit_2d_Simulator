from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent
GUARD = REPO / "improvement_candidate_guard.py"


def run_guard(root: Path, script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    return subprocess.run(
        [sys.executable, GUARD, "--root", root, "--script", script, "--target-sha256", digest, "--", *arguments],
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def test_guard_denies_socket_and_subprocess_audit_events(tmp_path):
    network = tmp_path / "network_probe.py"
    network.write_text(
        "import socket\ntry:\n socket.socket()\nexcept PermissionError as exc:\n print('NETWORK_DENIED', exc)\nelse:\n raise SystemExit(9)\n",
        encoding="utf-8",
    )
    result = run_guard(tmp_path, network)
    assert result.returncode == 0 and "NETWORK_DENIED" in result.stdout

    process = tmp_path / "process_probe.py"
    process.write_text(
        "import subprocess,sys\ntry:\n subprocess.run([sys.executable, '-c', 'pass'])\nexcept PermissionError as exc:\n print('PROCESS_DENIED', exc)\nelse:\n raise SystemExit(9)\n",
        encoding="utf-8",
    )
    result = run_guard(tmp_path, process)
    assert result.returncode == 0 and "PROCESS_DENIED" in result.stdout


def test_guard_denies_reads_and_writes_outside_candidate_root(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    outside = tmp_path / "outside.txt"; outside.write_text("secret", encoding="utf-8")
    probe = root / "file_probe.py"
    probe.write_text(
        "import pathlib,sys\nfor mode in ('r','w'):\n"
        " try:\n  open(sys.argv[1], mode).close()\n"
        " except PermissionError as exc:\n  print(mode.upper() + '_DENIED', exc)\n"
        " else:\n  raise SystemExit(9)\n",
        encoding="utf-8",
    )
    result = run_guard(root, probe, str(outside))
    assert result.returncode == 0 and "R_DENIED" in result.stdout and "W_DENIED" in result.stdout
    assert outside.read_text(encoding="utf-8") == "secret"


def test_guard_denies_delete_rename_link_and_mkdir_outside_root(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    outside = tmp_path / "outside.txt"; outside.write_text("preserve", encoding="utf-8")
    probe = root / "mutation_probe.py"
    probe.write_text(
        "import os,sys\n"
        "ops=[lambda:os.remove(sys.argv[1]),lambda:os.rename(sys.argv[1],sys.argv[1]+'.moved'),"
        "lambda:os.link(sys.argv[1],sys.argv[2]),lambda:os.mkdir(sys.argv[1]+'.dir')]\n"
        "for index,op in enumerate(ops):\n"
        " try: op()\n except PermissionError as exc: print('DENIED',index,exc)\n else: raise SystemExit(9)\n",
        encoding="utf-8",
    )
    result = run_guard(root, probe, str(outside), str(root / "linked.txt"))
    assert result.returncode == 0 and result.stdout.count("DENIED") == 4
    assert outside.read_text(encoding="utf-8") == "preserve" and not (root / "linked.txt").exists()


def test_guard_rejects_hash_drift_and_script_outside_root(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    script = root / "target.py"; script.write_text("print('ok')\n", encoding="utf-8")
    command = [sys.executable, GUARD, "--root", root, "--script", script, "--target-sha256", "0" * 64]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    assert result.returncode == 2 and "hash changed" in result.stderr
    outside = tmp_path / "outside.py"; outside.write_text("print('bad')\n", encoding="utf-8")
    result = run_guard(root, outside)
    assert result.returncode == 2 and "outside" in result.stderr


def test_guarded_pytest_module_remains_usable(tmp_path):
    (tmp_path / "test_sample.py").write_text("def test_sample():\n    assert 2 + 2 == 4\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, GUARD, "--root", tmp_path, "--module", "pytest", "--", "-q"],
        cwd=tmp_path,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
