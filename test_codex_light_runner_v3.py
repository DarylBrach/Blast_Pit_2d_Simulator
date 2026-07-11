import hashlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

import CodexLightRunner_v3 as runner


def target(tmp_path: Path, source: str = "print('ok')\n") -> Path:
    path = tmp_path / "target.py"
    path.write_text(source, encoding="utf-8")
    return path


def config(tmp_path: Path, *extra: str) -> runner.RunnerConfig:
    path = target(tmp_path)
    argv = ["--cwd", str(tmp_path), "--artifacts", str(tmp_path / "evidence"),
            "--python", sys.executable, *extra, str(path)]
    result = runner.make_config(argv)
    assert result is not None
    return result


def test_ollama_is_explicit_opt_in(tmp_path):
    assert config(tmp_path).ollama_enabled is False
    assert config(tmp_path, "--ollama").ollama_enabled is True


def test_minimal_environment_excludes_secret_and_allows_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("TEST_SECRET_TOKEN", "must-not-leak")
    cfg = config(tmp_path, "--minimal-env", "--env", "SAFE_VALUE=yes")
    env = runner.build_env(cfg)
    assert "TEST_SECRET_TOKEN" not in env
    assert env["SAFE_VALUE"] == "yes"


@pytest.mark.parametrize("name", ["../stop", "sub/stop"])
def test_kill_switch_must_be_scoped_filename(tmp_path, name):
    path = target(tmp_path)
    with pytest.raises(runner.RunnerError, match="one simple filename"):
        runner.make_config(["--cwd", str(tmp_path), "--kill-switch", name, str(path)])


def test_external_target_rejected_by_default(tmp_path):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    path = target(tmp_path)
    with pytest.raises(runner.RunnerError, match="within working directory"):
        runner.make_config(["--cwd", str(cwd), str(path)])


def test_redaction_handles_equals_and_next_argument():
    assert runner.redact(["--api-key=abc", "--password", "xyz", "normal"]) == [
        "--api-key=<redacted>", "--password", "<redacted>", "normal"
    ]


def test_atomic_json_leaves_no_temp(tmp_path):
    path = tmp_path / "state.json"
    runner.write_json(path, {"ok": True})
    assert json.loads(path.read_text()) == {"ok": True}
    assert not list(tmp_path.glob("*.tmp"))


def test_stale_kill_switch_fails_before_target_launch(tmp_path):
    cfg = config(tmp_path)
    cfg.kill_switch_path.write_text("stop", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="Stale kill switch"):
        runner.run(cfg)
    assert not list((tmp_path / "evidence").rglob("attempt_*"))


def test_run_writes_metadata_atomic_state_and_verifiable_manifest(tmp_path):
    cfg = config(tmp_path, "--minimal-env", "--no-codex-prompt")
    assert runner.run(cfg) == 0
    run_dirs = [p for p in (tmp_path / "evidence" / "runs" / "target").iterdir() if p.is_dir()]
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    effective = json.loads((run_dir / "effective_command.json").read_text())
    assert effective["execution_metadata"]["files"]["target"]["sha256"] == runner.sha256_file(cfg.target)
    assert effective["execution_metadata"]["environment_policy"] == "minimal"
    assert not (run_dir / "running_state.json").exists()
    manifest = json.loads((run_dir / "sha256_manifest.json").read_text())
    assert manifest["files"]
    for entry in manifest["files"]:
        data = (run_dir / entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]


def test_keyboard_interrupt_terminates_child_tree(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-preflight")

    class FakeProcess:
        pid = 12345
        returncode = None
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(b"")

        def poll(self):
            return None

    fake = FakeProcess()
    terminated = []
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: fake)
    monkeypatch.setattr(runner, "terminate_process_tree", lambda proc, grace_seconds=8: terminated.append(proc))
    monkeypatch.setattr(runner.time, "sleep", lambda seconds: (_ for _ in ()).throw(KeyboardInterrupt()))
    run_dir = tmp_path / "manual-run"
    run_dir.mkdir()
    with pytest.raises(KeyboardInterrupt):
        runner.run_target_once(cfg, run_dir, 1)
    assert terminated == [fake]
