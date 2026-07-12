import hashlib
import io
import json
import os
import sys
import threading
import time
from collections import deque
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
    assert manifest["schema_version"] == "codex-light-runner.manifest.v2"
    assert manifest["run_id"] == run_dir.name
    assert manifest["files"]
    for entry in manifest["files"]:
        data = (run_dir / entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    ledger_row = runner.verify_runner_record(cfg, run_dir.name, require_latest=True)
    assert ledger_row["status"] == "SUCCESS"
    terminal = json.loads((tmp_path / "evidence" / "latest" / "target_terminal.json").read_text())
    assert terminal["manifest_sha256"] == runner.sha256_file(run_dir / "sha256_manifest.json")
    assert terminal["ledger_hash"] == ledger_row["ledger_hash"]


def test_runner_seal_detects_log_manifest_and_ledger_tampering(tmp_path):
    cfg = config(tmp_path, "--minimal-env", "--no-codex-prompt")
    assert runner.run(cfg) == 0
    run_dir = next((tmp_path / "evidence" / "runs" / "target").iterdir())
    stdout = run_dir / "attempt_001" / "stdout.log"
    original_stdout = stdout.read_bytes()
    stdout.write_bytes(original_stdout + b"tampered\n")
    with pytest.raises(runner.RunnerError, match="manifest file set"):
        runner.verify_runner_record(cfg, run_dir.name, require_latest=True)
    stdout.write_bytes(original_stdout)
    ledger = tmp_path / "evidence" / "runner_ledger.jsonl"
    original_ledger = ledger.read_text(encoding="utf-8")
    row = json.loads(original_ledger)
    row["status"] = "FAILED"
    ledger.write_text(json.dumps(row, separators=(",", ":")) + "\n", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="ledger chain mismatch"):
        runner.verify_runner_record(cfg, run_dir.name, require_latest=True)
    ledger.write_text(original_ledger, encoding="utf-8")
    terminal_path = tmp_path / "evidence" / "latest" / "target_terminal.json"
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    terminal["status"] = "FAILED"
    terminal_path.write_text(json.dumps(terminal), encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="terminal pointer disagrees"):
        runner.verify_runner_record(cfg, run_dir.name, require_latest=True)


def test_allow_parallel_uses_distinct_runs_and_serialized_ledger(tmp_path):
    path = target(tmp_path, "import time\ntime.sleep(0.2)\nprint('done')\n")
    argv = ["--cwd", str(tmp_path), "--artifacts", str(tmp_path / "evidence"), "--python", sys.executable,
            "--no-preflight", "--no-codex-prompt", "--allow-parallel", str(path)]
    configs = [runner.make_config(argv), runner.make_config(argv)]
    assert all(item is not None for item in configs)
    results = []
    threads = [threading.Thread(target=lambda cfg=cfg: results.append(runner.run(cfg))) for cfg in configs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert not any(thread.is_alive() for thread in threads)
    assert sorted(results) == [0, 0]
    run_dirs = sorted((tmp_path / "evidence" / "runs" / "target").iterdir())
    assert len(run_dirs) == 2
    assert run_dirs[0].name != run_dirs[1].name
    cfg = configs[0]
    assert cfg is not None
    rows = runner.read_runner_ledger(cfg)
    assert [row["sequence"] for row in rows] == [1, 2]
    for run_dir in run_dirs:
        runner.verify_runner_record(cfg, run_dir.name)
    terminal = json.loads((tmp_path / "evidence" / "latest" / "target_terminal.json").read_text())
    legacy_state = json.loads((tmp_path / "evidence" / "latest" / "target_state.json").read_text())
    target_rows = [row for row in rows if row["runner_name"] == cfg.name and row["target"] == str(cfg.target)]
    assert terminal["record_id"] == target_rows[-1]["record_id"]
    assert legacy_state["run_id"] == terminal["run_id"]
    assert legacy_state["status"] == terminal["status"]


def test_runner_kernel_ledger_lock_serializes_waiters(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    runner.ensure_dirs(cfg, runner.run_id())
    monkeypatch.setattr(runner, "RUNNER_LEDGER_LOCK_TIMEOUT_SECONDS", 2.0)
    first = runner.acquire_runner_ledger_lock(cfg)
    acquired = []

    def wait_for_lock():
        lock = runner.acquire_runner_ledger_lock(cfg)
        acquired.append(time.monotonic())
        lock.close()

    thread = threading.Thread(target=wait_for_lock)
    thread.start()
    time.sleep(0.15)
    assert acquired == []
    first.close()
    thread.join(timeout=5)
    assert len(acquired) == 1
    assert (tmp_path / "evidence" / "runner_ledger.lock").is_file()


def test_duplicate_target_kernel_lock_is_busy_and_stale_metadata_is_harmless(tmp_path):
    cfg = config(tmp_path)
    first_run_dir = runner.ensure_dirs(cfg, runner.run_id())
    first = runner.acquire_lock(cfg, first_run_dir)
    assert first is not None
    with pytest.raises(runner.RunnerError, match="already active"):
        runner.acquire_lock(cfg, runner.ensure_dirs(cfg, runner.run_id()))
    first.close()
    second = runner.acquire_lock(cfg, runner.ensure_dirs(cfg, runner.run_id()))
    assert second is not None
    second.close()


def test_internal_failure_is_terminalized_and_ledgered(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")

    def fail_metadata(_config):
        raise runner.RunnerError("injected metadata failure")

    monkeypatch.setattr(runner, "execution_metadata", fail_metadata)
    with pytest.raises(runner.RunnerError, match="injected metadata failure"):
        runner.run(cfg)
    run_dir = next((tmp_path / "evidence" / "runs" / "target").iterdir())
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "FAILED"
    assert "injected metadata failure" in state["reason"]
    runner.verify_runner_record(cfg, run_dir.name, require_latest=True)


def test_failed_pointer_verification_restores_prior_pointer(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    assert runner.run(cfg) == 0
    pointer_path = tmp_path / "evidence" / "latest" / "target_terminal.json"
    prior = pointer_path.read_bytes()
    real_verify = runner.verify_runner_record

    def injected_failure(*args, **kwargs):
        raise runner.RunnerError("injected pointer verification failure")

    monkeypatch.setattr(runner, "verify_runner_record", injected_failure)
    with pytest.raises(runner.RunnerError, match="injected pointer verification failure"):
        runner.run(cfg)
    assert pointer_path.read_bytes() == prior
    monkeypatch.setattr(runner, "verify_runner_record", real_verify)
    with pytest.raises(runner.RunnerError, match="publication recovery is pending"):
        real_verify(cfg, json.loads(prior)["run_id"], require_latest=True)
    recovered = runner.recover_runner_publication(cfg)
    assert recovered is not None
    assert recovered["run_id"] != json.loads(prior)["run_id"]
    assert not (tmp_path / "evidence" / "runner_publication_wal.json").exists()
    real_verify(cfg, recovered["run_id"], require_latest=True)
    assert len(runner.read_runner_ledger(cfg)) == 2


def test_publication_wal_recovers_crash_before_ledger_append(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    real_complete = runner.complete_runner_publication_wal

    def crash_before_append(*args, **kwargs):
        raise runner.RunnerError("injected crash before ledger append")

    monkeypatch.setattr(runner, "complete_runner_publication_wal", crash_before_append)
    with pytest.raises(runner.RunnerError, match="injected crash before ledger append"):
        runner.run(cfg)
    wal_path = tmp_path / "evidence" / "runner_publication_wal.json"
    assert wal_path.is_file()
    assert not (tmp_path / "evidence" / "runner_ledger.jsonl").exists()
    monkeypatch.setattr(runner, "complete_runner_publication_wal", real_complete)
    other_target = tmp_path / "recovery-caller.py"
    other_target.write_text("print('recovery caller')\n", encoding="utf-8")
    recovery_caller = runner.make_config([
        "--cwd", str(tmp_path), "--artifacts", str(tmp_path / "evidence"), "--python", sys.executable,
        "--name", "recovery-caller", "--no-codex-prompt", str(other_target),
    ])
    assert recovery_caller is not None
    recovered = runner.recover_runner_publication(recovery_caller)
    assert recovered is not None
    assert not wal_path.exists()
    assert len(runner.read_runner_ledger(cfg)) == 1
    runner.verify_runner_record(cfg, recovered["run_id"], require_latest=True)


def test_publication_wal_recovers_crash_after_ledger_fsync(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    real_update = runner.update_runner_publication_wal

    def crash_after_ledger(config_value, wal, phase):
        updated = real_update(config_value, wal, phase)
        if phase == "LEDGER_ANCHORED":
            raise runner.RunnerError("injected crash after ledger fsync")
        return updated

    monkeypatch.setattr(runner, "update_runner_publication_wal", crash_after_ledger)
    with pytest.raises(runner.RunnerError, match="injected crash after ledger fsync"):
        runner.run(cfg)
    wal_path = tmp_path / "evidence" / "runner_publication_wal.json"
    assert json.loads(wal_path.read_text())["phase"] == "LEDGER_ANCHORED"
    assert len(runner.read_runner_ledger(cfg)) == 1
    monkeypatch.setattr(runner, "update_runner_publication_wal", real_update)
    recovered = runner.recover_runner_publication(cfg)
    assert recovered is not None
    assert len(runner.read_runner_ledger(cfg)) == 1
    runner.verify_runner_record(cfg, recovered["run_id"], require_latest=True)


def test_publication_wal_recovers_crash_after_pointer_write_before_phase_update(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    real_update = runner.update_runner_publication_wal

    def crash_before_pointer_phase(config_value, wal, phase):
        if phase == "POINTER_PUBLISHED":
            raise runner.RunnerError("injected crash after pointer write")
        return real_update(config_value, wal, phase)

    monkeypatch.setattr(runner, "update_runner_publication_wal", crash_before_pointer_phase)
    with pytest.raises(runner.RunnerError, match="injected crash after pointer write"):
        runner.run(cfg)
    wal_path = tmp_path / "evidence" / "runner_publication_wal.json"
    assert json.loads(wal_path.read_text())["phase"] == "LEDGER_ANCHORED"
    assert len(runner.read_runner_ledger(cfg)) == 1
    monkeypatch.setattr(runner, "update_runner_publication_wal", real_update)
    recovered = runner.recover_runner_publication(cfg)
    assert recovered is not None
    assert not wal_path.exists()
    assert len(runner.read_runner_ledger(cfg)) == 1
    runner.verify_runner_record(cfg, recovered["run_id"], require_latest=True)


def test_publication_wal_rejects_malformed_tampered_and_unsafe_inputs(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    real_complete = runner.complete_runner_publication_wal
    monkeypatch.setattr(
        runner,
        "complete_runner_publication_wal",
        lambda *args, **kwargs: (_ for _ in ()).throw(runner.RunnerError("retain WAL for tamper tests")),
    )
    with pytest.raises(runner.RunnerError, match="retain WAL"):
        runner.run(cfg)
    monkeypatch.setattr(runner, "complete_runner_publication_wal", real_complete)
    wal_path = tmp_path / "evidence" / "runner_publication_wal.json"
    original = wal_path.read_bytes()
    duplicate = original.rstrip()[:-1] + b',"phase":"BAD"}\n'
    wal_path.write_bytes(duplicate)
    with pytest.raises(runner.RunnerError, match="Duplicate JSON key"):
        runner.recover_runner_publication(cfg)
    value = json.loads(original)
    value["updated_at"] = float("nan")
    wal_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="Non-finite JSON constant"):
        runner.recover_runner_publication(cfg)
    value = json.loads(original)
    value["phase"] = "BAD"
    wal_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="phase is invalid"):
        runner.recover_runner_publication(cfg)
    value = json.loads(original)
    value["pointer"]["ledger_hash"] = "0" * 64
    wal_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="pointer binding is invalid"):
        runner.recover_runner_publication(cfg)
    wal_path.write_bytes(original)
    hardlink = tmp_path / "evidence" / "wal-hardlink.json"
    os.link(wal_path, hardlink)
    with pytest.raises(runner.RunnerError, match="Unsafe runner publication WAL"):
        runner.recover_runner_publication(cfg)
    hardlink.unlink()
    wal = json.loads(original)
    state_path = tmp_path / "evidence" / "runs" / "target" / wal["record"]["run_id"] / "state.json"
    state_original = state_path.read_bytes()
    state_path.write_bytes(state_original + b" ")
    with pytest.raises(runner.RunnerError, match="WAL hashes disagree"):
        runner.recover_runner_publication(cfg)
    state_path.write_bytes(state_original)
    recovered = runner.recover_runner_publication(cfg)
    assert recovered is not None
    runner.verify_runner_record(cfg, recovered["run_id"], require_latest=True)


def test_runner_name_binding_rejects_different_target_before_run_allocation(tmp_path):
    first = config(tmp_path, "--no-codex-prompt")
    assert runner.run(first) == 0
    other = tmp_path / "other.py"
    other.write_text("print('other')\n", encoding="utf-8")
    second = runner.make_config([
        "--cwd", str(tmp_path), "--artifacts", str(tmp_path / "evidence"), "--python", sys.executable,
        "--name", "target", "--no-codex-prompt", str(other),
    ])
    assert second is not None
    before = set((tmp_path / "evidence" / "runs" / "target").iterdir())
    with pytest.raises(runner.RunnerError, match="already bound to a different target"):
        runner.run(second)
    after = set((tmp_path / "evidence" / "runs" / "target").iterdir())
    assert after == before


def test_name_binding_ledger_rejects_tamper_removal_hardlink_and_case_collision(tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    assert runner.run(cfg) == 0
    path = tmp_path / "evidence" / "runner_name_binding_ledger.jsonl"
    original = path.read_bytes()
    forged = json.loads(original)
    forged["target"] = str(cfg.target.with_name("forged.py"))
    path.write_text(json.dumps(forged, separators=(",", ":")) + "\n", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="name-binding ledger chain"):
        runner.prepare_runner_publication(cfg)
    path.write_bytes(original)
    hardlink = tmp_path / "evidence" / "binding-hardlink.jsonl"
    os.link(path, hardlink)
    with pytest.raises(runner.RunnerError, match="Unsafe runner name-binding ledger"):
        runner.prepare_runner_publication(cfg)
    hardlink.unlink()
    path.unlink()
    with pytest.raises(runner.RunnerError, match="disagrees with terminal evidence history"):
        runner.prepare_runner_publication(cfg)
    path.write_bytes(original)
    case_variant = runner.make_config([
        "--cwd", str(tmp_path), "--artifacts", str(tmp_path / "evidence"), "--python", sys.executable,
        "--name", "Target", "--no-codex-prompt", str(cfg.target),
    ])
    assert case_variant is not None
    with pytest.raises(runner.RunnerError, match="already bound to a different target"):
        runner.run(case_variant)


def test_interrupt_after_seal_does_not_rewrite_terminal_status(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    real_finalize = runner.finalize_runner_state
    calls = 0

    def interrupt_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = real_finalize(*args, **kwargs)
        if calls == 1:
            raise KeyboardInterrupt()
        return result

    monkeypatch.setattr(runner, "finalize_runner_state", interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        runner.run(cfg)
    run_dir = next((tmp_path / "evidence" / "runs" / "target").iterdir())
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "SUCCESS"
    runner.verify_runner_record(cfg, run_dir.name, require_latest=True)


def test_runner_verification_rejects_tmp_hardlink_empty_dir_and_bad_selector(tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    assert runner.run(cfg) == 0
    run_dir = next((tmp_path / "evidence" / "runs" / "target").iterdir())
    temporary = run_dir / "secret.tmp"
    temporary.write_text("not sealed", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="unfinished temporary"):
        runner.verify_runner_record(cfg, run_dir.name)
    temporary.unlink()
    hardlink = run_dir / "state-hardlink.json"
    os.link(run_dir / "state.json", hardlink)
    with pytest.raises(runner.RunnerError, match="Unsafe runner"):
        runner.verify_runner_record(cfg, run_dir.name)
    hardlink.unlink()
    empty = run_dir / "unsealed-empty-directory"
    empty.mkdir()
    with pytest.raises(runner.RunnerError, match="manifest file set"):
        runner.verify_runner_record(cfg, run_dir.name)
    empty.rmdir()
    for selector in ("../outside", "C:/outside", "name:stream", "bad\\path"):
        with pytest.raises(runner.RunnerError, match="one safe run ID"):
            runner.verify_runner_record(cfg, selector)


def test_runner_ledger_strict_json_and_size_bounds(monkeypatch, tmp_path):
    cfg = config(tmp_path, "--no-codex-prompt")
    assert runner.run(cfg) == 0
    ledger = tmp_path / "evidence" / "runner_ledger.jsonl"
    original = ledger.read_text(encoding="utf-8")
    duplicate = original.rstrip("\n")[:-1] + ',"status":"FAILED"}\n'
    ledger.write_text(duplicate, encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="duplicate key"):
        runner.read_runner_ledger(cfg)
    ledger.write_text(original.replace('"sequence":1', '"sequence":NaN'), encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="Non-finite JSON constant"):
        runner.read_runner_ledger(cfg)
    ledger.write_text(original, encoding="utf-8")
    monkeypatch.setattr(runner, "MAX_RUNNER_LEDGER_BYTES", 10)
    with pytest.raises(runner.RunnerError, match="exceeds its size limit"):
        runner.read_runner_ledger(cfg)


def test_latest_state_is_visible_while_target_is_running(tmp_path):
    path=target(tmp_path,"import time\ntime.sleep(1)\n")
    cfg=runner.make_config(["--cwd",str(tmp_path),"--artifacts",str(tmp_path/"evidence"),"--python",sys.executable,"--no-preflight",str(path)])
    assert cfg is not None
    result=[]; thread=threading.Thread(target=lambda:result.append(runner.run(cfg))); thread.start()
    latest=tmp_path/"evidence"/"latest"/"target_state.json"; observed=None
    deadline=time.monotonic()+2
    while time.monotonic()<deadline and observed is None:
        if latest.is_file():
            candidate=json.loads(latest.read_text())
            if candidate.get("status")=="RUNNING": observed=candidate
        time.sleep(.02)
    thread.join(timeout=10)
    assert observed is not None; assert observed["artifacts_dir"]
    assert result==[0]


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


def test_stream_reader_survives_console_encoding_mismatch(monkeypatch, tmp_path):
    console_bytes=io.BytesIO(); console=io.TextIOWrapper(console_bytes,encoding="cp1252",errors="strict")
    monkeypatch.setattr(runner.sys,"stdout",console)
    runner.stream_reader(io.BytesIO("unicode: Ω\n".encode()),tmp_path/"stdout.log",tmp_path/"combined.log","stdout",
                         deque(maxlen=10),runner.ActivityClock(),runner.threading.Lock(),False)
    console.flush()
    assert b"unicode:" in console_bytes.getvalue()
    assert (tmp_path/"stdout.log").read_bytes()=="unicode: Ω\n".encode()
