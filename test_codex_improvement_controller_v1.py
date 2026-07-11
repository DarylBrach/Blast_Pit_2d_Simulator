from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import CodexImprovementController_v1 as controller


def run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    run_git(repo, "config", "user.email", "tests@example.invalid")
    run_git(repo, "config", "user.name", "Tests")
    (repo / "tmp_2d_simulator_v37.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "test_tmp_2d_simulator_v37.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "fixture")
    return repo


def config(repo: Path, tmp_path: Path) -> controller.ControllerConfig:
    return controller.ControllerConfig(
        repo=repo,
        python=Path(sys.executable),
        codex=Path(sys.executable),
        artifact_root=tmp_path / "evidence",
        worktree_root=tmp_path / "worktrees",
        model="gpt-5.5",
        cycles=1,
        codex_timeout_seconds=60,
        test_timeout_seconds=60,
        evaluation_timeout_seconds=60,
        max_diff_bytes=10_000,
        max_runtime_seconds=28_800,
        authorization=repo / "approval_codex_improvement_v1.json",
        dry_run=False,
    )


def test_metric_gate_allows_process_non_regression():
    baseline = {"cvar": 0.5, "mean": 0.6, "standard_mean": 0.7, "early_extinction_rate": 0.1}
    candidate = {"cvar": 0.495, "mean": 0.598, "standard_mean": 0.7, "early_extinction_rate": 0.1}
    assert controller.metric_gate("process", baseline, candidate) == (True, [])


def test_metric_gate_requires_algorithm_improvement():
    baseline = {"cvar": 0.5, "mean": 0.6, "standard_mean": 0.7, "early_extinction_rate": 0.1}
    candidate = {"cvar": 0.501, "mean": 0.601, "standard_mean": 0.7, "early_extinction_rate": 0.1}
    passed, reasons = controller.metric_gate("algorithm", baseline, candidate)
    assert not passed
    assert "lacks required" in reasons[0]


def test_metric_gate_rejects_extinction_regression():
    baseline = {"cvar": 0.5, "mean": 0.6, "standard_mean": 0.7, "early_extinction_rate": 0.1}
    candidate = {"cvar": 0.6, "mean": 0.7, "standard_mean": 0.7, "early_extinction_rate": 0.13}
    passed, reasons = controller.metric_gate("process", baseline, candidate)
    assert not passed
    assert any("extinction" in reason for reason in reasons)


def test_clean_repo_rejects_dirty_tree(tmp_path):
    repo = fixture_repo(tmp_path)
    (repo / "tmp_2d_simulator_v37.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(controller.ImprovementError, match="must be clean"):
        controller.clean_repo(config(repo, tmp_path))


def test_security_gate_accepts_allowlisted_change(tmp_path):
    repo = fixture_repo(tmp_path)
    evidence = tmp_path / "cycle"
    evidence.mkdir()
    controller.worktree_snapshot(repo,evidence)
    (repo / "tmp_2d_simulator_v37.py").write_text("VALUE = 2\n", encoding="utf-8")
    passed, reasons, diff = controller.security_gate(config(repo, tmp_path), repo, evidence)
    assert passed and not reasons and "VALUE = 2" in diff
    packet = json.loads((evidence / "security_gate.json").read_text())
    assert packet["pass"] is True


def test_security_gate_rejects_file_outside_allowlist(tmp_path):
    repo = fixture_repo(tmp_path)
    evidence = tmp_path / "cycle"
    evidence.mkdir()
    controller.worktree_snapshot(repo,evidence)
    (repo / "unexpected.py").write_text("x = 1\n", encoding="utf-8")
    passed, reasons, _ = controller.security_gate(config(repo, tmp_path), repo, evidence)
    assert not passed
    assert any("outside allowlist" in reason for reason in reasons)


def test_security_gate_rejects_network_import(tmp_path):
    repo = fixture_repo(tmp_path)
    evidence = tmp_path / "cycle"
    evidence.mkdir()
    controller.worktree_snapshot(repo,evidence)
    (repo / "tmp_2d_simulator_v37.py").write_text("import socket\n", encoding="utf-8")
    passed, reasons, _ = controller.security_gate(config(repo, tmp_path), repo, evidence)
    assert not passed
    assert any("forbidden" in reason for reason in reasons)


def test_prompt_contains_production_evidence_and_constraints():
    prompt = controller.prompt_for_cycle({"cvar": 0.5}, {"generation": 99, "challenge_cvar": 0.6, "workflow_state": "TRAINING_COMPLETE", "hof_policy_hash": "abc"}, 1)
    assert "completed generations: 100" in prompt
    assert "Modify only" in prompt
    assert "terminal audit" in prompt


def test_prompt_carries_rejection_lessons():
    prior={"cycle":1,"status":"REJECTED","codex_decision":{"hypothesis":"mutate all actors","summary":"left temp evidence","risks":["mean declined"]},"reasons":["mean regression"],"candidate_score":{"mean":.4}}
    prompt=controller.prompt_for_cycle({"cvar":.5},{"generation":99,"challenge_cvar":.6,"workflow_state":"TRAINING_COMPLETE","hof_policy_hash":"abc"},2,[prior])
    assert "mutate all actors" in prompt
    assert "mean regression" in prompt
    assert "left temp evidence" in prompt and "mean declined" in prompt
    assert "do not repeat" in prompt


def test_prompt_with_six_large_lessons_fits_windows_cmd_limit():
    prior=[{"status":"REJECTED","codex_decision":{"hypothesis":"h"*1000,"summary":"s"*2000,"risks":["r"*1000]},"reasons":["g"*5000],"candidate_score":{"cvar":.5,"mean":.6,"checkpoint":"x"*5000}} for _ in range(6)]
    prompt=controller.prompt_for_cycle({"cvar":.5,"mean":.6,"standard_mean":.7,"challenge_mean":.4,"early_extinction_rate":.1,"checkpoint":"x"*5000},{"generation":99,"challenge_cvar":.6,"workflow_state":"TRAINING_COMPLETE","hof_policy_hash":"abc"},2,prior)
    assert len(prompt)<6500
    assert "x"*100 not in prompt


def test_prompt_bounds_combined_cross_run_and_same_run_history():
    prior=[{"status":"REJECTED","codex_decision":{"hypothesis":f"lesson-{index}-"+"h"*1000,"summary":"s"*2000,"risks":["r"*1000]},"reasons":["g"*5000],"candidate_score":{"cvar":.5,"mean":.6}} for index in range(16)]
    prompt=controller.prompt_for_cycle({"cvar":.5,"mean":.6,"standard_mean":.7,"challenge_mean":.4,"early_extinction_rate":.1},{"generation":99,"challenge_cvar":.6,"workflow_state":"TRAINING_COMPLETE","hof_policy_hash":"abc"},10,prior)
    assert len(prompt)<6500
    assert "lesson-10-" in prompt and "lesson-15-" in prompt
    assert "lesson-9-" not in prompt


def test_historical_lessons_span_completed_runs(tmp_path):
    for name,hypothesis in (("20260711T010000Z","older accepted"),("20260711T020000Z","newer rejected")):
        run=tmp_path/name; run.mkdir()
        (run/"state.json").write_text(json.dumps({"cycles":[{"cycle":1,"codex_decision":{"hypothesis":hypothesis}}]}))
    lessons=controller.historical_lessons(tmp_path)
    assert [row["codex_decision"]["hypothesis"] for row in lessons]==["older accepted","newer rejected"]


def test_metric_gate_checks_standard_profile_regression():
    baseline={"cvar":.5,"mean":.6,"standard_mean":.7,"early_extinction_rate":.1}
    candidate={"cvar":.6,"mean":.6,"standard_mean":.65,"early_extinction_rate":.1}
    passed,reasons=controller.metric_gate("process",baseline,candidate)
    assert not passed and any("standard-profile" in reason for reason in reasons)


def test_atomic_json_replaces_complete_document(tmp_path):
    path = tmp_path / "state.json"
    controller.atomic_json(path, {"status": "ONE"})
    controller.atomic_json(path, {"status": "TWO"})
    assert json.loads(path.read_text()) == {"status": "TWO"}
    assert not list(tmp_path.glob("*.tmp"))


def test_canonical_authorization_hash_ignores_line_endings(tmp_path):
    lf=tmp_path/"lf.txt"; crlf=tmp_path/"crlf.txt"
    lf.write_bytes(b"one\ntwo\n"); crlf.write_bytes(b"one\r\ntwo\r\n")
    assert controller.canonical_text_sha256(lf)==controller.canonical_text_sha256(crlf)


def test_schema_requires_governed_fields():
    schema = json.loads((Path(__file__).parent / "schemas" / "codex_improvement_result.schema.json").read_text())
    assert set(schema["required"]) == {"category", "hypothesis", "summary", "changed_files", "tests_run", "risks"}
    assert schema["additionalProperties"] is False


def test_streamed_command_persists_live_output(tmp_path, capsys):
    result=controller.streamed_command([sys.executable,"-c","print('event-one'); print('event-two')"],tmp_path,30,tmp_path/"events.jsonl",tmp_path/"stderr.log")
    assert result.return_code==0
    assert (tmp_path/"events.jsonl").read_text().splitlines()==["event-one","event-two"]
    assert "event-one" in capsys.readouterr().out


def test_streamed_command_redacts_secret_from_evidence(tmp_path, capsys):
    secret="do-not-retain-this-secret"
    result=controller.streamed_command(
        [sys.executable,"-c",f"print('{secret}')"],tmp_path,30,tmp_path/"events.jsonl",tmp_path/"stderr.log",redactions=[secret]
    )
    assert result.return_code==0
    assert secret not in result.stdout
    assert secret not in (tmp_path/"events.jsonl").read_text()
    assert "<redacted>" in capsys.readouterr().out


def test_codex_environment_is_minimal_and_identifies_redactions(monkeypatch):
    monkeypatch.setenv("UNRELATED_PRIVATE_VALUE","not-for-codex")
    monkeypatch.setenv("OPENAI_API_KEY","test-key-value")
    env,secrets=controller.codex_environment()
    assert "UNRELATED_PRIVATE_VALUE" not in env
    assert env["OPENAI_API_KEY"]=="test-key-value"
    assert secrets==["test-key-value"]


def test_filesystem_gate_rejects_raw_change_outside_allowlist(tmp_path):
    worktree=tmp_path/"worktree"; worktree.mkdir()
    (worktree/"tmp_2d_simulator_v37.py").write_text("VALUE=1\n")
    cycle=tmp_path/"cycle"; cycle.mkdir()
    controller.worktree_snapshot(worktree,cycle)
    (worktree/"README.md").write_text("unexpected\n")
    passed,reasons=controller.filesystem_gate(worktree,cycle)
    assert not passed
    assert any("outside allowlist" in reason for reason in reasons)


def test_evidence_manifest_seals_run_files(tmp_path):
    (tmp_path/"state.json").write_text('{"status":"COMPLETE"}\n')
    state={"run_id":"test-run","base_commit":"abc","status":"COMPLETE"}
    digest=controller.seal_evidence(tmp_path,state)
    manifest=json.loads((tmp_path/"evidence_manifest.json").read_text())
    assert len(digest)==64
    assert "state.json" in manifest["files"]
    assert "evidence_manifest.json" not in manifest["files"]


def test_codex_cycle_pins_windows_sandbox_and_model(monkeypatch,tmp_path):
    repo=fixture_repo(tmp_path); (repo/"schemas").mkdir(); (repo/"schemas"/"codex_improvement_result.schema.json").write_text("{}")
    cycle=tmp_path/"cycle"; cycle.mkdir(); captured={}
    def fake(args,cwd,timeout,stdout_path,stderr_path,env=None,redactions=()):
        captured["args"]=[str(value) for value in args]
        (cycle/"codex_final.json").write_text(json.dumps({"category":"no_change","hypothesis":"none","summary":"none","changed_files":[],"tests_run":[],"risks":[]}))
        return controller.CommandResult(captured["args"],str(cwd),0,"","")
    monkeypatch.setattr(controller,"streamed_command",fake)
    controller.codex_cycle(config(repo,tmp_path),repo,cycle,"prompt")
    joined=" ".join(captured["args"])
    assert "gpt-5.5" in joined
    assert 'windows.sandbox="elevated"' in joined
    assert 'approval_policy="never"' in joined
