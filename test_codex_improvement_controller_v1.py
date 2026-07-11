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
        dry_run=False,
    )


def test_metric_gate_allows_process_non_regression():
    baseline = {"cvar": 0.5, "mean": 0.6, "early_extinction_rate": 0.1}
    candidate = {"cvar": 0.495, "mean": 0.598, "early_extinction_rate": 0.1}
    assert controller.metric_gate("process", baseline, candidate) == (True, [])


def test_metric_gate_requires_algorithm_improvement():
    baseline = {"cvar": 0.5, "mean": 0.6, "early_extinction_rate": 0.1}
    candidate = {"cvar": 0.501, "mean": 0.601, "early_extinction_rate": 0.1}
    passed, reasons = controller.metric_gate("algorithm", baseline, candidate)
    assert not passed
    assert "lacks required" in reasons[0]


def test_metric_gate_rejects_extinction_regression():
    baseline = {"cvar": 0.5, "mean": 0.6, "early_extinction_rate": 0.1}
    candidate = {"cvar": 0.6, "mean": 0.7, "early_extinction_rate": 0.13}
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
    (repo / "tmp_2d_simulator_v37.py").write_text("VALUE = 2\n", encoding="utf-8")
    evidence = tmp_path / "cycle"
    evidence.mkdir()
    passed, reasons, diff = controller.security_gate(config(repo, tmp_path), repo, evidence)
    assert passed and not reasons and "VALUE = 2" in diff
    packet = json.loads((evidence / "security_gate.json").read_text())
    assert packet["pass"] is True


def test_security_gate_rejects_file_outside_allowlist(tmp_path):
    repo = fixture_repo(tmp_path)
    (repo / "unexpected.py").write_text("x = 1\n", encoding="utf-8")
    evidence = tmp_path / "cycle"
    evidence.mkdir()
    passed, reasons, _ = controller.security_gate(config(repo, tmp_path), repo, evidence)
    assert not passed
    assert any("outside allowlist" in reason for reason in reasons)


def test_security_gate_rejects_network_import(tmp_path):
    repo = fixture_repo(tmp_path)
    (repo / "tmp_2d_simulator_v37.py").write_text("import socket\n", encoding="utf-8")
    evidence = tmp_path / "cycle"
    evidence.mkdir()
    passed, reasons, _ = controller.security_gate(config(repo, tmp_path), repo, evidence)
    assert not passed
    assert any("forbidden" in reason for reason in reasons)


def test_prompt_contains_production_evidence_and_constraints():
    prompt = controller.prompt_for_cycle({"cvar": 0.5}, {"generation": 99, "challenge_cvar": 0.6, "workflow_state": "TRAINING_COMPLETE", "hof_policy_hash": "abc"}, 1)
    assert "completed generations: 100" in prompt
    assert "Modify only" in prompt
    assert "terminal audit" in prompt


def test_atomic_json_replaces_complete_document(tmp_path):
    path = tmp_path / "state.json"
    controller.atomic_json(path, {"status": "ONE"})
    controller.atomic_json(path, {"status": "TWO"})
    assert json.loads(path.read_text()) == {"status": "TWO"}
    assert not list(tmp_path.glob("*.tmp"))


def test_schema_requires_governed_fields():
    schema = json.loads((Path(__file__).parent / "schemas" / "codex_improvement_result.schema.json").read_text())
    assert set(schema["required"]) == {"category", "hypothesis", "summary", "changed_files", "tests_run", "risks"}
    assert schema["additionalProperties"] is False
