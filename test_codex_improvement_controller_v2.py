from __future__ import annotations

import json
import hashlib
import contextlib
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

import CodexImprovementController_v2 as v2


REPO = Path(v2.__file__).resolve().parent


def config(repo: Path = REPO) -> v2.Config:
    return v2.Config(
        repo=repo,
        python=Path(sys.executable),
        codex=repo / "codex.cmd",
        docker=Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
        authorization=repo / "approval_codex_improvement_v2.json",
        artifact_root=repo.parent / "evidence-test",
        worktree_root=repo.parent / "worktree-test",
        evaluator=repo / "improvement_score_checkpoint_v2.py",
        real_codex_home=repo.parent / "codex-home-test",
        model=v2.MODEL_DEFAULT,
        cycles=1,
        max_runtime_seconds=3600,
        role_timeout_seconds=600,
        command_timeout_seconds=300,
        evaluation_timeout_seconds=600,
        remediation_cap=2,
        max_parallel_specialists=3,
        max_diff_bytes=120_000,
        sandbox_implementation="unelevated",
        dry_run=False,
        resume_run=None,
    )


def passing_review(role: str, diff_sha256: str = "a" * 64) -> dict[str, object]:
    return {
        "schema_version": "codex.specialist-review.v2",
        "role": role,
        "diff_sha256": diff_sha256,
        "verdict": "PASS",
        "criteria": [{"id": item, "pass": True, "evidence": "verified retained evidence"} for item in v2.CRITERIA[role]],
        "findings": [],
        "assumptions": [],
    }


def passing_final_qa(diff_sha256: str = "a" * 64) -> dict[str, object]:
    return {
        "schema_version": "codex.final-qa.v2",
        "diff_sha256": diff_sha256,
        "verdict": "PASS",
        "criteria": [{"id": item, "pass": True, "evidence": "verified retained evidence"} for item in v2.FINAL_QA_CRITERIA],
        "finding_dispositions": [],
        "blockers": [],
        "warnings": [],
        "recommendation": "Ready for human review only.",
    }


def valid_build(patch: str = "") -> dict[str, object]:
    changed = bool(patch)
    return {
        "schema_version": "codex.build-result.v2",
        "category": "algorithm" if changed else "no_change",
        "hypothesis": "A bounded deterministic improvement.",
        "summary": "One candidate-only change.",
        "patch": patch,
        "changed_files": ["test_tmp_2d_simulator_v37.py", "tmp_2d_simulator_v37.py"] if changed else [],
        "focused_tests": ["focused v37 tests"],
        "risks": ["candidate may not improve held-out metrics"],
        "documentation_recommendations": ["record the candidate result"],
        "behavior_changed": changed,
        "authority_impact": "none",
        "artifact_impact": "new_lineage_required" if changed else "none",
        "external_writes": [],
        "finding_ids_addressed": [],
    }


def test_transition_journal_is_hash_chained_projected_and_tamper_evident(tmp_path):
    journal = v2.Journal(tmp_path)
    first = journal.add("ONE")
    second = journal.add("TWO")
    state = json.loads((tmp_path / "state.json").read_text())
    assert second["previous_transition_hash"] == first["transition_hash"]
    assert state["last_transition_hash"] == second["transition_hash"]
    assert v2.Journal(tmp_path).last_state == "TWO"

    rows = (tmp_path / "transitions.jsonl").read_text().splitlines()
    row = json.loads(rows[0])
    row["state"] = "ALTERED"
    rows[0] = v2.canonical(row)
    (tmp_path / "transitions.jsonl").write_text("\n".join(rows) + "\n")
    with pytest.raises(v2.V2Error, match="chain"):
        v2.Journal(tmp_path)


def test_terminal_journal_is_immutable(tmp_path):
    journal = v2.Journal(tmp_path)
    journal.add("COMPLETE")
    with pytest.raises(v2.V2Error, match="immutable"):
        journal.add("AFTER_COMPLETE")


def test_category_forces_any_simulator_change_to_algorithm():
    assert v2.category_for_diff("diff --git a/tmp_2d_simulator_v37.py b/tmp_2d_simulator_v37.py") == "algorithm"
    assert v2.category_for_diff("diff --git a/test_tmp_2d_simulator_v37.py b/test_tmp_2d_simulator_v37.py") == "process"


def test_exact_role_criteria_and_finding_prefix_are_enforced():
    cfg = config()
    row = passing_review("architecture_state")
    v2.verify_review(cfg, row, "architecture_state", "a" * 64)
    row["criteria"].reverse()
    with pytest.raises(v2.V2Error, match="criteria"):
        v2.verify_review(cfg, row, "architecture_state", "a" * 64)

    row = passing_review("architecture_state")
    row["verdict"] = "CHANGES_REQUIRED"
    row["criteria"][0]["pass"] = False
    row["findings"] = [{
        "id": "SEC-001", "severity": "HIGH", "category": "security", "file": None, "line": None,
        "evidence": "verified evidence", "impact": "bounded impact", "remediation": "fix it", "test": "test it",
    }]
    with pytest.raises(v2.V2Error, match="finding ID"):
        v2.verify_review(cfg, row, "architecture_state", "a" * 64)


def test_adjudication_requires_complete_panel_and_is_deterministic():
    reviews = [passing_review(role) for role in v2.ROLES]
    assert v2.adjudicate(reviews)["verdict"] == "PASS"
    reviews[4]["verdict"] = "CHANGES_REQUIRED"
    reviews[4]["criteria"][0]["pass"] = False
    reviews[4]["findings"] = [{
        "id": "SEC-001", "severity": "HIGH", "category": "security", "file": None, "line": None,
        "evidence": "verified evidence", "impact": "bounded impact", "remediation": "fix it", "test": "test it",
    }]
    assert v2.adjudicate(reviews)["mandatory_finding_ids"] == ["SEC-001"]
    with pytest.raises(v2.V2Error, match="incomplete"):
        v2.adjudicate(reviews[:-1])


def test_final_qa_requires_exact_order_and_resolved_findings():
    cfg = config()
    row = passing_final_qa()
    v2.verify_final_qa(cfg, row, "a" * 64, [])
    row["finding_dispositions"] = [{"finding_id": "SEC-001", "status": "UNRESOLVED", "evidence": "still open"}]
    with pytest.raises(v2.V2Error, match="unresolved"):
        v2.verify_final_qa(cfg, row, "a" * 64, ["SEC-001"])


def test_rubric_has_no_unsupported_tens_and_requires_every_core_gate():
    reviews = [passing_review(role) for role in v2.ROLES]
    gates = {name: True for name in v2.CORE_GATES}
    evaluation = {"pass": True}
    qa = passing_final_qa()
    result = v2.rubric(reviews, gates, evaluation, qa)
    assert result["total"] == 100 and result["ten_out_of_ten"] is True
    gates["sandbox_canary"] = False
    result = v2.rubric(reviews, gates, evaluation, qa)
    assert result["total"] < 100 and next(item for item in result["items"] if item["id"] == "security")["score"] == 0
    assert v2.rubric(reviews, {"security": True}, evaluation, qa)["total"] < 100


def score(values: list[float], fold: str = "f") -> dict[str, object]:
    mean = sum(values) / len(values)
    return {
        "fold_sha256": fold,
        "fitness_values": values,
        "cvar": mean,
        "mean": mean,
        "standard_mean": mean,
        "challenge_mean": mean,
        "early_extinction_rate": 0.0,
    }


def test_paired_metric_gate_requires_matching_fold_nonregression_and_lcb():
    base = score([1.0] * 8)
    assert not v2.paired_metric_gate(base, score([1.0] * 8), "algorithm")["pass"]
    assert v2.paired_metric_gate(base, score([1.1] * 8), "algorithm")["pass"]
    with pytest.raises(v2.V2Error, match="pairing"):
        v2.paired_metric_gate(base, score([1.1] * 8, "other"), "algorithm")
    regressed = score([1.1] * 8)
    regressed["early_extinction_rate"] = 0.5
    assert not v2.paired_metric_gate(base, regressed, "algorithm")["pass"]


def test_hidden_fold_is_unique_balanced_and_not_seed_predictable(tmp_path):
    first = v2.create_hidden_fold(tmp_path / "a.json")
    second = v2.create_hidden_fold(tmp_path / "b.json")
    assert len(first["seeds"]) == len(set(first["seeds"])) == 32
    assert first["profiles"].count("standard") == first["profiles"].count("water_fire_challenge") == 16
    assert first["seeds"] != second["seeds"] and first["fold_id"] != second["fold_id"]


def test_stale_private_fold_blocks_new_run_without_deleting_evidence(tmp_path):
    stale = tmp_path / "prior-run" / "private_folds"
    stale.mkdir(parents=True)
    fold = stale / "cycle_001_fold_b.json"
    fold.write_text('{"seeds":[1]}\n', encoding="utf-8")
    with pytest.raises(v2.V2Error, match="stale private"):
        v2.reject_stale_private_folds(tmp_path)
    assert fold.read_text(encoding="utf-8") == '{"seeds":[1]}\n'


def test_stale_fold_scan_accepts_only_the_exact_regular_controller_lock(tmp_path):
    lock = tmp_path / ".controller-v2.lock"
    lock.write_text("owned by kernel lock test\n", encoding="utf-8")
    v2.reject_stale_private_folds(tmp_path)
    (tmp_path / "unexpected.txt").write_text("unsafe\n", encoding="utf-8")
    with pytest.raises(v2.V2Error, match="unsafe stale worktree entry"):
        v2.reject_stale_private_folds(tmp_path)


def test_cumulative_diff_policy_rechecks_earlier_forbidden_primitive():
    diff = (
        "diff --git a/tmp_2d_simulator_v37.py b/tmp_2d_simulator_v37.py\n"
        "--- a/tmp_2d_simulator_v37.py\n+++ b/tmp_2d_simulator_v37.py\n"
        "@@ -1 +1,2 @@\n VALUE = 1\n+import subprocess\n"
        "diff --git a/test_tmp_2d_simulator_v37.py b/test_tmp_2d_simulator_v37.py\n"
        "--- a/test_tmp_2d_simulator_v37.py\n+++ b/test_tmp_2d_simulator_v37.py\n"
        "@@ -1 +1,2 @@\n def test_value(): pass\n+def test_added(): pass\n"
    )
    reasons = v2.diff_policy_reasons(diff, sorted(v2.ALLOWED_CHANGED_FILES))
    assert any("subprocess" in reason for reason in reasons)


def test_build_result_is_schema_valid_toolless_and_exactly_scoped():
    cfg = config()
    v2.verify_build_result(cfg, valid_build())
    row = valid_build()
    row["external_writes"] = ["outside.txt"]
    with pytest.raises(v2.V2Error, match="external write"):
        v2.verify_build_result(cfg, row)
    row = valid_build()
    row["finding_ids_addressed"] = ["SEC-001"]
    with pytest.raises(v2.V2Error, match="mandatory"):
        v2.verify_build_result(cfg, row)


def test_shipped_v2_authorization_binds_every_control_cli_role_and_root():
    codex = (Path(os.environ["APPDATA"]) / "npm" / "codex.cmd").resolve()
    cfg = v2.Config(
        repo=REPO,
        python=Path(sys.executable),
        codex=codex,
        docker=Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
        authorization=REPO / "approval_codex_improvement_v2.json",
        artifact_root=REPO.parent / f"_codex_improvement_evidence_{REPO.name}",
        worktree_root=REPO.parent / f"_codex_improvement_worktrees_{REPO.name}",
        evaluator=REPO / "improvement_score_checkpoint_v2.py",
        real_codex_home=Path.home() / ".codex",
        model=v2.MODEL_DEFAULT,
        cycles=10,
        max_runtime_seconds=28_800,
        role_timeout_seconds=1_200,
        command_timeout_seconds=600,
        evaluation_timeout_seconds=900,
        remediation_cap=2,
        max_parallel_specialists=3,
        max_diff_bytes=120_000,
        sandbox_implementation="unelevated",
        dry_run=False,
        resume_run=None,
    )
    record, authorization_hash, cli_version = v2.load_authorization(cfg)
    assert record["controller_version"] == v2.VERSION
    assert cli_version == "codex-cli 0.128.0"
    assert authorization_hash == v2.legacy.canonical_text_sha256(cfg.authorization)
    assert all(record[key] == value for key, value in v2.expected_control_hashes(cfg).items())


def _init_candidate_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", path], check=True)
    (path / "tmp_2d_simulator_v37.py").write_text("VALUE = 1\n", encoding="utf-8")
    (path / "test_tmp_2d_simulator_v37.py").write_text("def test_value():\n    assert True\n", encoding="utf-8")
    subprocess.run(["git", "-C", path, "add", "."], check=True)
    subprocess.run(["git", "-C", path, "-c", "user.name=test", "-c", "user.email=test@local", "commit", "-qm", "base"], check=True)


def test_static_candidate_gate_requires_test_and_rejects_added_file_access(tmp_path):
    worktree = tmp_path / "candidate"
    worktree.mkdir()
    _init_candidate_repo(worktree)
    cfg = config(worktree)
    baseline = v2.legacy.directory_manifest(worktree, exclude_volatile=True)
    (worktree / "tmp_2d_simulator_v37.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(v2.CandidateRejected, match="focused"):
        v2.static_candidate_gate(cfg, worktree, baseline, tmp_path / "evidence-1", time.monotonic() + 30)

    (worktree / "test_tmp_2d_simulator_v37.py").write_text("def test_value():\n    assert 2 == 2\n", encoding="utf-8")
    diff, _, category = v2.static_candidate_gate(cfg, worktree, baseline, tmp_path / "evidence-2", time.monotonic() + 30)
    assert category == "algorithm" and "VALUE = 2" in diff

    (worktree / "tmp_2d_simulator_v37.py").write_text("VALUE = open('secret').read()\n", encoding="utf-8")
    with pytest.raises(v2.CandidateRejected, match="forbidden"):
        v2.static_candidate_gate(cfg, worktree, baseline, tmp_path / "evidence-3", time.monotonic() + 30)


def test_controller_routes_all_codex_roles_through_runtime(monkeypatch, tmp_path):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(v2.runtime, "run_toolless_codex_role", fake)
    cfg = config()
    result = v2.run_role(
        cfg,
        role="architecture_state",
        prompt="packet",
        schema=REPO / "schemas" / "specialist_review_v2.schema.json",
        evidence_dir=tmp_path / "evidence",
        isolation=tmp_path / "isolation-root" / "isolation",
        isolation_root=tmp_path / "isolation-root",
        deadline=time.monotonic() + 60,
    )
    assert result == {"ok": True}
    assert captured["role"] == "architecture_state"
    assert captured["model"] == v2.MODEL_DEFAULT


def test_candidate_validations_use_only_authorized_container_runtime(monkeypatch, tmp_path):
    calls = []

    def fake(**kwargs):
        calls.append(kwargs)
        result = v2.runtime.ProcessResult([], str(tmp_path), 0, "", "", False)
        v2.atomic(kwargs["evidence"], result.__dict__)
        return result

    monkeypatch.setattr(v2.runtime, "run_candidate_container", fake)
    cfg = config()
    protected = tmp_path / "protected.json"
    v2.atomic(protected, v2.runtime.ProcessResult([], str(tmp_path), 0, "", "", False).__dict__)
    workspace = tmp_path / "workspace"
    worktree = workspace / "worktree"
    worktree.mkdir(parents=True)
    registry = tmp_path / "registry"
    registry.mkdir()
    v2.run_validations(
        cfg,
        worktree,
        workspace,
        registry,
        "20260711T000000Z-abcdef12",
        1,
        {"candidate_image_id": "sha256:" + "a" * 64},
        "b" * 64,
        tmp_path / "attempt",
        protected,
        time.monotonic() + 60,
    )
    assert len(calls) == 3
    assert all(call["image_id"] == "sha256:" + "a" * 64 for call in calls)
    assert all(call["docker"] == cfg.docker for call in calls)
    assert all(call["workspace_root"] == workspace for call in calls)


def test_root_fold_c_scoring_uses_disposable_container_workspace_and_quiesces(monkeypatch, tmp_path):
    run_id = "20260711T000003Z-abcdef12"
    cfg = replace(config(), worktree_root=tmp_path / "worktrees")
    registry = cfg.worktree_root / run_id
    registry.mkdir(parents=True)
    run_dir = tmp_path / "evidence" / run_id
    run_dir.mkdir(parents=True)
    baseline = tmp_path / "baseline.npz"
    candidate = tmp_path / "candidate.npz"
    fold = tmp_path / "fold.json"
    for path in (baseline, candidate, fold):
        path.write_bytes(b"fixture")
    calls = []

    def score(*args, **kwargs):
        calls.append((args, kwargs))
        return {"fold_sha256": "a" * 64, "fitness_values": [1.0] * 8}

    order = []
    monkeypatch.setattr(v2, "trusted_score", score)
    monkeypatch.setattr(v2.runtime, "recover_governed_containers", lambda **kwargs: order.append("recover") or [])
    monkeypatch.setattr(v2.runtime, "assert_governed_containers_quiescent", lambda **kwargs: order.append("quiescent") or {})
    first, second = v2.root_fold_scores(
        cfg,
        run_id=run_id,
        baseline_checkpoint=baseline,
        candidate_checkpoint=candidate,
        fold=fold,
        authorization={"candidate_image_id": "sha256:" + "a" * 64},
        authorization_sha256="b" * 64,
        run_dir=run_dir,
        deadline=time.monotonic() + 60,
    )
    assert first == second and len(calls) == 2
    workspace = registry / "root_scoring_workspace"
    assert all(call[1]["workspace_root"] == workspace and call[1]["registry_dir"] == registry for call in calls)
    assert all(call[1]["cycle"] == 0 and call[1]["run_id"] == run_id for call in calls)
    assert order == ["recover", "quiescent"] and not workspace.exists()


def test_source_contains_no_duplicate_direct_codex_process_boundary():
    source = Path(v2.__file__).read_text(encoding="utf-8")
    assert "subprocess.Popen" not in source
    assert "codex\", \"exec" not in source
    assert "sandbox\", \"windows" not in source
    for required in ("runtime.run_toolless_codex_role", "runtime.start_candidate_acl_lease", "runtime.apply_patch_in_sandbox", "runtime.run_candidate_container"):
        assert required in source


def test_supported_launcher_targets_v2_and_exposes_operator_modes():
    launcher = (REPO / "run_codex_improvement_monitor.ps1").read_text(encoding="utf-8")
    for value in ("'Run'", "'DryRun'", "'Recover'", "'Status'", "'Review'", "'Verify'", "'Stop'", "'InspectTerminal'"):
        assert value in launcher
    assert "CodexImprovementController_v2.py" in launcher
    assert "approval_codex_improvement_v2.json" in launcher
    assert "improvement_operator.py" in launcher
    assert "--docker" in launcher and "Docker candidate boundary" in launcher
    assert "removing validated governed containers first" in launcher
    assert "CodexImprovementController_v1.py" not in launcher


def test_cycle_manifest_chains_and_excludes_itself(tmp_path):
    cycle = tmp_path / "cycle_001"
    cycle.mkdir()
    (cycle / "gate.json").write_text("{}\n", encoding="utf-8")
    manifest_hash = v2.seal_cycle(cycle, "0" * 64)
    record = json.loads((cycle / "cycle_manifest.json").read_text())
    assert len(manifest_hash) == 64
    assert record["previous_cycle_manifest_sha256"] == "0" * 64
    assert "cycle_manifest.json" not in record["files"]


def test_operator_decision_never_grants_automatic_authority():
    gates = v2.gate_template()
    for name in v2.CORE_GATES:
        v2.set_gate(gates, name, "PASS", f"{name}.json")
    reviews = [passing_review(role) for role in v2.ROLES]
    value = v2.operator_decision(
        run_id="20260711T000000Z-abcdef12",
        cycle=1,
        execution="SUCCESS",
        review="PASS",
        promotion="HUMAN_REVIEW_PENDING",
        gates=gates,
        base_commit="b" * 40,
        candidate_commit="a" * 40,
        diff_sha256="a" * 64,
        worktree="worktree",
        reviews=v2.decision_reviews(reviews, {role: f"roles/{role}/final_review/final.json" for role in v2.ROLES}, "final_qa.json", passing_final_qa()),
        rubric_value=v2.rubric(reviews, {name: True for name in v2.CORE_GATES}, {"pass": True}, passing_final_qa()),
        blockers=[],
        warnings=[],
    )
    assert value["promotion_authorized"] is value["release_authorized"] is False


def test_journal_emergency_terminal_corrects_preseal_terminal(tmp_path):
    journal = v2.Journal(tmp_path)
    journal.add("CYCLE_ACCEPTED", cycle=1)
    corrected = journal.emergency_terminal("COMPLETE_WITH_ERRORS", cause="cleanup failed")
    assert corrected["details"]["corrected_from"] == "CYCLE_ACCEPTED"
    assert v2.Journal(tmp_path).last_state == "COMPLETE_WITH_ERRORS"
    (tmp_path / "evidence_manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(v2.V2Error, match="sealed"):
        journal.emergency_terminal("ERROR")


def test_emergency_finalize_writes_terminal_bundle_on_root_fault(monkeypatch, tmp_path):
    cfg = config(tmp_path / "repo")
    cfg.artifact_root.mkdir(parents=True)
    cfg.worktree_root.mkdir(parents=True)
    run_dir = cfg.artifact_root / "20260711T000000Z-abcdef12"
    run_dir.mkdir()
    journal = v2.Journal(run_dir)
    journal.add("AUTHORIZED")
    (run_dir / "authorization_evidence.json").write_text("{}", encoding="utf-8")
    context = v2.ActiveRunContext(cfg, run_dir, journal, "a" * 40, {"protected": True})
    monkeypatch.setattr(v2, "production_snapshot", lambda config: {"protected": False})
    monkeypatch.setattr(v2, "recover_persisted_candidate_containers", lambda *args, **kwargs: [])
    published = []
    monkeypatch.setattr(v2, "publish_run", lambda config, run_dir, status: published.append((run_dir.name, status)))
    assert v2.emergency_finalize(context, RuntimeError("injected root fault")) == 2
    assert json.loads((run_dir / "state.json").read_text())["status"] == "COMPLETE_WITH_ERRORS"
    decision = json.loads((run_dir / "operator_decision.json").read_text())
    assert decision["execution"] == "FAILED"
    assert decision["lineage"]["production_modified"] is True
    assert (run_dir / "evidence_manifest.json").is_file()
    assert published == [(run_dir.name, "COMPLETE_WITH_ERRORS")]


def test_emergency_restore_failure_never_seals_or_publishes(monkeypatch, tmp_path):
    cfg = config(tmp_path / "repo")
    cfg.artifact_root.mkdir(parents=True); cfg.worktree_root.mkdir(parents=True)
    run_dir = cfg.artifact_root / "20260711T000000Z-abcdef12"; run_dir.mkdir()
    journal = v2.Journal(run_dir); journal.add("AUTHORIZED")
    context = v2.ActiveRunContext(cfg, run_dir, journal, "a" * 40, {"protected": True}, "b" * 64)
    monkeypatch.setattr(v2, "recover_persisted_acl_leases", lambda *args, **kwargs: (_ for _ in ()).throw(v2.runtime.RuntimeFailure("restore fault")))
    monkeypatch.setattr(v2, "recover_persisted_candidate_containers", lambda *args, **kwargs: [])
    sealed = []; published = []
    monkeypatch.setattr(v2, "seal_run", lambda *args, **kwargs: sealed.append(True))
    monkeypatch.setattr(v2, "publish_run", lambda *args, **kwargs: published.append(True))
    with pytest.raises(v2.runtime.RuntimeFailure, match="unsealed and unpublished"):
        v2.emergency_finalize(context, RuntimeError("root fault"))
    recovery = json.loads((run_dir / "emergency_recovery_required.json").read_text())
    assert recovery["sealed"] is recovery["published"] is False
    assert sealed == [] and published == [] and not (run_dir / "evidence_manifest.json").exists()


def test_emergency_recovery_precedes_production_guard_seal_and_publish(monkeypatch, tmp_path):
    cfg = config(tmp_path / "repo")
    cfg.artifact_root.mkdir(parents=True); cfg.worktree_root.mkdir(parents=True)
    run_dir = cfg.artifact_root / "20260711T000000Z-abcdef12"; run_dir.mkdir()
    journal = v2.Journal(run_dir); journal.add("AUTHORIZED")
    context = v2.ActiveRunContext(cfg, run_dir, journal, "a" * 40, {"protected": True}, "b" * 64)
    order = []
    monkeypatch.setattr(v2, "recover_persisted_candidate_containers", lambda *args, **kwargs: order.append("container-recover") or [])
    monkeypatch.setattr(v2, "recover_persisted_acl_leases", lambda *args, **kwargs: order.append("acl-recover") or [])
    original_assert = v2.assert_acl_quiescent
    monkeypatch.setattr(v2, "assert_acl_quiescent", lambda *args, **kwargs: order.append("quiescent") or original_assert(*args, **kwargs))
    monkeypatch.setattr(v2, "production_snapshot", lambda config: order.append("production") or {"protected": True})
    original_seal = v2.seal_run
    monkeypatch.setattr(v2, "seal_run", lambda *args, **kwargs: order.append("seal") or original_seal(*args, **kwargs))
    monkeypatch.setattr(v2, "publish_run", lambda *args, **kwargs: order.append("publish"))
    assert v2.emergency_finalize(context, RuntimeError("root fault")) == 2
    assert order.index("container-recover") < order.index("acl-recover") < order.index("production") < order.index("seal") < order.index("publish")


def test_startup_recovers_identity_bound_persisted_acl_lease(monkeypatch, tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    helper = repo / "improvement_acl_helper.ps1"; helper.write_text("# fixed helper\n", encoding="utf-8")
    cfg = replace(config(repo), artifact_root=tmp_path / "evidence", worktree_root=tmp_path / "worktrees")
    cfg.artifact_root.mkdir(); cfg.worktree_root.mkdir()
    workspace = cfg.worktree_root / "20260711T000000Z-abcdef12"
    root = workspace / "cycle_001_candidate_lease"; root.mkdir(parents=True)
    helper_sha256 = v2.legacy.sha256_file(helper)
    recovery_helper = workspace / f".acl-recovery-helper-{helper_sha256}.ps1"
    recovery_helper.write_bytes(helper.read_bytes())
    sddl = "D:"
    record = {
        "schema_version": v2.runtime.ACL_LEASE_SCHEMA,
        "lease_id": "stale-lease",
        "state": "ACTIVE",
        "root": str(root.resolve()),
        "authorized_parent": str(workspace.resolve()),
        "root_identity": v2.runtime.directory_identity(root),
        "helper_path": str(helper.resolve()),
        "helper_sha256": helper_sha256,
        "recovery_helper_path": str(recovery_helper.resolve()),
        "recovery_helper_sha256": helper_sha256,
        "authorization_sha256": "a" * 64,
        "controller_pid": 999999,
        "worktree_path": str(root.resolve() / "worktree"),
        "control_dir": str(workspace / "old-control"),
        "evidence_dir": str(cfg.artifact_root),
        "snapshot": {
            "schema_version": "blast-pit.acl-root-snapshot.v1",
            "root": str(root.resolve()),
            "authorized_parent": str(workspace.resolve()),
            "sddl": sddl,
            "sddl_sha256": hashlib.sha256(sddl.encode()).hexdigest(),
            "owner": "owner",
            "group": "group",
            "access_rules_protected": False,
            "rules": [],
        },
        "restricted_sid": "S-1-5-21-1-2-3-4",
        "history": [{"state": "ACTIVE", "recorded_at": "2026-07-11T00:00:00Z"}],
    }
    lease_path = workspace / "acl_lease_cycle_001.json"; v2.atomic(lease_path, record)
    monkeypatch.setattr(v2, "git", lambda *args, **kwargs: v2.runtime.ProcessResult([], str(repo), 0, "", ""))
    def restore(lease, **kwargs):
        v2.runtime._write_acl_lease(lease, "RESTORED_RECOVERY", restored_result_sha256="b" * 64, verified_result_sha256="c" * 64)
        return {}
    monkeypatch.setattr(v2.runtime, "restore_candidate_acl_lease", restore)
    rows = v2.recover_persisted_acl_leases(cfg, current_authorization_sha256="d" * 64)
    assert len(rows) == 1 and rows[0]["state"] == "RESTORED_RECOVERY"
    assert not root.exists() and not workspace.exists()
    final_record = next((cfg.artifact_root / "acl_recovery").rglob("acl_lease_final.json"))
    assert json.loads(final_record.read_text())["state"] == "RESTORED_RECOVERY"
    preflight = next((cfg.artifact_root / "acl_recovery").rglob("recovery_preflight.json"))
    assert json.loads(preflight.read_text())["authorization_matches_current"] is False
    host = v2.improvement_operator.recovery_status(cfg.artifact_root)
    assert host["status"] == "RECOVERED" and host["active_leases"] == []


def test_recovery_required_event_is_sealed_ledgered_and_prominent(tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    cfg = replace(config(repo), artifact_root=tmp_path / "evidence")
    event = cfg.artifact_root / "acl_recovery" / "recovery_20260711T000000Z_abcdef12"
    event.mkdir(parents=True)
    (event / "fault.txt").write_text("restore failed\n", encoding="utf-8")
    lease = {"lease_path": "worktrees/run/acl_lease_cycle_001.json", "state": "RECOVERY_REQUIRED", "root_removed": False}
    latest = v2.seal_acl_recovery_event(cfg, event, status="RECOVERY_REQUIRED", leases=[lease], error="restore failed")
    assert latest["status"] == "RECOVERY_REQUIRED" and (cfg.artifact_root / "acl_recovery_ledger.jsonl").is_file()
    host = v2.improvement_operator.recovery_status(cfg.artifact_root)
    assert host["status"] == "RECOVERY_REQUIRED" and host["active_leases"] == [lease["lease_path"]]


def test_container_recovery_failure_is_sealed_ledgered_and_operator_visible(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = replace(config(repo), artifact_root=tmp_path / "evidence", worktree_root=tmp_path / "worktrees")
    cfg.artifact_root.mkdir()
    cfg.worktree_root.mkdir()
    monkeypatch.setattr(
        v2.runtime,
        "recover_governed_containers",
        lambda **kwargs: (_ for _ in ()).throw(v2.runtime.RuntimeFailure("injected container recovery fault")),
    )
    with pytest.raises(v2.runtime.RuntimeFailure, match="container recovery failed"):
        v2.recover_persisted_candidate_containers(cfg)
    assert (cfg.artifact_root / "container_recovery_ledger.jsonl").is_file()
    host = v2.improvement_operator.container_recovery_status(cfg.artifact_root)
    assert host["status"] == "RECOVERY_REQUIRED" and host["event_id"].startswith("recovery_")


def test_acl_quiescence_rejects_in_memory_active_lease(tmp_path):
    cfg = replace(config(tmp_path / "repo"), worktree_root=tmp_path / "worktrees")
    cfg.worktree_root.mkdir(parents=True)
    run_id = "20260711T000000Z-abcdef12"
    context = v2.ActiveRunContext(cfg, tmp_path, None, "a" * 40, {}, "b" * 64)  # type: ignore[arg-type]
    context.acl_leases.append(object())  # type: ignore[arg-type]
    with pytest.raises(v2.runtime.RuntimeFailure, match="registry is not empty"):
        v2.assert_acl_quiescent(cfg, run_id, context, tmp_path / "gate.json")
    assert not (tmp_path / "gate.json").exists()


def test_recover_only_uses_lock_and_never_starts_candidate_run(monkeypatch, tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    (repo / "approval_codex_improvement_v2.json").write_text("{}\n", encoding="utf-8")
    (repo / "improvement_acl_helper.ps1").write_text("# helper\n", encoding="utf-8")
    cfg = replace(config(repo), artifact_root=tmp_path / "evidence", worktree_root=tmp_path / "worktrees", recover_only=True)
    calls = []
    monkeypatch.setattr(v2.runtime, "ControllerLock", lambda *args, **kwargs: contextlib.nullcontext())
    monkeypatch.setattr(v2, "recover_persisted_candidate_containers", lambda *args, **kwargs: calls.append("container-recover") or [])
    monkeypatch.setattr(v2, "recover_persisted_acl_leases", lambda *args, **kwargs: calls.append("acl-recover") or [])
    monkeypatch.setattr(v2.improvement_operator, "recovery_status", lambda *args, **kwargs: {"status": "NO_RECOVERY_EVENTS"})
    monkeypatch.setattr(v2.improvement_operator, "container_recovery_status", lambda *args, **kwargs: {"status": "NO_RECOVERY_EVENTS"})
    monkeypatch.setattr(v2, "_run_unfinalized", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("candidate run started")))
    assert v2.run(cfg) == 0 and calls == ["container-recover", "acl-recover"]


def test_publish_run_restores_previous_latest_on_postpublish_verify_failure(monkeypatch, tmp_path):
    cfg = config(tmp_path / "repo")
    cfg.artifact_root.mkdir(parents=True)
    run_dir = cfg.artifact_root / "20260711T000000Z-abcdef12"
    run_dir.mkdir()
    (run_dir / "evidence_manifest.json").write_text("manifest", encoding="utf-8")
    (run_dir / "operator_decision.json").write_text("decision", encoding="utf-8")
    previous = b'{"run_id":"older"}\n'
    (cfg.artifact_root / "latest.json").write_bytes(previous)
    manifest_hash = v2.legacy.sha256_file(run_dir / "evidence_manifest.json")
    decision_hash = v2.legacy.sha256_file(run_dir / "operator_decision.json")
    monkeypatch.setattr(v2.improvement_operator, "_local_ledger_entry", lambda root, run_id: ({"evidence_manifest_sha256": manifest_hash, "operator_decision_sha256": decision_hash, "ledger_hash": "b" * 64}, None))
    calls = {"count": 0}
    def verify(*args):
        calls["count"] += 1
        if calls["count"] == 2:
            raise v2.improvement_operator.OperatorError("injected verification failure")
    monkeypatch.setattr(v2.improvement_operator, "verify_record", verify)
    with pytest.raises(v2.improvement_operator.OperatorError):
        v2.publish_run(cfg, run_dir, "COMPLETE")
    assert (cfg.artifact_root / "latest.json").read_bytes() == previous


def test_publish_run_bootstraps_only_a_missing_local_ledger(monkeypatch, tmp_path):
    cfg = config(tmp_path / "repo")
    cfg.artifact_root.mkdir(parents=True)
    run_dir = cfg.artifact_root / "20260711T000000Z-abcdef12"
    run_dir.mkdir()
    (run_dir / "evidence_manifest.json").write_text("manifest", encoding="utf-8")
    (run_dir / "operator_decision.json").write_text("decision", encoding="utf-8")
    monkeypatch.setattr(v2.improvement_operator, "verify_record", lambda *args: {})

    v2.publish_run(cfg, run_dir, "COMPLETE_WITH_ERRORS")

    ledger = (cfg.artifact_root / "audit_ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(ledger) == 1
    assert json.loads(ledger[0])["run_id"] == run_dir.name
    assert json.loads((cfg.artifact_root / "latest.json").read_text())["run_id"] == run_dir.name

    unsafe = config(tmp_path / "unsafe" / "repo")
    unsafe.artifact_root.mkdir(parents=True)
    unsafe_run = unsafe.artifact_root / "20260711T000001Z-abcdef12"
    unsafe_run.mkdir()
    (unsafe_run / "evidence_manifest.json").write_text("manifest", encoding="utf-8")
    (unsafe_run / "operator_decision.json").write_text("decision", encoding="utf-8")
    (unsafe.artifact_root / "audit_ledger.jsonl").mkdir()
    with pytest.raises(v2.improvement_operator.OperatorError, match="missing or unsafe"):
        v2.publish_run(unsafe, unsafe_run, "COMPLETE_WITH_ERRORS")


def test_terminal_resume_is_byte_immutable(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = config(repo)
    run_id = "20260711T000000Z-abcdef12"
    cfg = replace(cfg, artifact_root=tmp_path / "evidence", worktree_root=tmp_path / "worktrees", resume_run=run_id)
    run_dir = cfg.artifact_root / run_id
    run_dir.mkdir(parents=True)
    journal = v2.Journal(run_dir)
    journal.add("COMPLETE_WITH_REJECTIONS")
    (run_dir / "operator_decision.json").write_text('{"promotion":"NOT_ELIGIBLE"}\n', encoding="utf-8")
    before = {path.relative_to(run_dir).as_posix(): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}
    def fake_git(config, args, **kwargs):
        value = "" if "status" in args else (str(repo) if "--show-toplevel" in args else "a" * 40)
        return v2.runtime.ProcessResult([], str(repo), 0, value, "")
    monkeypatch.setattr(v2, "git", fake_git)
    monkeypatch.setattr(v2, "load_authorization", lambda config: ({}, "b" * 64, "codex-cli 0.128.0"))
    monkeypatch.setattr(v2, "reject_stale_private_folds", lambda root: None)
    monkeypatch.setattr(v2.improvement_operator, "verify_record", lambda *args: {})
    assert v2._run_unfinalized(cfg) == 2
    after = {path.relative_to(run_dir).as_posix(): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}
    assert after == before
