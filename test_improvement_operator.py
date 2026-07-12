from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import improvement_operator as operator


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_record(path: Path) -> dict[str, object]:
    return {"kind": "file", "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def decision_record(*, ready: bool = True, execution: str = "SUCCESS") -> dict[str, object]:
    rubric_ids = tuple(operator.RUBRIC_EVIDENCE_FRAGMENT)
    gate_evidence = {
        "authorization": "authorization_evidence.json",
        "external_guard": "production_guard.json",
        "production_guard": "production_guard.json",
        **{name: f"gates/{name}.json" for name in operator.CORE_GATES - {"authorization", "external_guard", "production_guard"}},
    }
    return {
        "schema_version": "codex.improvement-operator-decision.v2",
        "run_id": "run-001",
        "cycle": 1,
        "execution": execution,
        "review": "PASS" if ready else ("BLOCK" if execution != "SUCCESS" else "CHANGES_REQUIRED"),
        "promotion": "HUMAN_REVIEW_PENDING" if ready else "NOT_ELIGIBLE",
        "cycle_gates": [
            {"name": name, "status": "PASS" if ready else "FAIL", "evidence": gate_evidence[name]}
            for name in sorted(operator.CORE_GATES)
        ],
        "lineage": {
            "base_commit": "b" * 40,
            "candidate_commit": "a" * 40 if ready else None,
            "diff_sha256": "c" * 64 if ready else None,
            "worktree": "worktree",
            "production_modified": False,
        },
        "reviews": [
            {
                "role": role,
                "status": "PASS" if ready else "NOT_RUN",
                "artifact": "final_qa.json" if role == "final_qa" else f"roles/{role}/final_review/final.json",
            }
            for role in sorted(operator.REVIEW_ROLES)
        ],
        "rubric": {
            "items": [
                {
                    "id": identifier,
                    "score": 10 if ready else 0,
                    "maximum": 10,
                    "evidence": (
                        "final_evaluation_summary.json"
                        if identifier == "evaluation"
                        else "final_qa.json"
                        if identifier == "specialist_consensus"
                        else f"roles/{operator.RUBRIC_EVIDENCE_FRAGMENT[identifier].split('/')[1]}/final_review/final.json"
                    ),
                }
                for identifier in rubric_ids
            ],
            "total": 100 if ready else 0,
            "maximum": 100,
            "ten_out_of_ten": ready,
        },
        "blockers": [] if ready else ["QA failed"],
        "warnings": [],
        "promotion_authorized": False,
        "release_authorized": False,
    }


def write_referenced_evidence(run: Path, decision: dict[str, object]) -> None:
    diff_sha = decision["lineage"]["diff_sha256"]
    write_json(run / "authorization_evidence.json", {"pass": True})
    for gate in decision["cycle_gates"]:
        path = run / gate["evidence"]
        if not path.exists():
            write_json(path, {"pass": gate["status"] == "PASS"})
    write_json(run / "final_evaluation_summary.json", {"pass": True})
    for review in decision["reviews"]:
        path = run / review["artifact"]
        if review["role"] == "final_qa":
            write_json(path, {"schema_version": "codex.final-qa.v2", "diff_sha256": diff_sha, "verdict": "PASS", "blockers": []})
        else:
            write_json(path, {"schema_version": "codex.specialist-review.v2", "role": review["role"], "diff_sha256": diff_sha, "verdict": "PASS", "findings": []})


def seal(root: Path, *, state_status: str) -> None:
    run = root / "run-001"
    manifest_path = run / "evidence_manifest.json"
    files = {
        path.relative_to(run).as_posix(): file_record(path)
        for path in sorted(run.rglob("*"))
        if path.is_file() and path != manifest_path
    }
    write_json(manifest_path, {"run_id": "run-001", "status": state_status, "files": files})
    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    decision_hash = hashlib.sha256((run / "operator_decision.json").read_bytes()).hexdigest()
    unsigned = {
        "schema_version": "blast-pit.improvement-ledger.v1",
        "sequence": 1,
        "previous_ledger_hash": "0" * 64,
        "run_id": "run-001",
        "evidence_manifest_sha256": manifest_hash,
        "operator_decision_sha256": decision_hash,
        "recorded_at": "2026-07-11T00:00:00Z",
    }
    ledger_hash = hashlib.sha256(canonical(unsigned).encode()).hexdigest()
    (root / "audit_ledger.jsonl").write_text(canonical({**unsigned, "ledger_hash": ledger_hash}) + "\n", encoding="utf-8")
    write_json(
        root / "latest.json",
        {
            "run_id": "run-001",
            "status": state_status,
            "evidence_manifest_sha256": manifest_hash,
            "operator_decision_sha256": decision_hash,
            "ledger_hash": ledger_hash,
        },
    )


def fixture(tmp_path: Path, *, ready: bool = True, execution: str = "SUCCESS", state_status: str | None = None) -> Path:
    root = tmp_path / "evidence"
    run = root / "run-001"
    run.mkdir(parents=True)
    decision = decision_record(ready=ready, execution=execution)
    controller_status = state_status or ("COMPLETE" if ready else "COMPLETE_WITH_REJECTIONS" if execution == "SUCCESS" else "COMPLETE_WITH_ERRORS")
    unsigned = {
        "schema_version": "blast-pit.improvement-transition.v2",
        "revision": 1,
        "state": controller_status,
        "timestamp": "2026-07-11T00:00:00Z",
        "previous_transition_hash": "0" * 64,
        "details": {},
    }
    transition_hash = hashlib.sha256(canonical(unsigned).encode()).hexdigest()
    (run / "transitions.jsonl").write_text(canonical({**unsigned, "transition_hash": transition_hash}) + "\n", encoding="utf-8")
    write_json(run / "state.json", {"run_id": "run-001", "status": controller_status, "revision": 1, "last_transition_hash": transition_hash})
    write_json(run / "production_guard.json", {"pass": True})
    write_referenced_evidence(run, decision)
    write_json(run / "operator_decision.json", decision)
    seal(root, state_status=controller_status)
    return root


def assert_tampered(call, text: str | None = None) -> None:
    with pytest.raises(operator.OperatorError) as caught:
        call()
    assert caught.value.exit_code == operator.EXIT_TAMPERED
    if text:
        assert text in str(caught.value)


def test_clean_evidence_verifies_and_status_review_reverify_seal(tmp_path):
    root = fixture(tmp_path)
    result = operator.verify_record(root)
    assert result["verified"] is True and result["file_count"] > 10
    assert operator.status_record(root)[1] == operator.EXIT_OK
    assert operator.review_record(root)[1] == operator.EXIT_OK


def test_tampered_missing_extra_file_and_empty_directory_fail_closed(tmp_path):
    root = fixture(tmp_path)
    (root / "run-001" / "state.json").write_text("{}\n", encoding="utf-8")
    assert_tampered(lambda: operator.verify_record(root), "mismatch")

    root = fixture(tmp_path / "missing")
    (root / "run-001" / "production_guard.json").unlink()
    assert_tampered(lambda: operator.verify_record(root), "production guard is missing")

    root = fixture(tmp_path / "extra")
    (root / "run-001" / "unexpected.txt").write_text("extra", encoding="utf-8")
    assert_tampered(lambda: operator.verify_record(root), "extra retained files")

    root = fixture(tmp_path / "empty")
    (root / "run-001" / "unexpected-empty-directory").mkdir()
    assert_tampered(lambda: operator.verify_record(root), "extra retained directories")


def test_latest_manifest_decision_and_ledger_mismatches_fail_closed(tmp_path):
    root = fixture(tmp_path)
    latest = json.loads((root / "latest.json").read_text())
    latest["evidence_manifest_sha256"] = "0" * 64
    write_json(root / "latest.json", latest)
    assert_tampered(lambda: operator.verify_record(root), "latest state evidence manifest")

    root = fixture(tmp_path / "decision")
    decision = json.loads((root / "run-001" / "operator_decision.json").read_text())
    decision["warnings"] = ["self-consistent forged replacement"]
    write_json(root / "run-001" / "operator_decision.json", decision)
    assert_tampered(lambda: operator.review_record(root), "mismatch")
    assert_tampered(lambda: operator.status_record(root), "mismatch")

    root = fixture(tmp_path / "ledger")
    line = json.loads((root / "audit_ledger.jsonl").read_text())
    line["evidence_manifest_sha256"] = "0" * 64
    (root / "audit_ledger.jsonl").write_text(canonical(line) + "\n", encoding="utf-8")
    assert_tampered(lambda: operator.verify_record(root), "ledger")


def test_failed_and_nonready_execution_are_blocked(tmp_path):
    failed = fixture(tmp_path / "failed", ready=False, execution="FAILED", state_status="COMPLETE_WITH_ERRORS")
    assert operator.status_record(failed)[1] == operator.EXIT_BLOCKED
    blocked = fixture(tmp_path / "blocked", ready=False)
    assert operator.review_record(blocked)[1] == operator.EXIT_BLOCKED


def test_json_cli_prints_exact_sealed_decision(tmp_path, capsys):
    root = fixture(tmp_path)
    expected = json.loads((root / "run-001" / "operator_decision.json").read_text())
    expected["host_acl_recovery"] = {"status": "NO_RECOVERY_EVENTS", "event_id": None, "active_leases": []}
    expected["host_container_recovery"] = {"status": "NO_RECOVERY_EVENTS", "event_id": None}
    assert operator.main(["review", "--artifact-root", str(root), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == expected


def test_container_recovery_required_blocks_status_review_and_verify(monkeypatch, tmp_path):
    root = fixture(tmp_path)
    monkeypatch.setattr(
        operator,
        "container_recovery_status",
        lambda artifact_root: {"status": "RECOVERY_REQUIRED", "event_id": "recovery_fault"},
    )
    status, status_code = operator.status_record(root)
    review, review_code = operator.review_record(root)
    verified = operator.verify_record(root)
    assert status_code == operator.EXIT_BLOCKED and review_code == operator.EXIT_BLOCKED
    assert status["host_container_recovery"]["status"] == "RECOVERY_REQUIRED"
    assert review["host_container_recovery"]["status"] == "RECOVERY_REQUIRED"
    assert verified["host_container_recovery"]["status"] == "RECOVERY_REQUIRED"


def test_ready_cross_field_authority_and_gate_invariants():
    value = decision_record()
    value["promotion_authorized"] = True
    assert_tampered(lambda: operator.validate_operator_decision(value), "promotion must be false")

    value = decision_record()
    value["blockers"] = ["unresolved"]
    assert_tampered(lambda: operator.validate_operator_decision(value), "cannot have blockers")

    value = decision_record()
    value["cycle_gates"].pop()
    assert_tampered(lambda: operator.validate_operator_decision(value), "exact core gates")


def test_cycle_manifest_chain_and_gap_are_verified(tmp_path):
    root = fixture(tmp_path)
    run = root / "run-001"
    cycle = run / "cycle_001"
    cycle.mkdir()
    payload = cycle / "gate.json"
    payload.write_text("ok", encoding="utf-8")
    write_json(
        cycle / "cycle_manifest.json",
        {
            "cycle": 1,
            "previous_cycle_manifest_sha256": "0" * 64,
            "files": {"gate.json": {"bytes": 2, "sha256": hashlib.sha256(b"ok").hexdigest()}},
        },
    )
    seal(root, state_status="COMPLETE")
    assert operator.verify_record(root)["verified"] is True
    payload.write_text("no", encoding="utf-8")
    assert_tampered(lambda: operator.verify_record(root))

    root = fixture(tmp_path / "gap")
    run = root / "run-001"
    (run / "cycle_002").mkdir()
    write_json(run / "cycle_002" / "cycle_manifest.json", {"cycle": 2, "previous_cycle_manifest_sha256": "0" * 64, "files": {}})
    seal(root, state_status="COMPLETE")
    assert_tampered(lambda: operator.verify_record(root), "non-contiguous")


def test_transition_chain_semantics_are_verified(tmp_path):
    root = fixture(tmp_path)
    path = root / "run-001" / "transitions.jsonl"
    row = json.loads(path.read_text())
    row["revision"] = 2
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert_tampered(lambda: operator.verify_record(root), "transition chain mismatch")


def test_rubric_ten_must_cite_dimension_specific_evidence(tmp_path):
    root = fixture(tmp_path)
    path = root / "run-001" / "operator_decision.json"
    value = json.loads(path.read_text())
    testing = next(item for item in value["rubric"]["items"] if item["id"] == "testing")
    testing["evidence"] = "roles/architecture_state/final_review/final.json"
    write_json(path, value)
    seal(root, state_status="COMPLETE")
    assert_tampered(lambda: operator.verify_record(root), "unrelated evidence")


def test_nonlatest_explicit_run_uses_ledger_anchor_without_mutation(tmp_path):
    root = fixture(tmp_path)
    before = {path: path.read_bytes() for path in (root / "run-001").rglob("*") if path.is_file()}
    latest = json.loads((root / "latest.json").read_text())
    latest["run_id"] = "newer-run"
    latest["evidence_manifest_sha256"] = "0" * 64
    latest["operator_decision_sha256"] = "0" * 64
    latest["ledger_hash"] = "0" * 64
    write_json(root / "latest.json", latest)
    assert operator.verify_record(root, "run-001")["verified"] is True
    after = {path: path.read_bytes() for path in (root / "run-001").rglob("*") if path.is_file()}
    assert before == after
