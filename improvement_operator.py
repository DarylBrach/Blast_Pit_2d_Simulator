from __future__ import annotations

"""Read-only operator status, review, and evidence verification for improvement runs."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence


EXIT_OK = 0
EXIT_MISSING = 1
EXIT_BLOCKED = 2
EXIT_TAMPERED = 3

EXECUTION_STATUSES = {"NOT_RUN", "RUNNING", "SUCCESS", "FAILED", "TIMEOUT", "KILLED"}
REVIEW_STATUSES = {"NOT_RUN", "RUNNING", "PASS", "CHANGES_REQUIRED", "BLOCK"}
PROMOTION_STATUSES = {"NOT_RUN", "NOT_ELIGIBLE", "HUMAN_REVIEW_PENDING", "REJECTED"}
GATE_STATUSES = {"NOT_RUN", "RUNNING", "PASS", "FAIL", "TIMEOUT", "SKIPPED"}
SPECIALIST_STATUSES = {"NOT_RUN", "RUNNING", "PASS", "CHANGES_REQUIRED", "BLOCK", "TIMEOUT", "ERROR"}
REVIEW_ROLES = {"architecture_state", "algorithm_objective", "workflow_state", "governance_evidence", "security_sandbox", "testing_reliability", "docs_ux", "final_qa"}
CORE_GATES = {"authorization", "sandbox_canary", "external_guard", "filesystem", "security", "compile", "focused_tests", "full_tests", "specialist_consensus", "evaluation", "final_qa", "production_guard"}
DECISION_KEYS = {"schema_version", "run_id", "cycle", "execution", "review", "promotion", "cycle_gates", "lineage", "reviews", "rubric", "blockers", "warnings", "promotion_authorized", "release_authorized"}
NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
HEX_RE = re.compile(r"^[a-f0-9]+$")
MAX_JSON_BYTES = 4_000_000
MAX_EVIDENCE_FILES = 20_000
MAX_EVIDENCE_BYTES = 512_000_000
RUBRIC_EVIDENCE_FRAGMENT = {
    "architecture": "roles/architecture_state/",
    "workflow": "roles/workflow_state/",
    "security": "roles/security_sandbox/",
    "algorithm": "roles/algorithm_objective/",
    "determinism": "roles/testing_reliability/",
    "testing": "roles/testing_reliability/",
    "evaluation": "final_evaluation_summary.json",
    "evidence": "roles/governance_evidence/",
    "maintainability": "roles/docs_ux/",
    "specialist_consensus": "final_qa.json",
}


class OperatorError(RuntimeError):
    def __init__(self, message: str, exit_code: int = EXIT_MISSING):
        super().__init__(message)
        self.exit_code = exit_code


def read_json(path: Path, label: str, exit_code: int = EXIT_MISSING) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_JSON_BYTES:
        raise OperatorError(f"{label} is missing or unsafe: {path}", exit_code)

    def strict_pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OperatorError(f"{label} contains duplicate key {key!r}", EXIT_TAMPERED)
            result[key] = value
        return result
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise OperatorError(f"{label} is unreadable or invalid: {path}", exit_code) from exc
    if not isinstance(value, dict):
        raise OperatorError(f"{label} must be a JSON object: {path}", exit_code)
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_ancestors(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists():
            break
        if _is_reparse(current):
            raise OperatorError(f"evidence path contains a symlink or reparse point: {current}", EXIT_TAMPERED)
    return absolute.resolve(strict=True)


def _strict_tree(root: Path) -> tuple[set[str], set[str]]:
    root = _validate_ancestors(root)
    files: set[str] = set()
    directories: set[str] = set()
    total = 0
    for current, names, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in names:
            path = current_path / name
            if _is_reparse(path):
                raise OperatorError(f"evidence tree contains a reparse directory: {path}", EXIT_TAMPERED)
            directories.add(path.relative_to(root).as_posix())
        for name in filenames:
            path = current_path / name
            info = path.stat(follow_symlinks=False)
            if _is_reparse(path) or not path.is_file() or info.st_nlink != 1:
                raise OperatorError(f"evidence tree contains an unsafe file: {path}", EXIT_TAMPERED)
            total += info.st_size
            files.add(path.relative_to(root).as_posix())
            if len(files) > MAX_EVIDENCE_FILES or total > MAX_EVIDENCE_BYTES:
                raise OperatorError("evidence tree exceeds verification bounds", EXIT_TAMPERED)
    return files, directories


def _local_ledger_entry(artifact_root: Path, run_id: str) -> tuple[dict[str, Any], str]:
    path = artifact_root / "audit_ledger.jsonl"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_JSON_BYTES:
        raise OperatorError("local audit ledger is missing or unsafe", EXIT_TAMPERED)
    previous = "0" * 64
    sequence = 0
    selected: dict[str, Any] | None = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise OperatorError(f"local audit ledger has invalid JSON at line {number}", EXIT_TAMPERED) from exc
        if not isinstance(row, dict):
            raise OperatorError(f"local audit ledger line {number} is not an object", EXIT_TAMPERED)
        supplied = row.get("ledger_hash")
        unsigned = dict(row)
        unsigned.pop("ledger_hash", None)
        calculated = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if row.get("sequence") != sequence + 1 or row.get("previous_ledger_hash") != previous or supplied != calculated:
            raise OperatorError(f"local audit ledger chain mismatch at line {number}", EXIT_TAMPERED)
        sequence += 1
        previous = supplied
        if row.get("run_id") == run_id:
            if selected is not None:
                raise OperatorError("local audit ledger contains a duplicate run ID", EXIT_TAMPERED)
            selected = row
    if selected is None:
        raise OperatorError("selected run is not anchored in the local audit ledger", EXIT_TAMPERED)
    return selected, previous


def _evidence_reference(run_dir: Path, expected: set[str], value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise OperatorError(f"{label} has no canonical evidence path", EXIT_TAMPERED)
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() not in expected:
        raise OperatorError(f"{label} references unsealed evidence: {value!r}", EXIT_TAMPERED)
    path = run_dir / relative
    if not path.is_file() or path.is_symlink():
        raise OperatorError(f"{label} evidence is missing or unsafe: {value!r}", EXIT_TAMPERED)
    return path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OperatorError(f"invalid operator decision: {message}", EXIT_TAMPERED)


def validate_operator_decision(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the shipped v2 schema plus cross-field authority semantics."""
    require(set(value) == DECISION_KEYS, "required fields or additional properties mismatch")
    require(value.get("schema_version") == "codex.improvement-operator-decision.v2", "schema_version mismatch")
    run_id = value.get("run_id")
    require(isinstance(run_id, str) and 1 <= len(run_id) <= 80 and all(c.isalnum() or c in "_.-" for c in run_id), "invalid run_id")
    require(isinstance(value.get("cycle"), int) and not isinstance(value["cycle"], bool) and 1 <= value["cycle"] <= 10000, "invalid cycle")
    require(value.get("execution") in EXECUTION_STATUSES, "invalid execution status")
    require(value.get("review") in REVIEW_STATUSES, "invalid review status")
    require(value.get("promotion") in PROMOTION_STATUSES, "invalid promotion status")
    require(value.get("promotion_authorized") is False, "automatic promotion must be false")
    require(value.get("release_authorized") is False, "automatic release must be false")

    gates = value.get("cycle_gates")
    require(isinstance(gates, list) and 1 <= len(gates) <= 100, "cycle_gates must be non-empty")
    for gate in gates:
        require(isinstance(gate, dict) and set(gate) == {"name", "status", "evidence"}, "invalid gate fields")
        require(isinstance(gate["name"], str) and NAME_RE.fullmatch(gate["name"]) is not None and gate["status"] in GATE_STATUSES, "invalid gate")
        require(gate["evidence"] is None or isinstance(gate["evidence"], str) and len(gate["evidence"]) <= 1000, "invalid gate evidence")
    require(len({gate["name"] for gate in gates}) == len(gates), "duplicate gate names")

    lineage = value.get("lineage")
    require(isinstance(lineage, dict) and set(lineage) == {"base_commit", "candidate_commit", "diff_sha256", "worktree", "production_modified"}, "invalid lineage fields")
    require(isinstance(lineage["base_commit"], str) and len(lineage["base_commit"]) in {40, 64} and HEX_RE.fullmatch(lineage["base_commit"]) is not None, "invalid base commit")
    require(lineage["candidate_commit"] is None or isinstance(lineage["candidate_commit"], str) and len(lineage["candidate_commit"]) in {40, 64} and HEX_RE.fullmatch(lineage["candidate_commit"]) is not None, "invalid candidate commit")
    require(lineage["diff_sha256"] is None or isinstance(lineage["diff_sha256"], str) and len(lineage["diff_sha256"]) == 64 and HEX_RE.fullmatch(lineage["diff_sha256"]) is not None, "invalid diff hash")
    require(isinstance(lineage["worktree"], str) and 1 <= len(lineage["worktree"]) <= 500 and isinstance(lineage["production_modified"], bool), "invalid lineage values")

    reviews = value.get("reviews")
    require(isinstance(reviews, list) and len(reviews) <= 50, "invalid reviews")
    for review in reviews:
        require(isinstance(review, dict) and set(review) == {"role", "status", "artifact"}, "invalid specialist review fields")
        require(review["role"] in REVIEW_ROLES and review["status"] in SPECIALIST_STATUSES, "invalid specialist review")
        require(review["artifact"] is None or isinstance(review["artifact"], str) and len(review["artifact"]) <= 500, "invalid specialist artifact")
    require(len({review["role"] for review in reviews}) == len(reviews), "duplicate specialist roles")

    rubric = value.get("rubric")
    require(isinstance(rubric, dict) and set(rubric) == {"items", "total", "maximum", "ten_out_of_ten"}, "invalid rubric fields")
    items = rubric.get("items")
    require(isinstance(items, list) and len(items) == 10, "rubric requires exactly ten items")
    total = 0
    for item in items:
        require(isinstance(item, dict) and set(item) == {"id", "score", "maximum", "evidence"}, "invalid rubric item")
        require(isinstance(item["score"], int) and not isinstance(item["score"], bool) and 0 <= item["score"] <= 10 and item["maximum"] == 10, "invalid rubric score")
        require(isinstance(item["id"], str) and NAME_RE.fullmatch(item["id"]) is not None and isinstance(item["evidence"], str) and 1 <= len(item["evidence"]) <= 1500, "invalid rubric evidence")
        total += item["score"]
    require({item["id"] for item in items} == set(RUBRIC_EVIDENCE_FRAGMENT), "rubric IDs must match the exact governed dimensions")
    require(rubric["maximum"] == 100 and rubric["total"] == total, "rubric total mismatch")
    require(rubric["ten_out_of_ten"] is (total == 100), "rubric ten_out_of_ten mismatch")
    for field in ("blockers", "warnings"):
        require(isinstance(value.get(field), list) and len(value[field]) <= 100 and all(isinstance(x, str) and 1 <= len(x) <= 1500 for x in value[field]), f"invalid {field}")

    ready = value["promotion"] == "HUMAN_REVIEW_PENDING"
    if ready:
        require(value["execution"] == "SUCCESS", "human review pending requires successful execution")
        require(value["review"] == "PASS", "human review pending requires review PASS")
        require(value["blockers"] == [], "human review pending cannot have blockers")
        require(lineage["candidate_commit"] is not None and lineage["production_modified"] is False, "human review pending requires protected candidate lineage")
        by_gate = {gate["name"]: gate for gate in gates}
        require(set(by_gate) == CORE_GATES and all(gate["status"] == "PASS" for gate in gates), "human review pending requires exact core gates PASS")
        by_role = {review["role"]: review for review in reviews}
        require(len(reviews) == len(REVIEW_ROLES) and set(by_role) == REVIEW_ROLES and all(review["status"] == "PASS" for review in reviews), "human review pending requires exactly one PASS per specialist and final QA")
        for role, review in by_role.items():
            artifact = review["artifact"]
            require(isinstance(artifact, str) and (artifact == "final_qa.json" if role == "final_qa" else artifact.startswith(f"roles/{role}/") and artifact.endswith("/final.json")), "human review pending requires exact final review artifact paths")
        require(rubric["total"] == 100 and rubric["ten_out_of_ten"] is True, "human review pending requires rubric 100")
    if value["blockers"]:
        require(value["review"] != "PASS" or value["promotion"] != "HUMAN_REVIEW_PENDING", "blockers contradict ready review state")
    return value


def resolve_run(artifact_root: Path, run_id: str | None = None) -> tuple[str, Path, dict[str, Any]]:
    try:
        root = _validate_ancestors(artifact_root)
    except (OSError, RuntimeError) as exc:
        raise OperatorError(f"artifact root is missing or unsafe: {artifact_root}") from exc
    latest_path = root / "latest.json"
    latest = read_json(latest_path, "latest controller state") if latest_path.is_file() else {}
    latest_run = latest.get("run_id")
    if run_id is None and (not isinstance(latest_run, str) or not latest_run):
        raise OperatorError("latest controller state has no unambiguous run_id")
    selected = run_id or latest_run
    if not isinstance(selected, str) or not selected or Path(selected).name != selected:
        raise OperatorError(f"invalid run id: {selected!r}")
    candidate_run_dir = root / selected
    _validate_ancestors(candidate_run_dir)
    run_dir = candidate_run_dir.resolve()
    if root not in run_dir.parents or not run_dir.is_dir() or run_dir.is_symlink():
        raise OperatorError(f"selected run directory is missing or unsafe: {run_dir}")
    return selected, run_dir, latest


def load_operator_record(artifact_root: Path, run_id: str | None = None) -> tuple[dict[str, Any], dict[str, Any], Path]:
    selected, run_dir, latest = resolve_run(artifact_root, run_id)
    decision = read_json(run_dir / "operator_decision.json", "operator decision")
    validate_operator_decision(decision)
    if decision.get("run_id") != selected:
        raise OperatorError("operator decision run_id does not match the selected run", EXIT_TAMPERED)
    return decision, latest, run_dir


def status_record(artifact_root: Path) -> tuple[dict[str, Any], int]:
    verify_record(artifact_root)
    decision, _, _ = load_operator_record(artifact_root)
    decision = {
        **decision,
        "host_acl_recovery": recovery_status(artifact_root),
        "host_container_recovery": container_recovery_status(artifact_root),
    }
    execution = decision["execution"]
    blocked = (
        execution != "SUCCESS"
        or bool(decision["blockers"])
        or decision["host_acl_recovery"]["status"] == "RECOVERY_REQUIRED"
        or decision["host_container_recovery"]["status"] == "RECOVERY_REQUIRED"
    )
    return decision, EXIT_BLOCKED if blocked else EXIT_OK


def review_record(artifact_root: Path) -> tuple[dict[str, Any], int]:
    verify_record(artifact_root)
    decision, _, _ = load_operator_record(artifact_root)
    decision = {
        **decision,
        "host_acl_recovery": recovery_status(artifact_root),
        "host_container_recovery": container_recovery_status(artifact_root),
    }
    if decision["execution"] == "SUCCESS" and decision["review"] == "PASS" and decision["promotion"] == "HUMAN_REVIEW_PENDING" and decision["blockers"] == [] and decision["host_acl_recovery"]["status"] != "RECOVERY_REQUIRED" and decision["host_container_recovery"]["status"] != "RECOVERY_REQUIRED":
        return decision, EXIT_OK
    return decision, EXIT_BLOCKED


def recovery_status(artifact_root: Path) -> dict[str, Any]:
    root = artifact_root.resolve()
    latest_path = root / "acl_recovery_latest.json"
    if not latest_path.exists():
        return {"status": "NO_RECOVERY_EVENTS", "event_id": None, "active_leases": []}
    latest = read_json(latest_path, "ACL recovery latest", EXIT_TAMPERED)
    required = {
        "schema_version", "event_id", "event_path", "status", "ledger_hash", "recovery_manifest_sha256",
        "recovery_decision_sha256", "active_leases",
    }
    if set(latest) != required or latest.get("schema_version") != "blast-pit.acl-recovery-latest.v1" or latest.get("status") not in {"RECOVERED", "RECOVERY_REQUIRED"}:
        raise OperatorError("ACL recovery latest record is invalid", EXIT_TAMPERED)
    event_path = latest.get("event_path")
    if not isinstance(event_path, str) or "\\" in event_path or Path(event_path).is_absolute() or ".." in Path(event_path).parts:
        raise OperatorError("ACL recovery event path is invalid", EXIT_TAMPERED)
    event_dir = (root / event_path).resolve()
    if root not in event_dir.parents or not event_dir.is_dir() or _is_reparse(event_dir):
        raise OperatorError("ACL recovery event directory is missing or unsafe", EXIT_TAMPERED)
    manifest = event_dir / "recovery_manifest.json"
    decision = event_dir / "recovery_decision.json"
    if not manifest.is_file() or manifest.is_symlink() or not decision.is_file() or decision.is_symlink():
        raise OperatorError("ACL recovery sealed event files are missing or unsafe", EXIT_TAMPERED)
    if sha256_file(manifest) != latest.get("recovery_manifest_sha256") or sha256_file(decision) != latest.get("recovery_decision_sha256"):
        raise OperatorError("ACL recovery latest hashes disagree with the sealed event", EXIT_TAMPERED)
    manifest_record = read_json(manifest, "ACL recovery manifest", EXIT_TAMPERED)
    decision_record = read_json(decision, "ACL recovery decision", EXIT_TAMPERED)
    files = manifest_record.get("files")
    tree_files, _ = _strict_tree(event_dir)
    actual = {item for item in tree_files if item != "recovery_manifest.json"}
    if (
        manifest_record.get("event_id") != latest.get("event_id")
        or manifest_record.get("status") != latest.get("status")
        or decision_record.get("event_id") != latest.get("event_id")
        or decision_record.get("status") != latest.get("status")
        or not isinstance(files, dict)
        or set(files) != actual
    ):
        raise OperatorError("ACL recovery sealed event identity or file set is invalid", EXIT_TAMPERED)
    for relative, descriptor in files.items():
        path = event_dir / relative
        if (
            not isinstance(descriptor, dict)
            or not path.is_file()
            or path.is_symlink()
            or descriptor.get("bytes") != path.stat().st_size
            or descriptor.get("sha256") != sha256_file(path)
        ):
            raise OperatorError(f"ACL recovery sealed file mismatch: {relative}", EXIT_TAMPERED)
    ledger_path = root / "acl_recovery_ledger.jsonl"
    if not ledger_path.is_file() or ledger_path.is_symlink() or ledger_path.stat().st_size > MAX_JSON_BYTES:
        raise OperatorError("ACL recovery ledger is missing or unsafe", EXIT_TAMPERED)
    previous = "0" * 64; sequence = 0; selected = None
    for number, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OperatorError(f"ACL recovery ledger JSON is invalid at line {number}", EXIT_TAMPERED) from exc
        supplied = row.get("ledger_hash"); unsigned = dict(row); unsigned.pop("ledger_hash", None)
        calculated = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if row.get("sequence") != sequence + 1 or row.get("previous_ledger_hash") != previous or supplied != calculated:
            raise OperatorError(f"ACL recovery ledger chain mismatch at line {number}", EXIT_TAMPERED)
        sequence += 1; previous = supplied
        if row.get("event_id") == latest.get("event_id"):
            selected = row
    if selected is None or selected.get("ledger_hash") != latest.get("ledger_hash") or selected.get("status") != latest.get("status"):
        raise OperatorError("ACL recovery latest record is not anchored in its ledger", EXIT_TAMPERED)
    active = latest.get("active_leases")
    if not isinstance(active, list) or not all(isinstance(item, str) for item in active):
        raise OperatorError("ACL recovery active-lease list is invalid", EXIT_TAMPERED)
    if (latest["status"] == "RECOVERED") is bool(active):
        raise OperatorError("ACL recovery status contradicts its active-lease list", EXIT_TAMPERED)
    return {"status": latest["status"], "event_id": latest["event_id"], "active_leases": active}


def container_recovery_status(artifact_root: Path) -> dict[str, Any]:
    root = artifact_root.resolve()
    latest_path = root / "container_recovery_latest.json"
    if not latest_path.exists():
        return {"status": "NO_RECOVERY_EVENTS", "event_id": None}
    latest = read_json(latest_path, "container recovery latest", EXIT_TAMPERED)
    required = {
        "schema_version", "event_id", "event_path", "status", "ledger_hash",
        "recovery_manifest_sha256", "recovery_decision_sha256",
    }
    allowed = {"QUIESCENT", "RECOVERED", "RECOVERY_REQUIRED"}
    if set(latest) != required or latest.get("schema_version") != "blast-pit.container-recovery-latest.v1" or latest.get("status") not in allowed:
        raise OperatorError("container recovery latest record is invalid", EXIT_TAMPERED)
    event_path = latest.get("event_path")
    if not isinstance(event_path, str) or "\\" in event_path or Path(event_path).is_absolute() or ".." in Path(event_path).parts:
        raise OperatorError("container recovery event path is invalid", EXIT_TAMPERED)
    event_dir = (root / event_path).resolve()
    if root not in event_dir.parents or not event_dir.is_dir() or _is_reparse(event_dir):
        raise OperatorError("container recovery event directory is missing or unsafe", EXIT_TAMPERED)
    manifest = event_dir / "recovery_manifest.json"
    decision = event_dir / "recovery_decision.json"
    if not manifest.is_file() or manifest.is_symlink() or not decision.is_file() or decision.is_symlink():
        raise OperatorError("container recovery sealed event files are missing or unsafe", EXIT_TAMPERED)
    if sha256_file(manifest) != latest.get("recovery_manifest_sha256") or sha256_file(decision) != latest.get("recovery_decision_sha256"):
        raise OperatorError("container recovery latest hashes disagree with the sealed event", EXIT_TAMPERED)
    manifest_record = read_json(manifest, "container recovery manifest", EXIT_TAMPERED)
    decision_record = read_json(decision, "container recovery decision", EXIT_TAMPERED)
    files = manifest_record.get("files")
    tree_files, _ = _strict_tree(event_dir)
    actual = {item for item in tree_files if item != "recovery_manifest.json"}
    if (
        manifest_record.get("event_id") != latest.get("event_id")
        or manifest_record.get("status") != latest.get("status")
        or decision_record.get("event_id") != latest.get("event_id")
        or decision_record.get("status") != latest.get("status")
        or not isinstance(files, dict)
        or set(files) != actual
    ):
        raise OperatorError("container recovery sealed event identity or file set is invalid", EXIT_TAMPERED)
    for relative, descriptor in files.items():
        path = event_dir / relative
        if (
            not isinstance(descriptor, dict)
            or not path.is_file()
            or path.is_symlink()
            or descriptor.get("bytes") != path.stat().st_size
            or descriptor.get("sha256") != sha256_file(path)
        ):
            raise OperatorError(f"container recovery sealed file mismatch: {relative}", EXIT_TAMPERED)
    ledger_path = root / "container_recovery_ledger.jsonl"
    if not ledger_path.is_file() or ledger_path.is_symlink() or ledger_path.stat().st_size > MAX_JSON_BYTES:
        raise OperatorError("container recovery ledger is missing or unsafe", EXIT_TAMPERED)
    previous = "0" * 64
    sequence = 0
    selected = None
    for number, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OperatorError(f"container recovery ledger JSON is invalid at line {number}", EXIT_TAMPERED) from exc
        supplied = row.get("ledger_hash")
        unsigned = dict(row)
        unsigned.pop("ledger_hash", None)
        calculated = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if row.get("sequence") != sequence + 1 or row.get("previous_ledger_hash") != previous or supplied != calculated:
            raise OperatorError(f"container recovery ledger chain mismatch at line {number}", EXIT_TAMPERED)
        sequence += 1
        previous = supplied
        if row.get("event_id") == latest.get("event_id"):
            selected = row
    if selected is None or selected.get("ledger_hash") != latest.get("ledger_hash") or selected.get("status") != latest.get("status"):
        raise OperatorError("container recovery latest record is not anchored in its ledger", EXIT_TAMPERED)
    return {"status": latest["status"], "event_id": latest["event_id"]}


def verify_record(artifact_root: Path, run_id: str | None = None) -> dict[str, Any]:
    selected, run_dir, latest = resolve_run(artifact_root, run_id)
    manifest_path = run_dir / "evidence_manifest.json"
    manifest = read_json(manifest_path, "evidence manifest", EXIT_TAMPERED)
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise OperatorError("evidence manifest files must be an object", EXIT_TAMPERED)

    expected = set(files)
    if "evidence_manifest.json" in expected:
        raise OperatorError("evidence manifest must exclude itself", EXIT_TAMPERED)
    tree_files, tree_directories = _strict_tree(run_dir)
    actual = {relative for relative in tree_files if relative != "evidence_manifest.json"}
    expected_directories: set[str] = set()
    for relative in expected:
        parent = Path(relative).parent
        while parent != Path("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    failures: list[str] = []
    if missing:
        failures.append(f"missing retained files: {missing}")
    if extra:
        failures.append(f"extra retained files: {extra}")
    extra_directories = sorted(tree_directories - expected_directories)
    if extra_directories:
        failures.append(f"extra retained directories: {extra_directories}")

    for relative in sorted(expected & actual):
        descriptor = files[relative]
        path = run_dir / relative
        if not isinstance(descriptor, dict) or descriptor.get("kind", "file") != "file" or path.is_symlink():
            failures.append(f"unsafe or invalid manifest entry: {relative}")
            continue
        size = path.stat().st_size
        if descriptor.get("bytes") != size:
            failures.append(f"size mismatch: {relative}")
        if descriptor.get("sha256") != sha256_file(path):
            failures.append(f"SHA-256 mismatch: {relative}")

    state = read_json(run_dir / "state.json", "run state", EXIT_TAMPERED)
    production = read_json(run_dir / "production_guard.json", "production guard", EXIT_TAMPERED)
    decision = validate_operator_decision(read_json(run_dir / "operator_decision.json", "operator decision", EXIT_TAMPERED))
    if manifest.get("run_id") != selected or state.get("run_id") != selected or decision.get("run_id") != selected:
        failures.append("run_id disagreement across manifest, state, and operator decision")
    manifest_status = manifest.get("status")
    state_status = state.get("status")
    if manifest_status != state_status:
        failures.append("status disagreement across manifest and state")
    execution_map = {"SUCCESS": {"COMPLETE", "COMPLETE_WITH_REJECTIONS", "SUCCESS"}, "FAILED": {"ERROR", "FAILED", "COMPLETE_WITH_ERRORS"}, "TIMEOUT": {"TIMEOUT"}, "KILLED": {"KILLED"}, "RUNNING": {"RUNNING", "BASELINE_EVALUATING"}, "NOT_RUN": {"NOT_RUN", "DRY_RUN_COMPLETE"}}
    if state_status not in execution_map[decision["execution"]]:
        failures.append("operator execution status disagrees with controller state")
    if production.get("pass") is not True:
        failures.append("production guard did not pass")
    if decision["lineage"]["production_modified"] is not False:
        failures.append("operator decision reports production modification")

    try:
        for gate in decision["cycle_gates"]:
            if gate["status"] == "PASS":
                _evidence_reference(run_dir, expected, gate.get("evidence"), f"gate {gate['name']}")
        for item in decision["rubric"]["items"]:
            if item["score"] == 10:
                _evidence_reference(run_dir, expected, item.get("evidence"), f"rubric item {item['id']}")
                fragment = RUBRIC_EVIDENCE_FRAGMENT.get(item["id"])
                if fragment is None or fragment not in item["evidence"]:
                    failures.append(f"rubric item cites unrelated evidence: {item['id']}")
        for review in decision["reviews"]:
            if review["status"] != "PASS":
                continue
            path = _evidence_reference(run_dir, expected, review.get("artifact"), f"review {review['role']}")
            value = read_json(path, f"review {review['role']}", EXIT_TAMPERED)
            if value.get("diff_sha256") != decision["lineage"].get("diff_sha256") or value.get("verdict") != "PASS":
                failures.append(f"review artifact identity/verdict mismatch: {review['role']}")
            if review["role"] == "final_qa":
                if value.get("schema_version") != "codex.final-qa.v2" or value.get("blockers") != []:
                    failures.append("final QA artifact is not a blocker-free v2 PASS")
            elif value.get("schema_version") != "codex.specialist-review.v2" or value.get("role") != review["role"] or value.get("findings") != []:
                failures.append(f"specialist artifact role/findings mismatch: {review['role']}")
    except OperatorError as exc:
        failures.append(str(exc))

    transitions = run_dir / "transitions.jsonl"
    if not transitions.is_file() or transitions.is_symlink():
        failures.append("transition journal is missing or unsafe")
    else:
        previous = "0" * 64; revision = 0; final_transition = None
        for number, line in enumerate(transitions.read_text(encoding="utf-8").splitlines(), 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                failures.append(f"invalid transition JSON at line {number}"); break
            supplied = row.get("transition_hash"); unsigned = dict(row); unsigned.pop("transition_hash", None)
            calculated = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            if row.get("revision") != revision + 1 or row.get("previous_transition_hash") != previous or supplied != calculated:
                failures.append(f"transition chain mismatch at line {number}"); break
            revision += 1; previous = supplied; final_transition = row
        if final_transition is None:
            failures.append("transition journal contains no valid transitions")
        else:
            if state.get("revision") != revision or state.get("last_transition_hash") != previous or state.get("status") != final_transition.get("state"):
                failures.append("final transition hash/revision/status disagrees with state")

    previous_cycle_hash = "0" * 64
    cycle_directories = sorted(path for path in run_dir.iterdir() if path.is_dir() and path.name.startswith("cycle_"))
    expected_cycle_names = [f"cycle_{number:03d}" for number in range(1, len(cycle_directories) + 1)]
    if [path.name for path in cycle_directories] != expected_cycle_names:
        failures.append("cycle directories are duplicated, malformed, or non-contiguous")
    for cycle_number, cycle_directory in enumerate(cycle_directories, 1):
        nested = cycle_directory / "cycle_manifest.json"
        if not nested.is_file() or nested.is_symlink():
            failures.append(f"cycle manifest is missing or unsafe: {cycle_directory.name}")
            continue
        nested_manifest = read_json(nested, "cycle manifest", EXIT_TAMPERED)
        if nested_manifest.get("cycle") != cycle_number:
            failures.append(f"cycle manifest number mismatch: {cycle_directory.name}")
        nested_files = nested_manifest.get("files")
        if not isinstance(nested_files, dict):
            failures.append(f"cycle manifest files must be an object: {nested.relative_to(run_dir).as_posix()}")
            continue
        nested_tree_files, nested_tree_directories = _strict_tree(nested.parent)
        actual_nested = {relative for relative in nested_tree_files if relative != "cycle_manifest.json"}
        if set(nested_files) != actual_nested:
            failures.append(f"cycle manifest file set mismatch: {nested.relative_to(run_dir).as_posix()}")
        nested_expected_directories: set[str] = set()
        for relative in nested_files:
            parent = Path(relative).parent
            while parent != Path("."):
                nested_expected_directories.add(parent.as_posix())
                parent = parent.parent
        if nested_tree_directories - nested_expected_directories:
            failures.append(f"cycle manifest contains unsealed directories: {nested.relative_to(run_dir).as_posix()}")
        if nested_manifest.get("previous_cycle_manifest_sha256") != previous_cycle_hash:
            failures.append(f"cycle manifest chain mismatch: {nested.relative_to(run_dir).as_posix()}")
        for relative, descriptor in nested_files.items():
            path = nested.parent / relative
            if not path.is_file() or path.is_symlink():
                failures.append(f"cycle manifest missing or unsafe file: {path.relative_to(run_dir).as_posix()}")
            elif not isinstance(descriptor, dict) or descriptor.get("bytes") != path.stat().st_size or descriptor.get("sha256") != sha256_file(path):
                failures.append(f"cycle manifest mismatch: {path.relative_to(run_dir).as_posix()}")
        previous_cycle_hash = sha256_file(nested)
    transition_files = [path.relative_to(run_dir).as_posix() for path in run_dir.rglob("*") if path.is_file() and "transition" in path.name.lower()]
    for relative in transition_files:
        if relative not in expected:
            failures.append(f"unsealed transition evidence: {relative}")
    if selected == latest.get("run_id"):
        latest_hash = latest.get("evidence_manifest_sha256")
        if latest_hash != sha256_file(manifest_path):
            failures.append("latest state evidence manifest SHA-256 mismatch")
        if latest.get("operator_decision_sha256") != sha256_file(run_dir / "operator_decision.json"):
            failures.append("latest state operator decision SHA-256 mismatch")
    elif run_id is None:
        failures.append("latest state does not identify the selected run")

    try:
        ledger_entry, ledger_tip = _local_ledger_entry(artifact_root.resolve(), selected)
        if ledger_entry.get("evidence_manifest_sha256") != sha256_file(manifest_path):
            failures.append("local audit ledger evidence-manifest hash mismatch")
        if ledger_entry.get("operator_decision_sha256") != sha256_file(run_dir / "operator_decision.json"):
            failures.append("local audit ledger operator-decision hash mismatch")
        if selected == latest.get("run_id") and latest.get("ledger_hash") != ledger_entry.get("ledger_hash"):
            failures.append("latest state local-ledger hash mismatch")
    except OperatorError as exc:
        failures.append(str(exc))

    if failures:
        raise OperatorError("evidence verification failed: " + "; ".join(failures), EXIT_TAMPERED)
    return {
        "run_id": selected,
        "verified": True,
        "file_count": len(expected),
        "manifest_sha256": sha256_file(manifest_path),
        "production_guard_pass": True,
        "execution_status": state_status,
        "host_acl_recovery": recovery_status(artifact_root),
        "host_container_recovery": container_recovery_status(artifact_root),
    }


def print_bluf(mode: str, record: dict[str, Any]) -> None:
    if mode == "verify":
        host = record.get("host_acl_recovery", {"status": "UNKNOWN"})
        container = record.get("host_container_recovery", {"status": "UNKNOWN"})
        print(f"BLUF: VERIFIED run {record['run_id']} ({record['file_count']} retained files; production guard PASS); host ACL recovery {host['status']}; container recovery {container['status']}.")
        return
    lineage = record["lineage"]
    disposition = "READY_FOR_HUMAN_REVIEW" if record["promotion"] == "HUMAN_REVIEW_PENDING" and record["review"] == "PASS" and not record["blockers"] else "BLOCKED"
    commit = lineage.get("candidate_commit") or "none"
    blockers = record.get("blockers") or []
    print(f"BLUF: {disposition}; run {record['run_id']}; execution {record['execution']}; review commit {commit}.")
    if blockers:
        print("Blockers: " + " | ".join(str(item) for item in blockers))
    host = record.get("host_acl_recovery")
    if isinstance(host, dict):
        print(f"Host ACL recovery: {host.get('status')} (event {host.get('event_id') or 'none'}).")
    container = record.get("host_container_recovery")
    if isinstance(container, dict):
        print(f"Host container recovery: {container.get('status')} (event {container.get('event_id') or 'none'}).")
    print("Next authorized action: " + ("HUMAN_REVIEW" if disposition == "READY_FOR_HUMAN_REVIEW" else "REMEDIATE"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Blast_Pit improvement operator")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "review"):
        item = sub.add_parser(name)
        item.add_argument("--artifact-root", type=Path, required=True)
        item.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("--artifact-root", type=Path, required=True)
    verify.add_argument("--run-id")
    verify.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            record, code = status_record(args.artifact_root)
        elif args.command == "review":
            record, code = review_record(args.artifact_root)
        else:
            record = verify_record(args.artifact_root, args.run_id)
            code = EXIT_BLOCKED if (
                record.get("host_acl_recovery", {}).get("status") == "RECOVERY_REQUIRED"
                or record.get("host_container_recovery", {}).get("status") == "RECOVERY_REQUIRED"
            ) else EXIT_OK
        if args.json:
            print(json.dumps(record, indent=2, sort_keys=True))
        else:
            print_bluf(args.command, record)
        return code
    except OperatorError as exc:
        print(f"[improvement-operator] {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
