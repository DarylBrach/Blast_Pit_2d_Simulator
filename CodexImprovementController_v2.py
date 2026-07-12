from __future__ import annotations

"""Governed, candidate-only, multi-specialist improvement controller.

The controller never pushes, merges, releases, or changes the protected checkout.
Codex roles are tool-less and receive only bounded inline packets. Candidate
patches are applied through the qualified Windows write boundary; every
candidate-controlled Python path executes in an authorization-bound Linux
container with no network and only one disposable host mount.
"""

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import CodexImprovementController_v1 as legacy
import improvement_harness_runtime_v2 as runtime
import improvement_operator


VERSION = "2.2.0"
AUTH_SCHEMA = "blast-pit.codex-improvement-authorization.v2"
MODEL_DEFAULT = "gpt-5.5"
ALLOWED_CHANGED_FILES = {"tmp_2d_simulator_v37.py", "test_tmp_2d_simulator_v37.py"}
ROLES = (
    "architecture_state",
    "algorithm_objective",
    "workflow_state",
    "governance_evidence",
    "security_sandbox",
    "testing_reliability",
    "docs_ux",
)
CRITERIA = {
    "architecture_state": ("control_flow", "compatibility", "state_invariants"),
    "algorithm_objective": ("objective_semantics", "category", "holdout_isolation"),
    "workflow_state": ("transitions", "timeout_recovery", "resume_integrity"),
    "governance_evidence": ("authority", "evidence_binding", "production_guard"),
    "security_sandbox": ("path_containment", "external_writes", "forbidden_primitives"),
    "testing_reliability": ("regression", "determinism", "fault_injection"),
    "docs_ux": ("operator_clarity", "recovery_guidance", "claims_accuracy"),
}
FINDING_PREFIX = {
    "architecture_state": "ARCH",
    "algorithm_objective": "ALGO",
    "workflow_state": "FLOW",
    "governance_evidence": "GOV",
    "security_sandbox": "SEC",
    "testing_reliability": "TEST",
    "docs_ux": "DOC",
}
FINAL_QA_CRITERIA = (
    "authorization",
    "sandbox",
    "source_scope",
    "compile",
    "focused_tests",
    "full_tests",
    "specialist_consensus",
    "evaluation",
    "evidence_integrity",
    "production_guard",
    "authority_boundary",
    "documentation",
)
CORE_GATES = (
    "authorization",
    "sandbox_canary",
    "external_guard",
    "filesystem",
    "security",
    "compile",
    "focused_tests",
    "full_tests",
    "specialist_consensus",
    "evaluation",
    "final_qa",
    "production_guard",
)
RUBRIC_IDS = (
    "architecture",
    "workflow",
    "security",
    "algorithm",
    "determinism",
    "testing",
    "evaluation",
    "evidence",
    "maintainability",
    "specialist_consensus",
)
TERMINAL_STATES = {
    "COMPLETE",
    "COMPLETE_WITH_REJECTIONS",
    "COMPLETE_WITH_ERRORS",
    "DRY_RUN_COMPLETE",
    "ERROR",
    "TIMEOUT",
}
CONTROL_PATHS = {
    "controller_source_sha256": "CodexImprovementController_v2.py",
    "runtime_source_sha256": "improvement_harness_runtime_v2.py",
    "v1_controller_source_sha256": "CodexImprovementController_v1.py",
    "candidate_driver_source_sha256": "improvement_candidate_driver.py",
    "candidate_driver_v2_source_sha256": "improvement_candidate_driver_v2.py",
    "candidate_export_source_sha256": "improvement_candidate_export.py",
    "v2_scorer_source_sha256": "improvement_score_checkpoint_v2.py",
    "operator_source_sha256": "improvement_operator.py",
    "supervisor_source_sha256": "CodexLightRunner_v3.py",
    "launcher_source_sha256": "run_codex_improvement_monitor.ps1",
    "launcher_bat_source_sha256": "run_codex_improvement_monitor.bat",
    "canary_source_sha256": "improvement_sandbox_canary.py",
    "candidate_guard_source_sha256": "improvement_candidate_guard.py",
    "container_canary_source_sha256": "improvement_container_canary.py",
    "container_policy_source_sha256": "candidate_container_policy_v1.json",
    "candidate_dockerfile_source_sha256": "Dockerfile.candidate",
    "candidate_lock_source_sha256": "requirements-candidate.lock",
    "candidate_image_builder_source_sha256": "build_candidate_container.ps1",
    "candidate_image_attestation_source_sha256": "candidate_image_attestation_v1.json",
    "acl_helper_source_sha256": "improvement_acl_helper.ps1",
    "simulator_source_sha256": "tmp_2d_simulator_v37.py",
    "simulator_v36_source_sha256": "tmp_2d_simulator_v36.py",
    "simulator_v35_source_sha256": "tmp_2d_simulator_v35.py",
    "simulator_test_source_sha256": "test_tmp_2d_simulator_v37.py",
    "development_seed_sha256": "improvement_dev_seeds_v1.txt",
    "build_schema_sha256": "schemas/codex_build_result_v2.schema.json",
    "review_schema_sha256": "schemas/specialist_review_v2.schema.json",
    "final_qa_schema_sha256": "schemas/final_qa_v2.schema.json",
    "operator_schema_sha256": "schemas/improvement_operator_decision_v2.schema.json",
}
FORBIDDEN_ADDED_PATTERNS = (
    re.compile(r"\b(?:import|from)\s+(?:subprocess|socket|requests|urllib|httpx|winreg|ctypes|multiprocessing)\b"),
    re.compile(r"\b(?:open|exec|eval|compile|__import__)\s*\("),
    re.compile(r"\.(?:read_text|read_bytes|write_text|write_bytes|open)\s*\("),
    re.compile(r"\bos\.(?:environ|getenv|system|popen|spawn|walk|listdir|scandir|remove|unlink|rename|replace|mkdir|makedirs|rmdir)\b"),
    re.compile(r"\b(?:shutil|tempfile|pickle|marshal)\."),
    re.compile(r"(?i)(?:\.codex|auth\.json|terminal_audit|audit_seeds|approval_v37|artifacts[/\\]v37|https?://|git\s+(?:push|merge))"),
)
PROTECTED_REMOVAL_PATTERNS = (
    re.compile(r"\b(?:load_approval|validate_approval|canonical_source_sha256|validate_generation_journal)\b"),
    re.compile(r"(?i)\b(?:audit|export|release_authorized|authorization)\b"),
)


class V2Error(RuntimeError):
    """Fail-closed controller error."""


class CandidateRejected(V2Error):
    """A bounded candidate failed a candidate-quality gate."""


@dataclass(frozen=True)
class Config:
    repo: Path
    python: Path
    codex: Path
    docker: Path
    authorization: Path
    artifact_root: Path
    worktree_root: Path
    evaluator: Path
    real_codex_home: Path
    model: str
    cycles: int
    max_runtime_seconds: int
    role_timeout_seconds: int
    command_timeout_seconds: int
    evaluation_timeout_seconds: int
    remediation_cap: int
    max_parallel_specialists: int
    max_diff_bytes: int
    sandbox_implementation: str
    dry_run: bool
    resume_run: str | None
    recover_only: bool = False

    # Compatibility properties for the small, read-only v1 Git/protection helpers.
    @property
    def max_runtime(self) -> int:
        return self.max_runtime_seconds

    @property
    def role_timeout(self) -> int:
        return self.role_timeout_seconds

    @property
    def command_timeout(self) -> int:
        return self.command_timeout_seconds

    @property
    def test_timeout_seconds(self) -> int:
        return self.command_timeout_seconds


@dataclass
class CycleOutcome:
    cycle: int
    status: str
    execution: str
    base_commit: str
    worktree: str
    gates: dict[str, dict[str, Any]]
    candidate_commit: str | None = None
    diff_sha256: str | None = None
    category: str | None = None
    reviews: list[dict[str, Any]] = field(default_factory=list)
    review_artifacts: dict[str, str] = field(default_factory=dict)
    final_qa: dict[str, Any] | None = None
    rubric: dict[str, Any] | None = None
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    baseline_checkpoint: Path | None = None
    candidate_checkpoint: Path | None = None
    evaluation: dict[str, Any] | None = None
    raw_evaluation: dict[str, Any] | None = None
    private_fold: Path | None = None
    private_fold_record: dict[str, Any] | None = None
    mandatory_findings: list[str] = field(default_factory=list)
    manifest_sha256: str | None = None


@dataclass
class ActiveRunContext:
    config: Config
    run_dir: Path
    journal: "Journal"
    base_commit: str
    protected_snapshot: dict[str, Any]
    authorization_sha256: str | None = None
    acl_leases: list[runtime.AclLease] = field(default_factory=list)


_ACTIVE_RUN: ActiveRunContext | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def atomic(path: Path, value: object) -> None:
    runtime.atomic_json(path, value)


def strict_json(path: Path, *, max_bytes: int = 1_000_000) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes:
        raise V2Error(f"missing or unsafe JSON document: {path}")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise V2Error(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(V2Error(f"non-finite JSON value: {item}")),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise V2Error(f"invalid JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise V2Error(f"JSON document must be an object: {path}")
    return value


def validate_schema(path: Path, value: dict[str, Any]) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - installation preflight covers this
        raise V2Error("jsonschema is required for governed v2 validation") from exc
    schema = strict_json(path)
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path) or "<root>"
        raise V2Error(f"schema validation failed at {location}: {exc.message}") from exc


def trusted_environment() -> dict[str, str]:
    allowed = {"APPDATA", "COMSPEC", "LANG", "LC_ALL", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
    result = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    result.update({"PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": ""})
    return result


def remaining_timeout(deadline: float, requested: int) -> int:
    remaining = int(deadline - time.monotonic())
    if remaining < 2:
        raise runtime.RuntimeTimeout("controller runtime budget exhausted")
    return max(1, min(requested, remaining))


def command(
    args: Sequence[str | Path],
    cwd: Path,
    timeout: int,
    *,
    evidence: Path | None = None,
    environment: dict[str, str] | None = None,
    require_success: bool = True,
) -> runtime.ProcessResult:
    result = runtime.run_process(
        args,
        cwd,
        timeout,
        environment=environment or trusted_environment(),
        evidence=evidence,
    )
    if require_success and result.return_code != 0:
        raise runtime.RuntimeFailure(f"command failed with exit {result.return_code}: {result.stderr[-1000:]}")
    return result


def git(
    config: Config,
    args: Sequence[str | Path],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
    evidence: Path | None = None,
    require_success: bool = True,
) -> runtime.ProcessResult:
    forbidden = {"push", "merge", "pull", "fetch"}
    if args and str(args[0]).lower() in forbidden:
        raise V2Error("networking and integration Git operations are outside controller authority")
    return command(["git", *args], cwd or config.repo, timeout, evidence=evidence, require_success=require_success)


def codex_version(config: Config) -> str:
    result = command([config.codex, "--version"], config.repo, 30)
    value = result.stdout.strip()
    if not re.fullmatch(r"codex-cli [0-9]+\.[0-9]+\.[0-9]+", value):
        raise V2Error(f"unrecognized Codex CLI version output: {value!r}")
    return value


def expected_control_hashes(config: Config) -> dict[str, str]:
    return {key: legacy.canonical_text_sha256(config.repo / relative) for key, relative in CONTROL_PATHS.items()}


def load_authorization(config: Config) -> tuple[dict[str, Any], str, str]:
    record = strict_json(config.authorization, max_bytes=128_000)
    version = codex_version(config)
    required = {
        "schema_version": AUTH_SCHEMA,
        "project": "Blast_Pit_2d_Simulator",
        "status": "approved",
        "authority": "human-owner",
        "controller_version": VERSION,
        "automatic_push": False,
        "automatic_merge": False,
        "automatic_release": False,
        "candidate_network_access": False,
        "windows_raw_network_isolation_required": False,
        "candidate_python_audit_guard": False,
        "candidate_execution_boundary": "docker-linux-container",
        "candidate_container_runtime": runtime.CONTAINER_RUNTIME_VERSION,
        "candidate_container_read_only_bind": True,
        "candidate_container_bounded_tmpfs": True,
        "sealed_container_recovery_events": True,
        "candidate_image_attestation": True,
        "acl_child_delete_lease": True,
        "sealed_acl_recovery_events": True,
        "versioned_recovery_helper_archive": True,
        "role_policy_version": runtime.ROLE_POLICY_VERSION,
        "sandbox_implementation": "unelevated",
        "model": config.model,
        "artifact_root": str(config.artifact_root),
        "worktree_root": str(config.worktree_root),
        "codex_cli_version": version,
        "codex_launcher_sha256": legacy.sha256_file(config.codex),
        "docker_executable_sha256": legacy.sha256_file(config.docker),
    }
    if any(record.get(key) != value for key, value in required.items()):
        raise V2Error("v2 authorization scope, tool policy, CLI, model, or root binding mismatch")
    prior_name = record.get("prior_authorization_path")
    if prior_name != "approval_codex_improvement_v1_2.json":
        raise V2Error("v2 authorization prior record is invalid")
    prior = config.repo / prior_name
    if legacy.canonical_text_sha256(prior) != record.get("prior_authorization_sha256"):
        raise V2Error("v2 authorization prior record hash mismatch")
    expected = expected_control_hashes(config)
    if any(record.get(key) != value for key, value in expected.items()):
        raise V2Error("v2 authorization source, schema, or seed binding mismatch")
    if sorted(record.get("allowed_changed_files", [])) != sorted(ALLOWED_CHANGED_FILES):
        raise V2Error("v2 authorization changed-file allowlist mismatch")
    if record.get("specialist_roles") != list(ROLES):
        raise V2Error("v2 authorization specialist role order mismatch")
    if record.get("specialist_criteria") != {key: list(value) for key, value in CRITERIA.items()}:
        raise V2Error("v2 authorization specialist criteria mismatch")
    if record.get("final_qa_criteria") != list(FINAL_QA_CRITERIA):
        raise V2Error("v2 authorization final-QA criteria mismatch")
    source_v36_checkpoint = config.repo / "artifacts" / "v36" / "qdppo-evaluation-001" / "evolution_state_v36.npz"
    if record.get("source_v36_checkpoint_sha256") != legacy.sha256_file(source_v36_checkpoint):
        raise V2Error("v2 authorization source v36 checkpoint hash mismatch")
    image_id = record.get("candidate_image_id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise V2Error("v2 authorization candidate image ID is invalid")
    policy_path = config.repo / "candidate_container_policy_v1.json"
    if record.get("candidate_container_policy_sha256") != legacy.canonical_text_sha256(policy_path):
        raise V2Error("v2 authorization candidate container policy hash mismatch")
    attestation_path = config.repo / "candidate_image_attestation_v1.json"
    if record.get("candidate_image_attestation_sha256") != legacy.canonical_text_sha256(attestation_path):
        raise V2Error("v2 authorization candidate image attestation hash mismatch")
    attestation = strict_json(attestation_path, max_bytes=256_000)
    build_inputs = attestation.get("build_inputs")
    expected_build_inputs = {
        name: legacy.sha256_file(config.repo / name)
        for name in (
            "Dockerfile.candidate",
            "Dockerfile.candidate.dockerignore",
            "requirements-candidate.lock",
            "build_candidate_container.ps1",
        )
    }
    if (
        attestation.get("schema_version") != "blast-pit.candidate-image-attestation.v1"
        or attestation.get("status") != "human-reviewed-local-build"
        or attestation.get("image_id") != image_id
        or build_inputs != expected_build_inputs
        or not isinstance(attestation.get("python_package_sbom"), list)
        or (attestation.get("review_assertions") or {}).get("installed_packages_equal_lock_plus_approved_base_tooling") is not True
    ):
        raise V2Error("candidate image attestation does not bind the reviewed image inputs and SBOM")
    docker_identity = runtime.docker_host_identity(
        docker=config.docker,
        cwd=config.repo,
        environment=trusted_environment(),
        timeout=60,
        image_id=image_id,
    )
    expected_identity = record.get("docker_host_identity")
    if not isinstance(expected_identity, dict) or docker_identity != {"schema_version": "blast-pit.docker-host-identity.v1", **expected_identity}:
        raise V2Error("Docker host or candidate image identity drifted from v2 authorization")
    numeric_bounds = {
        "max_cycles": config.cycles,
        "max_runtime_seconds": config.max_runtime_seconds,
        "max_remediation_rounds": config.remediation_cap,
        "max_parallel_specialists": config.max_parallel_specialists,
        "max_diff_bytes": config.max_diff_bytes,
    }
    if any(isinstance(record.get(key), bool) or not isinstance(record.get(key), int) or record[key] < requested for key, requested in numeric_bounds.items()):
        raise V2Error("requested controller scope exceeds v2 authorization")
    try:
        expires = datetime.fromisoformat(str(record["expires_utc"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise V2Error("v2 authorization expiry is invalid") from exc
    if datetime.now(timezone.utc) >= expires:
        raise V2Error("v2 authorization has expired")
    return record, legacy.canonical_text_sha256(config.authorization), version


class Journal:
    """Append-only transition chain with a projected state document."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.path = run_dir / "transitions.jsonl"
        self.previous = "0" * 64
        self.revision = 0
        self.last_state: str | None = None
        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_size > 8_000_000:
                raise V2Error("transition journal is unsafe")
            for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
                try:
                    row = json.loads(line, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
                except (json.JSONDecodeError, ValueError) as exc:
                    raise V2Error(f"invalid transition JSON at line {number}") from exc
                supplied = row.get("transition_hash")
                unsigned = dict(row)
                unsigned.pop("transition_hash", None)
                if (
                    row.get("revision") != self.revision + 1
                    or row.get("previous_transition_hash") != self.previous
                    or supplied != digest(unsigned)
                ):
                    raise V2Error(f"transition chain invalid at line {number}")
                self.revision += 1
                self.previous = supplied
                self.last_state = row.get("state")

    def add(self, state: str, **details: Any) -> dict[str, Any]:
        if self.last_state in TERMINAL_STATES:
            raise V2Error("terminal transition journal is immutable")
        unsigned = {
            "schema_version": "blast-pit.improvement-transition.v2",
            "revision": self.revision + 1,
            "state": state,
            "timestamp": utc_now(),
            "previous_transition_hash": self.previous,
            "details": details,
        }
        row = {**unsigned, "transition_hash": digest(unsigned)}
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical(row) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.revision += 1
        self.previous = row["transition_hash"]
        self.last_state = state
        atomic(
            self.run_dir / "state.json",
            {
                "schema_version": "blast-pit.improvement-state.v2",
                "run_id": self.run_dir.name,
                "status": state,
                "revision": self.revision,
                "last_transition_hash": self.previous,
                "updated_at": row["timestamp"],
                "details": details,
            },
        )
        return row

    def emergency_terminal(self, state: str, **details: Any) -> dict[str, Any]:
        """Append one corrective terminal only before the run evidence is sealed."""
        if (self.run_dir / "evidence_manifest.json").exists():
            raise V2Error("sealed terminal journal cannot be corrected")
        previous_state = self.last_state
        self.last_state = None
        try:
            return self.add(state, corrected_from=previous_state, emergency=True, **details)
        except Exception:
            self.last_state = previous_state
            raise


def validate_review_consistency(row: dict[str, Any]) -> None:
    failed = any(item.get("pass") is not True for item in row.get("criteria", []))
    findings = bool(row.get("findings"))
    if row.get("verdict") == "PASS" and (failed or findings):
        raise V2Error("PASS review contradicts its criteria or findings")
    if row.get("verdict") != "PASS" and not (failed or findings):
        raise V2Error("non-PASS review lacks actionable evidence")


def verify_review(config: Config, row: dict[str, Any], role: str, diff_sha256: str) -> None:
    validate_schema(config.repo / "schemas" / "specialist_review_v2.schema.json", row)
    if row.get("role") != role or row.get("diff_sha256") != diff_sha256:
        raise V2Error("specialist review identity mismatch")
    if tuple(item.get("id") for item in row.get("criteria", [])) != CRITERIA[role]:
        raise V2Error("specialist criteria order mismatch")
    identifiers: set[str] = set()
    prefix = FINDING_PREFIX[role] + "-"
    for finding in row.get("findings", []):
        identifier = finding["id"]
        if not identifier.startswith(prefix) or identifier in identifiers:
            raise V2Error("specialist finding ID is unstable, duplicated, or role-mismatched")
        identifiers.add(identifier)
        if finding.get("file") not in {None, *ALLOWED_CHANGED_FILES}:
            raise V2Error("specialist finding points outside the candidate allowlist")
    validate_review_consistency(row)


def adjudicate(reviews: Sequence[dict[str, Any]]) -> dict[str, Any]:
    if len(reviews) != len(ROLES):
        raise V2Error("specialist panel is incomplete")
    findings: dict[str, dict[str, Any]] = {}
    for review in reviews:
        for finding in review.get("findings", []):
            identifier = finding["id"]
            if identifier in findings and canonical(findings[identifier]) != canonical(finding):
                raise V2Error("specialists reused one finding ID for conflicting evidence")
            findings[identifier] = finding
    ordered = [findings[key] for key in sorted(findings)]
    mandatory = [item["id"] for item in ordered]
    if any(review.get("verdict") != "PASS" for review in reviews) and not mandatory:
        raise V2Error("non-PASS specialist panel omitted mandatory findings")
    return {
        "schema_version": "codex.adjudication.v2",
        "verdict": "PASS" if not mandatory else "REMEDIATION_REQUIRED",
        "mandatory_finding_ids": mandatory,
        "findings": ordered,
    }


def verify_final_qa(
    config: Config,
    row: dict[str, Any],
    diff_sha256: str,
    mandatory_findings: Sequence[str],
) -> None:
    validate_schema(config.repo / "schemas" / "final_qa_v2.schema.json", row)
    if row.get("diff_sha256") != diff_sha256:
        raise V2Error("final QA diff identity mismatch")
    if tuple(item.get("id") for item in row.get("criteria", [])) != FINAL_QA_CRITERIA:
        raise V2Error("final QA criteria order mismatch")
    dispositions = row.get("finding_dispositions", [])
    if [item.get("finding_id") for item in dispositions] != sorted(set(mandatory_findings)):
        raise V2Error("final QA finding dispositions are incomplete or out of order")
    if any(item.get("status") not in {"RESOLVED", "NOT_APPLICABLE"} for item in dispositions):
        raise V2Error("final QA left a mandatory finding unresolved")
    passed = all(item.get("pass") is True for item in row.get("criteria", []))
    if row.get("verdict") == "PASS" and (not passed or row.get("blockers")):
        raise V2Error("final QA PASS contradicts criteria or blockers")
    if row.get("verdict") != "PASS" and passed and not row.get("blockers"):
        raise V2Error("non-PASS final QA lacks a failed criterion or blocker")


def category_for_diff(diff: str) -> str:
    source_header = "diff --git a/tmp_2d_simulator_v37.py b/tmp_2d_simulator_v37.py"
    return "algorithm" if source_header in diff else "process"


def empty_rubric(reason: str = "candidate did not reach the evidence gate") -> dict[str, Any]:
    return {
        "items": [{"id": item, "score": 0, "maximum": 10, "evidence": reason} for item in RUBRIC_IDS],
        "total": 0,
        "maximum": 100,
        "ten_out_of_ten": False,
    }


def rubric(
    reviews: Sequence[dict[str, Any]],
    gates: dict[str, bool],
    evaluation: dict[str, Any] | None,
    final_qa: dict[str, Any] | None = None,
    evidence: dict[str, str] | None = None,
) -> dict[str, Any]:
    by_role = {review.get("role"): review for review in reviews}
    role_pass = {role: by_role.get(role, {}).get("verdict") == "PASS" for role in ROLES}
    exact_gates = set(gates) == set(CORE_GATES)
    gate = lambda name: exact_gates and gates.get(name) is True
    evaluation_pass = bool(evaluation and evaluation.get("pass") is True)
    final_pass = bool(final_qa and final_qa.get("verdict") == "PASS")
    conditions = {
        "architecture": role_pass["architecture_state"] and gate("filesystem"),
        "workflow": role_pass["workflow_state"] and gate("compile"),
        "security": role_pass["security_sandbox"] and all(gate(name) for name in ("sandbox_canary", "external_guard", "security", "production_guard")),
        "algorithm": role_pass["algorithm_objective"] and evaluation_pass,
        "determinism": role_pass["algorithm_objective"] and role_pass["testing_reliability"] and gate("focused_tests") and evaluation_pass,
        "testing": role_pass["testing_reliability"] and all(gate(name) for name in ("compile", "focused_tests", "full_tests")),
        "evaluation": gate("evaluation") and evaluation_pass,
        "evidence": role_pass["governance_evidence"] and all(gate(name) for name in ("authorization", "external_guard", "production_guard")),
        "maintainability": role_pass["architecture_state"] and role_pass["docs_ux"] and gate("full_tests"),
        "specialist_consensus": all(role_pass.values()) and gate("specialist_consensus") and gate("final_qa") and final_pass,
    }
    evidence = evidence or {}
    items = [
        {
            "id": identifier,
            "score": 10 if conditions[identifier] else 0,
            "maximum": 10,
            "evidence": evidence.get(identifier, f"deterministic conditions: {conditions[identifier]}"),
        }
        for identifier in RUBRIC_IDS
    ]
    total = sum(item["score"] for item in items)
    return {"items": items, "total": total, "maximum": 100, "ten_out_of_ten": total == 100}


def paired_metric_gate(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    category: str,
    remediation_attempts: int = 0,
) -> dict[str, Any]:
    baseline_values = baseline.get("fitness_values")
    candidate_values = candidate.get("fitness_values")
    if (
        baseline.get("fold_sha256") != candidate.get("fold_sha256")
        or not isinstance(baseline_values, list)
        or not isinstance(candidate_values, list)
        or len(baseline_values) != len(candidate_values)
        or len(baseline_values) < 8
    ):
        raise V2Error("hidden-fold pairing mismatch")
    deltas = [float(right) - float(left) for left, right in zip(baseline_values, candidate_values)]
    if not all(math.isfinite(value) for value in deltas):
        raise V2Error("hidden-fold delta is non-finite")
    mean = sum(deltas) / len(deltas)
    variance = sum((value - mean) ** 2 for value in deltas) / max(1, len(deltas) - 1)
    lcb = mean - 1.96 * math.sqrt(variance / len(deltas))
    checks = {
        "cvar": float(candidate["cvar"]) >= float(baseline["cvar"]) - 0.01,
        "mean": float(candidate["mean"]) >= float(baseline["mean"]) - 0.01,
        "standard_mean": float(candidate["standard_mean"]) >= float(baseline["standard_mean"]) - 0.01,
        "challenge_mean": float(candidate["challenge_mean"]) >= float(baseline["challenge_mean"]) - 0.01,
        "early_extinction_rate": float(candidate["early_extinction_rate"]) <= float(baseline["early_extinction_rate"]) + 0.02,
    }
    threshold = 0.005 + 0.001 * remediation_attempts if category == "algorithm" else 0.0
    improvement = category != "algorithm" or (mean >= threshold and lcb >= 0.0)
    return {
        "pass": all(checks.values()) and improvement,
        "paired_mean_delta": mean,
        "paired_lcb95": lcb,
        "required_mean_delta": threshold,
        "non_regression": checks,
        "improvement_required": category == "algorithm",
    }


def gate_template() -> dict[str, dict[str, Any]]:
    return {name: {"name": name, "status": "NOT_RUN", "evidence": None} for name in CORE_GATES}


def set_gate(gates: dict[str, dict[str, Any]], name: str, status: str, evidence: str | None) -> None:
    gates[name] = {"name": name, "status": status, "evidence": evidence}


def gate_bools(gates: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {name: gates.get(name, {}).get("status") == "PASS" for name in CORE_GATES}


def production_snapshot(config: Config) -> dict[str, Any]:
    value = legacy.protection_snapshot(config)
    memory_root = Path.home() / ".codex" / "memories"
    system_temp = Path(tempfile.gettempdir()).resolve()
    temp_entries: dict[str, Any] = {}
    if system_temp.is_dir() and not runtime.is_reparse(system_temp):
        for path in sorted(system_temp.glob("*blast_pit*")):
            if runtime.is_reparse(path):
                temp_entries[path.name] = {"kind": "reparse"}
            elif path.is_dir():
                temp_entries[path.name] = legacy.directory_manifest(path, include_mtime=True)
            elif path.is_file():
                info = path.stat(follow_symlinks=False)
                temp_entries[path.name] = {"bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "sha256": legacy.sha256_file(path)}
    value.update(
        {
            "bound_controls": expected_control_hashes(config),
            "codex_memory": legacy.directory_manifest(memory_root, include_mtime=True),
            "system_temp_blast_pit": temp_entries,
        }
    )
    return value


def compare_protection(before: dict[str, Any], after: dict[str, Any], path: Path) -> bool:
    passed = before == after
    atomic(path, {"pass": passed, "before": before, "after": after})
    return passed


def production_context(config: Config) -> dict[str, Any]:
    path = config.repo / "artifacts" / "v37" / "robustness-v37-8h-001" / "status_v37.json"
    record = strict_json(path)
    allowed = ("generation", "planned_generations", "challenge_cvar", "workflow_state", "hof_policy_hash", "audit_eligible")
    return {key: record.get(key) for key in allowed}


def bounded_source_packet(config: Config, source_root: Path, *, diff: str = "", extra: dict[str, Any] | None = None) -> str:
    chunks = [
        "===== tmp_2d_simulator_v37.py =====\n" + (source_root / "tmp_2d_simulator_v37.py").read_text(encoding="utf-8"),
        "===== test_tmp_2d_simulator_v37.py =====\n" + (source_root / "test_tmp_2d_simulator_v37.py").read_text(encoding="utf-8"),
    ]
    for relative in ("SECURITY.md", "docs/WORKFLOW_STATE_MACHINE.md", "docs/TESTING.md", "docs/CODEX_IMPROVEMENT_LOOP.md"):
        path = config.repo / relative
        if path.is_file():
            chunks.append(f"===== {relative} excerpt =====\n" + path.read_text(encoding="utf-8", errors="strict")[:8_000])
    if diff:
        chunks.append("===== candidate.patch =====\n" + diff)
    if extra:
        chunks.append("===== governed_evidence.json =====\n" + json.dumps(extra, indent=2, sort_keys=True, allow_nan=False))
    packet = "\n\n".join(chunks)
    if len(packet.encode("utf-8")) > 220_000:
        raise V2Error("inline role packet exceeds the authorization bound")
    return packet


def inline_packet(packet: Path, max_chars: int = 220_000) -> str:
    chunks: list[str] = []
    for path in sorted(item for item in packet.rglob("*") if item.is_file()):
        chunks.append(f"\n===== {path.relative_to(packet).as_posix()} =====\n{path.read_text(encoding='utf-8', errors='strict')}")
    value = "".join(chunks)
    if len(value) > max_chars:
        raise V2Error("review packet exceeds inline bound")
    return value


def run_role(
    config: Config,
    *,
    role: str,
    prompt: str,
    schema: Path,
    evidence_dir: Path,
    isolation: Path,
    isolation_root: Path,
    deadline: float,
) -> dict[str, Any]:
    return runtime.run_toolless_codex_role(
        codex=config.codex,
        model=config.model,
        schema=schema,
        prompt=prompt,
        role=role,
        evidence_dir=evidence_dir,
        isolation=isolation,
        isolation_root=isolation_root,
        real_codex_home=config.real_codex_home,
        timeout=remaining_timeout(deadline, config.role_timeout_seconds),
    )


def build_prompt(config: Config, worktree: Path, cycle: int, lessons: Sequence[dict[str, Any]]) -> str:
    safe_lessons = [
        {"cycle": item.get("cycle"), "status": item.get("status"), "reasons": item.get("blockers", [])[:3]}
        for item in lessons[-4:]
    ]
    packet = bounded_source_packet(
        config,
        worktree,
        extra={"cycle": cycle, "production_status": production_context(config), "prior_lessons": safe_lessons},
    )
    return f"""You are the tool-less builder for a governed candidate-only improvement cycle.

Return exactly one codex.build-result.v2 JSON object. You have no tools and must not request tools.
Analyze only the inline packet. Propose one minimal unified Git patch against the current files.
The controller, not you, applies the patch. Allowed paths are exactly:
- tmp_2d_simulator_v37.py
- test_tmp_2d_simulator_v37.py

For an algorithm change, modify the simulator and add/update a focused test. Preserve approval,
audit, export, resume, atomic-write, deterministic-seed, and authority boundaries. Do not add
filesystem discovery, environment access, dynamic execution, subprocess, networking, registry,
or reads of audit/terminal evidence. external_writes must be []; authority_impact must be none.
Use artifact_impact new_lineage_required when behavior changes. finding_ids_addressed must be [].
If no defensible improvement exists, use category no_change, patch "", and changed_files [].

{packet}"""


def verify_build_result(
    config: Config,
    row: dict[str, Any],
    *,
    mandatory_findings: Sequence[str] = (),
) -> None:
    validate_schema(config.repo / "schemas" / "codex_build_result_v2.schema.json", row)
    if row.get("external_writes") != [] or row.get("authority_impact") != "none":
        raise V2Error("tool-less build result claimed an external write or authority impact")
    if sorted(set(row.get("changed_files", []))) != row.get("changed_files", []):
        raise V2Error("build result changed_files must be sorted and unique")
    if any(path not in ALLOWED_CHANGED_FILES for path in row.get("changed_files", [])):
        raise V2Error("build result changed file is outside the allowlist")
    if sorted(row.get("finding_ids_addressed", [])) != sorted(set(mandatory_findings)):
        raise V2Error("build result finding dispositions do not match mandatory remediation")
    no_change = row.get("category") == "no_change"
    if no_change != (not row.get("patch") and not row.get("changed_files")):
        raise V2Error("no-change build semantics are inconsistent")
    if not no_change and row.get("artifact_impact") not in {"new_lineage_required", "schema_compatible"}:
        raise V2Error("changed behavior lacks an explicit candidate-lineage impact")


def specialist_prompt(role: str, diff_sha256: str, packet: str) -> str:
    criteria = ", ".join(CRITERIA[role])
    prefix = FINDING_PREFIX[role]
    return f"""Act as the independent {role} specialist. This is a tool-less evidence review.
Do not request tools. Evaluate exactly these criteria in this order: {criteria}.
Return exactly one codex.specialist-review.v2 JSON object for diff_sha256 {diff_sha256}.
Every finding ID must use {prefix}-NNN and be actionable. PASS requires every criterion PASS and
zero findings. Treat unsupported claims, missing evidence, authority expansion, hidden-fold
adaptation, sandbox escape primitives, or inadequate tests as CHANGES_REQUIRED or BLOCK.

{packet}"""


def final_qa_prompt(diff_sha256: str, packet: str, mandatory_findings: Sequence[str]) -> str:
    criteria = ", ".join(FINAL_QA_CRITERIA)
    return f"""Act as independent final QA for a governed candidate. You are tool-less; do not request tools.
Return exactly one codex.final-qa.v2 JSON object for diff_sha256 {diff_sha256}.
Evaluate exactly these criteria in this order: {criteria}.
Provide one sorted finding_disposition for each of: {json.dumps(sorted(set(mandatory_findings)))}.
Only RESOLVED or NOT_APPLICABLE dispositions may accompany PASS. PASS requires all criteria true,
no blockers, a 10/10 deterministic rubric basis, no production mutation, and no automatic promotion.

{packet}"""


def run_specialist_panel(
    config: Config,
    *,
    packet: str,
    diff_sha256: str,
    evidence_root: Path,
    isolation_root: Path,
    attempt_name: str,
    deadline: float,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    schema = config.repo / "schemas" / "specialist_review_v2.schema.json"

    def one(role: str) -> tuple[str, dict[str, Any], str]:
        evidence = evidence_root / role / attempt_name
        isolation = isolation_root / f"{role}-{attempt_name}"
        row = run_role(
            config,
            role=role,
            prompt=specialist_prompt(role, diff_sha256, packet),
            schema=schema,
            evidence_dir=evidence,
            isolation=isolation,
            isolation_root=isolation_root,
            deadline=deadline,
        )
        verify_review(config, row, role, diff_sha256)
        return role, row, evidence.relative_to(evidence_root.parent).as_posix() + "/final.json"

    with ThreadPoolExecutor(max_workers=config.max_parallel_specialists) as pool:
        values = list(pool.map(one, ROLES))
    by_role = {role: (row, artifact) for role, row, artifact in values}
    return [by_role[role][0] for role in ROLES], {role: by_role[role][1] for role in ROLES}


def current_diff(config: Config, worktree: Path, deadline: float) -> str:
    result = git(
        config,
        ["-c", f"safe.directory={worktree.resolve()}", "-C", worktree, "diff", "--no-ext-diff", "--binary", "--", *sorted(ALLOWED_CHANGED_FILES)],
        timeout=remaining_timeout(deadline, config.command_timeout_seconds),
    )
    return result.stdout


def diff_policy_reasons(diff: str, paths: Sequence[str]) -> list[str]:
    reasons: list[str] = []
    if "tmp_2d_simulator_v37.py" in paths and "test_tmp_2d_simulator_v37.py" not in paths:
        reasons.append("algorithm change did not add or update a focused v37 test")
    added = [line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    removed = [line[1:] for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
    for line in added:
        for pattern in FORBIDDEN_ADDED_PATTERNS:
            if pattern.search(line):
                reasons.append(f"forbidden added primitive matched {pattern.pattern!r}")
    for line in removed:
        for pattern in PROTECTED_REMOVAL_PATTERNS:
            if pattern.search(line):
                reasons.append(f"protected governance behavior removal matched {pattern.pattern!r}")
    return sorted(set(reasons))


def static_candidate_gate(config: Config, worktree: Path, baseline_manifest: dict[str, Any], attempt_dir: Path, deadline: float) -> tuple[str, str, str]:
    attempt_dir.mkdir(parents=True, exist_ok=False)
    diff = current_diff(config, worktree, deadline)
    reasons: list[str] = []
    try:
        paths = runtime.parse_patch_paths(diff, ALLOWED_CHANGED_FILES, config.max_diff_bytes)
    except runtime.RuntimeFailure as exc:
        paths = []
        reasons.append(str(exc))
    status = git(
        config,
        ["-c", f"safe.directory={worktree.resolve()}", "-C", worktree, "status", "--porcelain=v1", "--untracked-files=all"],
        timeout=remaining_timeout(deadline, config.command_timeout_seconds),
    ).stdout.splitlines()
    unexpected_status = [line for line in status if line[3:].replace("\\", "/") not in ALLOWED_CHANGED_FILES]
    if unexpected_status:
        reasons.append(f"Git status contains paths outside the allowlist: {unexpected_status}")
    current_manifest = legacy.directory_manifest(worktree, exclude_volatile=True)
    changed = sorted(path for path in set(baseline_manifest) | set(current_manifest) if baseline_manifest.get(path) != current_manifest.get(path))
    unexpected_files = [path for path in changed if path not in ALLOWED_CHANGED_FILES]
    if unexpected_files:
        reasons.append(f"raw filesystem changes outside the allowlist: {unexpected_files}")
    reasons.extend(diff_policy_reasons(diff, paths))
    reasons = sorted(set(reasons))
    diff_sha256 = hashlib.sha256(diff.encode("utf-8")).hexdigest()
    runtime.atomic_text(attempt_dir / "candidate.patch", diff)
    atomic(
        attempt_dir / "security_gate.json",
        {
            "pass": not reasons,
            "changed_files": paths,
            "filesystem_changed_files": changed,
            "diff_bytes": len(diff.encode("utf-8")),
            "diff_sha256": diff_sha256,
            "reasons": reasons,
        },
    )
    atomic(
        attempt_dir / "filesystem_gate.json",
        {"pass": not unexpected_files, "changed_files": changed, "unexpected": unexpected_files},
    )
    if reasons:
        raise CandidateRejected("; ".join(reasons))
    return diff, diff_sha256, category_for_diff(diff)


def run_validations(
    config: Config,
    worktree: Path,
    workspace_root: Path,
    registry_dir: Path,
    run_id: str,
    cycle: int,
    authorization: dict[str, Any],
    authorization_sha256: str,
    attempt_dir: Path,
    protected_full_suite: Path,
    deadline: float,
) -> None:
    validation = attempt_dir / "validation"
    validation.mkdir(parents=True, exist_ok=False)
    commands = {
        "compile": ["python", "-m", "py_compile", "tmp_2d_simulator_v37.py", "test_tmp_2d_simulator_v37.py"],
        "focused_tests": [
            "python",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "test_tmp_2d_simulator_v37.py::RobustnessTests::test_requires_multiple_challenge_rollouts",
            "test_tmp_2d_simulator_v37.py::RobustnessTests::test_cvar_weights_emphasize_worst_episode",
        ],
        "candidate_full_tests": ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_tmp_2d_simulator_v37.py"],
    }
    for name, values in commands.items():
        try:
            runtime.run_candidate_container(
                docker=config.docker,
                image_id=str(authorization["candidate_image_id"]),
                policy_path=config.repo / "candidate_container_policy_v1.json",
                workspace_root=workspace_root,
                workdir=worktree.relative_to(workspace_root).as_posix(),
                command=values,
                run_id=run_id,
                cycle=cycle,
                command_id=name.replace("_", "-"),
                authorization_sha256=authorization_sha256,
                registry_dir=registry_dir,
                cwd=config.repo,
                environment=trusted_environment(),
                timeout=remaining_timeout(deadline, config.command_timeout_seconds),
                evidence=validation / f"{name}.json",
            )
        except (runtime.RuntimeFailure, runtime.RuntimeTimeout) as exc:
            raise CandidateRejected(f"{name} failed in candidate container: {exc}") from exc
    protected = strict_json(protected_full_suite)
    if protected.get("return_code") != 0 or protected.get("timed_out") is not False:
        raise CandidateRejected("authorization-bound protected harness suite did not pass")
    atomic(
        validation / "full_tests.json",
        {
            "schema_version": "blast-pit.composite-full-test-gate.v1",
            "pass": True,
            "protected_harness_suite": {
                "path": str(protected_full_suite),
                "sha256": legacy.sha256_file(protected_full_suite),
            },
            "candidate_complete_v37_suite": {
                "path": "candidate_full_tests.json",
                "sha256": legacy.sha256_file(validation / "candidate_full_tests.json"),
            },
        },
    )


def run_protected_harness_preflight(config: Config, run_dir: Path, deadline: float) -> Path:
    evidence = run_dir / "protected_full_suite.json"
    try:
        command(
            [config.python, "-m", "pytest", "-q"],
            config.repo,
            remaining_timeout(deadline, config.command_timeout_seconds),
            evidence=evidence,
        )
    except (runtime.RuntimeFailure, runtime.RuntimeTimeout) as exc:
        raise V2Error(f"authorization-bound protected harness suite failed: {exc}") from exc
    return evidence


def candidate_train(
    config: Config,
    source_root: Path,
    workspace_root: Path,
    registry_dir: Path,
    output_root: Path,
    retained_root: Path,
    experiment_id: str,
    run_id: str,
    cycle: int,
    authorization: dict[str, Any],
    authorization_sha256: str,
    evidence: Path,
    deadline: float,
) -> Path:
    arguments: list[str] = [
        "--experiment-id",
        experiment_id,
        "--artifact-root",
        "/output",
        "--source-v36",
        runtime.container_path(workspace_root, source_root / "artifacts" / "v36" / "qdppo-evaluation-001" / "evolution_state_v36.npz"),
        "--seed-file",
        runtime.container_path(workspace_root, source_root / "improvement_dev_seeds_v1.txt"),
        "--parent-authorization",
        runtime.container_path(workspace_root, source_root / config.authorization.name),
        "--generations",
        "4",
        "--max-frames",
        "64",
        "--rollout-frames",
        "64",
        "--max-runtime-seconds",
        str(min(600, config.evaluation_timeout_seconds)),
    ]
    args = [
        "python",
        runtime.container_path(workspace_root, source_root / "improvement_candidate_export.py"),
        "--driver",
        "improvement_candidate_driver_v2.py",
        "--",
        *arguments,
    ]
    try:
        result = runtime.run_candidate_container(
            docker=config.docker,
            image_id=str(authorization["candidate_image_id"]),
            policy_path=config.repo / "candidate_container_policy_v1.json",
            workspace_root=workspace_root,
            workdir=source_root.relative_to(workspace_root).as_posix(),
            command=args,
            run_id=run_id,
            cycle=cycle,
            command_id=f"training-{experiment_id}",
            authorization_sha256=authorization_sha256,
            registry_dir=registry_dir,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=remaining_timeout(deadline, config.evaluation_timeout_seconds),
            evidence=evidence,
        )
    except (runtime.RuntimeFailure, runtime.RuntimeTimeout) as exc:
        raise CandidateRejected(f"candidate development training failed in the candidate container: {exc}") from exc
    try:
        output_manifest = runtime.materialize_candidate_output_bundle(result.stdout, output_root)
        atomic(
            evidence.with_name(evidence.stem + "_materialized_output.json"),
            {
                "schema_version": "blast-pit.candidate-output-materialization.v1",
                "pass": True,
                "root": str(output_root),
                "files": output_manifest,
            },
        )
    except runtime.RuntimeFailure as exc:
        raise CandidateRejected(f"candidate development output bundle was rejected: {exc}") from exc
    checkpoint = output_root / experiment_id / "evolution_state_v37.npz"
    runtime.validate_no_reparse_ancestors(checkpoint, require_exists=True)
    if not checkpoint.is_file() or checkpoint.stat(follow_symlinks=False).st_nlink != 1:
        raise CandidateRejected("candidate training did not produce a safe checkpoint")
    runtime.strict_manifest(output_root, max_files=2_000, max_bytes=128_000_000)
    runtime.copy_strict_tree(output_root, retained_root, max_files=2_000, max_bytes=128_000_000)
    retained_checkpoint = retained_root / experiment_id / "evolution_state_v37.npz"
    runtime.validate_no_reparse_ancestors(retained_checkpoint, require_exists=True)
    if not retained_checkpoint.is_file() or retained_checkpoint.stat(follow_symlinks=False).st_nlink != 1:
        raise CandidateRejected("retained candidate checkpoint is missing or unsafe")
    return retained_checkpoint


def create_hidden_fold(path: Path, count: int = 32) -> dict[str, Any]:
    if count < 8 or count % 2:
        raise V2Error("hidden fold must be even and contain at least eight trials")
    values: set[int] = set()
    while len(values) < count:
        values.add(secrets.randbits(63))
    seeds = list(values)
    secrets.SystemRandom().shuffle(seeds)
    profiles = ["standard"] * (count // 2) + ["water_fire_challenge"] * (count // 2)
    secrets.SystemRandom().shuffle(profiles)
    record = {"fold_id": f"hidden-{secrets.token_hex(8)}", "seeds": seeds, "profiles": profiles}
    atomic(path, record)
    return record


def trusted_score(
    config: Config,
    checkpoint: Path,
    fold: Path,
    *,
    workspace_root: Path,
    registry_dir: Path,
    run_id: str,
    cycle: int,
    authorization: dict[str, Any],
    authorization_sha256: str,
    evidence: Path,
    deadline: float,
) -> dict[str, Any]:
    score_root = workspace_root / f"trusted_score_{secrets.token_hex(8)}"
    score_root.mkdir(parents=False, exist_ok=False)
    trusted_sources = (
        config.evaluator,
        config.repo / "tmp_2d_simulator_v37.py",
        config.repo / "tmp_2d_simulator_v36.py",
        config.repo / "tmp_2d_simulator_v35.py",
    )
    try:
        for source in trusted_sources:
            destination = score_root / source.name
            shutil.copyfile(source, destination, follow_symlinks=False)
            if legacy.sha256_file(destination) != legacy.sha256_file(source):
                raise V2Error(f"trusted scorer source copy mismatch: {source.name}")
        checkpoint_copy = score_root / "checkpoint.npz"
        fold_copy = score_root / "hidden_fold.json"
        for source, destination in ((checkpoint, checkpoint_copy), (fold, fold_copy)):
            runtime.validate_no_reparse_ancestors(source, require_exists=True)
            if not source.is_file() or source.stat(follow_symlinks=False).st_nlink != 1:
                raise V2Error(f"trusted scorer input is unsafe: {source}")
            shutil.copyfile(source, destination, follow_symlinks=False)
            if legacy.sha256_file(destination) != legacy.sha256_file(source):
                raise V2Error(f"trusted scorer input copy mismatch: {source.name}")
        result = runtime.run_candidate_container(
            docker=config.docker,
            image_id=str(authorization["candidate_image_id"]),
            policy_path=config.repo / "candidate_container_policy_v1.json",
            workspace_root=workspace_root,
            workdir=score_root.relative_to(workspace_root).as_posix(),
            command=[
                "python",
                "improvement_score_checkpoint_v2.py",
                "--checkpoint",
                "checkpoint.npz",
                "--fold-file",
                "hidden_fold.json",
            ],
            run_id=run_id,
            cycle=cycle,
            command_id="trusted-score",
            authorization_sha256=authorization_sha256,
            registry_dir=registry_dir,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=remaining_timeout(deadline, config.evaluation_timeout_seconds),
            evidence=evidence,
        )
    finally:
        if score_root.exists():
            runtime.safe_remove_tree(score_root, workspace_root)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise V2Error("trusted scorer emitted an ambiguous result")
    try:
        score = json.loads(lines[0], parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
    except (json.JSONDecodeError, ValueError) as exc:
        raise V2Error("trusted scorer emitted invalid JSON") from exc
    required = {
        "schema_version": "blast-pit.improvement-score.v2",
        "evaluator_source_sha256": legacy.sha256_file(config.evaluator),
        "simulator_source_sha256": legacy.sha256_file(config.repo / "tmp_2d_simulator_v37.py"),
    }
    if any(score.get(key) != value for key, value in required.items()):
        raise V2Error("trusted scorer source identity mismatch")
    fold_record = strict_json(fold)
    canonical_fold = {"seeds": fold_record["seeds"], "profiles": fold_record["profiles"]}
    if score.get("fold_sha256") != digest(canonical_fold) or score.get("trial_count") != len(fold_record["seeds"]):
        raise V2Error("trusted scorer fold identity mismatch")
    numeric = [value for value in score.values() if isinstance(value, (int, float)) and not isinstance(value, bool)]
    if not all(math.isfinite(float(value)) for value in numeric):
        raise V2Error("trusted scorer emitted a non-finite value")
    return score


def root_fold_scores(
    config: Config,
    *,
    run_id: str,
    baseline_checkpoint: Path,
    candidate_checkpoint: Path,
    fold: Path,
    authorization: dict[str, Any],
    authorization_sha256: str,
    run_dir: Path,
    deadline: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = config.worktree_root / run_id
    workspace = registry / "root_scoring_workspace"
    workspace.mkdir(parents=False, exist_ok=False)
    try:
        baseline = trusted_score(
            config,
            baseline_checkpoint,
            fold,
            workspace_root=workspace,
            registry_dir=registry,
            run_id=run_id,
            cycle=0,
            authorization=authorization,
            authorization_sha256=authorization_sha256,
            evidence=run_dir / "final_baseline_score_command.json",
            deadline=deadline,
        )
        candidate = trusted_score(
            config,
            candidate_checkpoint,
            fold,
            workspace_root=workspace,
            registry_dir=registry,
            run_id=run_id,
            cycle=0,
            authorization=authorization,
            authorization_sha256=authorization_sha256,
            evidence=run_dir / "final_candidate_score_command.json",
            deadline=deadline,
        )
        return baseline, candidate
    finally:
        runtime.recover_governed_containers(
            docker=config.docker,
            worktree_root=config.worktree_root,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=min(120, max(15, int(deadline - time.monotonic()))),
            evidence_dir=run_dir / "root_scoring_container_cleanup",
            run_id=run_id,
        )
        runtime.assert_governed_containers_quiescent(
            docker=config.docker,
            worktree_root=config.worktree_root,
            run_id=run_id,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=min(120, max(15, int(deadline - time.monotonic()))),
            evidence=run_dir / "root_scoring_container_quiescence.json",
        )
        if workspace.exists():
            runtime.safe_remove_tree(workspace, registry)


def aggregate_score(score: dict[str, Any]) -> dict[str, Any]:
    omit = {"fitness_values", "checkpoint", "python_executable"}
    return {key: value for key, value in score.items() if key not in omit}


def commit_candidate(config: Config, worktree: Path, cycle: int, cycle_dir: Path, deadline: float) -> str:
    safe_dir = f"safe.directory={worktree.resolve()}"
    git(config, ["-c", safe_dir, "-C", worktree, "add", "--", *sorted(ALLOWED_CHANGED_FILES)], timeout=remaining_timeout(deadline, 120))
    names = git(config, ["-c", safe_dir, "-C", worktree, "diff", "--cached", "--name-only"], timeout=remaining_timeout(deadline, 120)).stdout.splitlines()
    if sorted(names) != sorted(set(names)) or any(name not in ALLOWED_CHANGED_FILES for name in names):
        raise V2Error("staged candidate paths are outside the allowlist")
    git(
        config,
        [
            "-c",
            safe_dir,
            "-c",
            "user.name=Codex Improvement Controller",
            "-c",
            "user.email=codex-controller@localhost",
            "-C",
            worktree,
            "commit",
            "-m",
            f"Governed candidate improvement cycle {cycle:03d}",
        ],
        timeout=remaining_timeout(deadline, 180),
        evidence=cycle_dir / "candidate_commit.json",
    )
    commit = git(config, ["-c", safe_dir, "-C", worktree, "rev-parse", "HEAD"], timeout=remaining_timeout(deadline, 60)).stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{40,64}", commit):
        raise V2Error("candidate commit identity is invalid")
    return commit


def decision_reviews(reviews: Sequence[dict[str, Any]], artifacts: dict[str, str], final_qa_artifact: str | None = None, final_qa: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    result = [
        {"role": role, "status": next((row["verdict"] for row in reviews if row.get("role") == role), "NOT_RUN"), "artifact": artifacts.get(role)}
        for role in ROLES
    ]
    result.append({"role": "final_qa", "status": final_qa.get("verdict", "NOT_RUN") if final_qa else "NOT_RUN", "artifact": final_qa_artifact})
    return result


def operator_decision(
    *,
    run_id: str,
    cycle: int,
    execution: str,
    review: str,
    promotion: str,
    gates: dict[str, dict[str, Any]],
    base_commit: str,
    candidate_commit: str | None,
    diff_sha256: str | None,
    worktree: str,
    reviews: list[dict[str, Any]],
    rubric_value: dict[str, Any],
    blockers: Sequence[str],
    warnings: Sequence[str],
    production_modified: bool = False,
) -> dict[str, Any]:
    value = {
        "schema_version": "codex.improvement-operator-decision.v2",
        "run_id": run_id,
        "cycle": max(1, cycle),
        "execution": execution,
        "review": review,
        "promotion": promotion,
        "cycle_gates": [gates[name] for name in CORE_GATES],
        "lineage": {
            "base_commit": base_commit,
            "candidate_commit": candidate_commit,
            "diff_sha256": diff_sha256,
            "worktree": worktree,
            "production_modified": production_modified,
        },
        "reviews": reviews,
        "rubric": rubric_value,
        "blockers": list(blockers),
        "warnings": list(warnings),
        "promotion_authorized": False,
        "release_authorized": False,
    }
    improvement_operator.validate_operator_decision(value)
    return value


def seal_cycle(cycle_dir: Path, previous_manifest_sha256: str) -> str:
    manifest = {
        "schema_version": "blast-pit.improvement-cycle-manifest.v2",
        "cycle": int(cycle_dir.name.split("_")[-1]),
        "previous_cycle_manifest_sha256": previous_manifest_sha256,
        "sealed_at": utc_now(),
        "files": runtime.strict_manifest(cycle_dir),
    }
    path = cycle_dir / "cycle_manifest.json"
    atomic(path, manifest)
    return legacy.sha256_file(path)


def seal_run(run_dir: Path, base_commit: str, status: str) -> str:
    manifest = {
        "schema_version": "blast-pit.improvement-evidence-manifest.v2",
        "run_id": run_dir.name,
        "base_commit": base_commit,
        "status": status,
        "controller_source_sha256": legacy.canonical_text_sha256(Path(__file__)),
        "sealed_at": utc_now(),
        "files": runtime.strict_manifest(run_dir),
    }
    path = run_dir / "evidence_manifest.json"
    atomic(path, manifest)
    return legacy.sha256_file(path)


def _safe_error(exc: BaseException) -> str:
    value = " ".join(str(exc).split())[:1200]
    return f"{type(exc).__name__}: {value or 'unspecified failure'}"


def execute_cycle(
    config: Config,
    *,
    run_id: str,
    run_dir: Path,
    journal: Journal,
    cycle: int,
    base_commit: str,
    protected_snapshot: dict[str, Any],
    previous_manifest_sha256: str,
    prior_outcomes: Sequence[CycleOutcome],
    private_fold_root: Path,
    protected_full_suite: Path,
    authorization: dict[str, Any],
    authorization_sha256: str,
    deadline: float,
) -> CycleOutcome:
    cycle_dir = run_dir / f"cycle_{cycle:03d}"
    cycle_dir.mkdir(parents=True, exist_ok=False)
    gates = gate_template()
    set_gate(gates, "authorization", "PASS", "../authorization_evidence.json")
    workspace_root = config.worktree_root / run_id
    workspace_root.mkdir(parents=True, exist_ok=True)
    lease_root = workspace_root / f"cycle_{cycle:03d}_candidate_lease"
    worktree = lease_root / "worktree"
    candidate_isolation = workspace_root / f"cycle_{cycle:03d}_candidate_control"
    role_isolation_root = workspace_root / f"cycle_{cycle:03d}_role_isolations"
    baseline_output = lease_root / "baseline_training"
    candidate_output = lease_root / "candidate_training"
    retained_baseline_output = cycle_dir / "baseline_training"
    retained_candidate_output = cycle_dir / "candidate_training"
    role_isolation_root.mkdir()
    branch = f"codex/v2-{run_id.lower()}-c{cycle:03d}"
    outcome = CycleOutcome(cycle, "RUNNING", "RUNNING", base_commit, str(worktree), gates)
    sandbox_environment: dict[str, str] | None = None
    acl_lease: runtime.AclLease | None = None
    remediation_attempts = 0
    latest_attempt_dir: Path | None = None
    latest_adjudication: dict[str, Any] | None = None
    build_summary: dict[str, Any] | None = None
    cleanup_rows: list[dict[str, Any]] = []
    journal.add("CYCLE_STARTING", cycle=cycle, base_commit=base_commit)

    try:
        lease_root.mkdir(parents=True, exist_ok=False)
        sandbox_environment, sandbox_temp = runtime.prepare_candidate_sandbox(
            candidate_isolation,
            workspace_root,
            [lease_root],
            scratch=lease_root / "temp",
            profile="candidate",
            implementation=config.sandbox_implementation,
        )
        sandbox_evidence = cycle_dir / "sandbox"
        acl_lease = runtime.start_candidate_acl_lease(
            lease_path=workspace_root / f"acl_lease_cycle_{cycle:03d}.json",
            root=lease_root,
            authorized_parent=workspace_root,
            helper=config.repo / "improvement_acl_helper.ps1",
            control_dir=candidate_isolation,
            evidence_dir=sandbox_evidence,
            authorization_sha256=authorization_sha256,
            worktree_path=worktree,
            codex=config.codex,
            python=config.python,
            profile="candidate",
            environment=sandbox_environment,
            canary_source=config.repo / "improvement_sandbox_canary.py",
            forbidden=[config.repo, Path.home().resolve()],
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            token=secrets.token_hex(16),
            registry=_ACTIVE_RUN.acl_leases if _ACTIVE_RUN is not None else None,
        )
        container_qualification = runtime.qualify_candidate_container(
            docker=config.docker,
            image_id=str(authorization["candidate_image_id"]),
            policy_path=config.repo / "candidate_container_policy_v1.json",
            workspace_root=lease_root,
            canary_source=config.repo / "improvement_container_canary.py",
            run_id=run_id,
            cycle=cycle,
            authorization_sha256=authorization_sha256,
            registry_dir=workspace_root,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            evidence_dir=sandbox_evidence,
            token=secrets.token_hex(16),
        )
        atomic(
            sandbox_evidence / "isolation_qualification.json",
            {
                "schema_version": "blast-pit.composite-isolation-qualification.v1",
                "pass": True,
                "windows_patch_boundary": "sandbox_qualification.json",
                "candidate_execution_boundary": "container_qualification.json",
                "container_image_id": container_qualification["image_id"],
                "python_audit_hook_security_boundary": False,
            },
        )
        set_gate(gates, "sandbox_canary", "PASS", "sandbox/isolation_qualification.json")
        baseline_output.mkdir()
        candidate_output.mkdir()
        git(
            config,
            ["worktree", "add", "-b", branch, worktree, base_commit],
            timeout=remaining_timeout(deadline, 180),
            evidence=cycle_dir / "worktree_create.json",
        )
        baseline_manifest = legacy.directory_manifest(worktree, exclude_volatile=True)
        atomic(cycle_dir / "worktree_baseline_manifest.json", {"root": str(worktree), "files": baseline_manifest})
        journal.add("BUILDING", cycle=cycle)
        builder = run_role(
            config,
            role="builder",
            prompt=build_prompt(config, worktree, cycle, [item.__dict__ for item in prior_outcomes]),
            schema=config.repo / "schemas" / "codex_build_result_v2.schema.json",
            evidence_dir=cycle_dir / "roles" / "builder" / "attempt_00",
            isolation=role_isolation_root / "builder-attempt_00",
            isolation_root=role_isolation_root,
            deadline=deadline,
        )
        try:
            verify_build_result(config, builder)
        except V2Error as exc:
            raise CandidateRejected(f"builder result rejected: {exc}") from exc
        build_summary = {key: value for key, value in builder.items() if key != "patch"}
        atomic(cycle_dir / "builder_summary.json", build_summary)
        if builder["category"] == "no_change":
            raise CandidateRejected("builder found no defensible bounded improvement")

        outside_after_builder = production_snapshot(config)
        if not compare_protection(protected_snapshot, outside_after_builder, cycle_dir / "external_guard_builder.json"):
            raise runtime.RuntimeFailure("tool-less builder phase changed protected state")

        baseline_checkpoint = candidate_train(
            config,
            worktree,
            lease_root,
            workspace_root,
            baseline_output,
            retained_baseline_output,
            f"baseline-c{cycle:03d}",
            run_id,
            cycle,
            authorization,
            authorization_sha256,
            cycle_dir / "baseline_training_command.json",
            deadline,
        )
        outcome.baseline_checkpoint = baseline_checkpoint

        apply_dir = cycle_dir / "attempt_00"
        apply_dir.mkdir()
        runtime.apply_patch_in_sandbox(
            patch=builder["patch"],
            declared_files=builder["changed_files"],
            allowed_files=ALLOWED_CHANGED_FILES,
            max_bytes=config.max_diff_bytes,
            worktree=worktree,
            scratch=sandbox_temp,
            codex=config.codex,
            profile="candidate",
            environment=sandbox_environment,
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            evidence_dir=apply_dir,
        )
        latest_attempt_dir = apply_dir
        diff, diff_sha256, category = static_candidate_gate(config, worktree, baseline_manifest, apply_dir / "gates", deadline)
        run_validations(
            config,
            worktree,
            lease_root,
            workspace_root,
            run_id,
            cycle,
            authorization,
            authorization_sha256,
            apply_dir,
            protected_full_suite,
            deadline,
        )
        outcome.diff_sha256 = diff_sha256
        outcome.category = category

        packet = bounded_source_packet(
            config,
            worktree,
            diff=diff,
            extra={"build_summary": build_summary, "validation": "guarded compile/focused/complete v37 tests plus the protected harness suite passed"},
        )
        reviews, artifacts = run_specialist_panel(
            config,
            packet=packet,
            diff_sha256=diff_sha256,
            evidence_root=cycle_dir / "roles",
            isolation_root=role_isolation_root,
            attempt_name="attempt_00",
            deadline=deadline,
        )
        outcome.reviews = reviews
        outcome.review_artifacts = {role: f"roles/{role}/attempt_00/final.json" for role in ROLES}
        latest_adjudication = adjudicate(reviews)
        atomic(cycle_dir / "adjudication_attempt_00.json", latest_adjudication)
        outcome.mandatory_findings.extend(latest_adjudication["mandatory_finding_ids"])

        while latest_adjudication["verdict"] != "PASS":
            if remediation_attempts >= config.remediation_cap:
                raise CandidateRejected("specialist findings remained after the authorized remediation cap")
            remediation_attempts += 1
            attempt_name = f"attempt_{remediation_attempts:02d}"
            mandatory = latest_adjudication["mandatory_finding_ids"]
            remediation_prompt = f"""You are the tool-less remediator. Return one codex.build-result.v2 JSON object.
Resolve exactly these mandatory finding IDs: {json.dumps(mandatory)}. Return an incremental unified
patch relative to the inline current files. Do not request tools. external_writes must be [] and
authority_impact must be none. finding_ids_addressed must contain the exact sorted IDs.

{bounded_source_packet(config, worktree, diff=diff, extra={'adjudication': latest_adjudication})}"""
            remediation = run_role(
                config,
                role="remediator",
                prompt=remediation_prompt,
                schema=config.repo / "schemas" / "codex_build_result_v2.schema.json",
                evidence_dir=cycle_dir / "roles" / "remediator" / attempt_name,
                isolation=role_isolation_root / f"remediator-{attempt_name}",
                isolation_root=role_isolation_root,
                deadline=deadline,
            )
            try:
                verify_build_result(config, remediation, mandatory_findings=mandatory)
            except V2Error as exc:
                raise CandidateRejected(f"remediation result rejected: {exc}") from exc
            if remediation["category"] == "no_change":
                raise CandidateRejected("remediator returned no change for mandatory findings")
            attempt_dir = cycle_dir / attempt_name
            attempt_dir.mkdir()
            runtime.apply_patch_in_sandbox(
                patch=remediation["patch"],
                declared_files=remediation["changed_files"],
                allowed_files=ALLOWED_CHANGED_FILES,
                max_bytes=config.max_diff_bytes,
                worktree=worktree,
                scratch=sandbox_temp,
                codex=config.codex,
                profile="candidate",
                environment=sandbox_environment,
                timeout=remaining_timeout(deadline, config.command_timeout_seconds),
                evidence_dir=attempt_dir,
            )
            latest_attempt_dir = attempt_dir
            diff, diff_sha256, category = static_candidate_gate(config, worktree, baseline_manifest, attempt_dir / "gates", deadline)
            run_validations(
                config,
                worktree,
                lease_root,
                workspace_root,
                run_id,
                cycle,
                authorization,
                authorization_sha256,
                attempt_dir,
                protected_full_suite,
                deadline,
            )
            outcome.diff_sha256 = diff_sha256
            outcome.category = category
            packet = bounded_source_packet(
                config,
                worktree,
                diff=diff,
                extra={"remediation_attempt": remediation_attempts, "prior_adjudication": latest_adjudication},
            )
            reviews, artifacts = run_specialist_panel(
                config,
                packet=packet,
                diff_sha256=diff_sha256,
                evidence_root=cycle_dir / "roles",
                isolation_root=role_isolation_root,
                attempt_name=attempt_name,
                deadline=deadline,
            )
            outcome.reviews = reviews
            outcome.review_artifacts = {role: f"roles/{role}/{attempt_name}/final.json" for role in ROLES}
            latest_adjudication = adjudicate(reviews)
            atomic(cycle_dir / f"adjudication_{attempt_name}.json", latest_adjudication)
            outcome.mandatory_findings.extend(latest_adjudication["mandatory_finding_ids"])

        if latest_attempt_dir is None:
            raise V2Error("candidate attempt evidence is missing")
        set_gate(gates, "filesystem", "PASS", f"{latest_attempt_dir.relative_to(cycle_dir).as_posix()}/gates/filesystem_gate.json")
        set_gate(gates, "security", "PASS", f"{latest_attempt_dir.relative_to(cycle_dir).as_posix()}/gates/security_gate.json")
        validation_rel = f"{latest_attempt_dir.relative_to(cycle_dir).as_posix()}/validation"
        set_gate(gates, "compile", "PASS", validation_rel + "/compile.json")
        set_gate(gates, "focused_tests", "PASS", validation_rel + "/focused_tests.json")
        set_gate(gates, "full_tests", "PASS", validation_rel + "/full_tests.json")
        set_gate(gates, "specialist_consensus", "PASS", f"adjudication_attempt_{remediation_attempts:02d}.json")

        candidate_checkpoint = candidate_train(
            config,
            worktree,
            lease_root,
            workspace_root,
            candidate_output,
            retained_candidate_output,
            f"candidate-c{cycle:03d}",
            run_id,
            cycle,
            authorization,
            authorization_sha256,
            cycle_dir / "candidate_training_command.json",
            deadline,
        )
        outcome.candidate_checkpoint = candidate_checkpoint
        fold = private_fold_root / f"cycle_{cycle:03d}_fold_b.json"
        outcome.private_fold_record = create_hidden_fold(fold)
        try:
            baseline_score = trusted_score(
                config,
                baseline_checkpoint,
                fold,
                workspace_root=lease_root,
                registry_dir=workspace_root,
                run_id=run_id,
                cycle=cycle,
                authorization=authorization,
                authorization_sha256=authorization_sha256,
                evidence=cycle_dir / "baseline_score_command.json",
                deadline=deadline,
            )
            candidate_score = trusted_score(
                config,
                candidate_checkpoint,
                fold,
                workspace_root=lease_root,
                registry_dir=workspace_root,
                run_id=run_id,
                cycle=cycle,
                authorization=authorization,
                authorization_sha256=authorization_sha256,
                evidence=cycle_dir / "candidate_score_command.json",
                deadline=deadline,
            )
        finally:
            fold.unlink(missing_ok=True)
        paired = paired_metric_gate(baseline_score, candidate_score, outcome.category or "algorithm", remediation_attempts)
        evaluation = {
            "schema_version": "blast-pit.paired-evaluation-summary.v2",
            "pass": paired["pass"],
            "fold_id": baseline_score["fold_id"],
            "fold_sha256": baseline_score["fold_sha256"],
            "baseline": aggregate_score(baseline_score),
            "candidate": aggregate_score(candidate_score),
            "paired": paired,
        }
        outcome.evaluation = evaluation
        outcome.raw_evaluation = {"baseline": baseline_score, "candidate": candidate_score}
        atomic(cycle_dir / "evaluation_summary.json", evaluation)
        if not paired["pass"]:
            set_gate(gates, "evaluation", "FAIL", "evaluation_summary.json")
            raise CandidateRejected("paired hidden-fold evaluation did not prove the required improvement and non-regression")
        set_gate(gates, "evaluation", "PASS", "evaluation_summary.json")

        outside_after_candidate = production_snapshot(config)
        if not compare_protection(protected_snapshot, outside_after_candidate, cycle_dir / "external_guard.json"):
            raise runtime.RuntimeFailure("candidate phase changed protected state")
        set_gate(gates, "external_guard", "PASS", "external_guard.json")
        set_gate(gates, "production_guard", "PASS", "external_guard.json")

        qa_packet = bounded_source_packet(
            config,
            worktree,
            diff=diff,
            extra={
                "specialist_reviews": outcome.reviews,
                "evaluation": evaluation,
                "gates": gate_bools(gates),
                "mandatory_findings": sorted(set(outcome.mandatory_findings)),
                "automatic_promotion": False,
            },
        )
        final_qa = run_role(
            config,
            role="final_qa",
            prompt=final_qa_prompt(diff_sha256, qa_packet, outcome.mandatory_findings),
            schema=config.repo / "schemas" / "final_qa_v2.schema.json",
            evidence_dir=cycle_dir / "final_qa_role",
            isolation=role_isolation_root / "final-qa",
            isolation_root=role_isolation_root,
            deadline=deadline,
        )
        try:
            verify_final_qa(config, final_qa, diff_sha256, outcome.mandatory_findings)
        except V2Error as exc:
            raise CandidateRejected(f"final QA result rejected: {exc}") from exc
        outcome.final_qa = final_qa
        atomic(cycle_dir / "final_qa.json", final_qa)
        if final_qa["verdict"] != "PASS":
            set_gate(gates, "final_qa", "FAIL", "final_qa.json")
            raise CandidateRejected("independent final QA did not pass")
        set_gate(gates, "final_qa", "PASS", "final_qa.json")

        rubric_evidence = {identifier: "final_qa.json" for identifier in RUBRIC_IDS}
        outcome.rubric = rubric(outcome.reviews, gate_bools(gates), evaluation, final_qa, rubric_evidence)
        atomic(cycle_dir / "rubric.json", outcome.rubric)
        if not outcome.rubric["ten_out_of_ten"]:
            raise CandidateRejected("candidate did not achieve the deterministic 100/100 rubric")
        candidate_commit = commit_candidate(config, worktree, cycle, cycle_dir, deadline)
        outcome.candidate_commit = candidate_commit
        outcome.status = "ACCEPTED"
        outcome.execution = "SUCCESS"
    except CandidateRejected as exc:
        outcome.status = "REJECTED"
        outcome.execution = "SUCCESS"
        outcome.blockers.append(_safe_error(exc))
    except runtime.RuntimeTimeout as exc:
        outcome.status = "TIMEOUT"
        outcome.execution = "TIMEOUT"
        outcome.blockers.append(_safe_error(exc))
    except (V2Error, runtime.RuntimeFailure, OSError, subprocess.SubprocessError) as exc:
        outcome.status = "ERROR"
        outcome.execution = "FAILED"
        outcome.blockers.append(_safe_error(exc))
    finally:
        lease_restore_error: BaseException | None = None
        try:
            runtime.recover_governed_containers(
                docker=config.docker,
                worktree_root=config.worktree_root,
                cwd=config.repo,
                environment=trusted_environment(),
                timeout=min(120, max(15, int(deadline - time.monotonic()))),
                evidence_dir=cycle_dir / "container_cleanup",
                run_id=run_id,
            )
            runtime.assert_governed_containers_quiescent(
                docker=config.docker,
                worktree_root=config.worktree_root,
                run_id=run_id,
                cwd=config.repo,
                environment=trusted_environment(),
                timeout=min(120, max(15, int(deadline - time.monotonic()))),
                evidence=cycle_dir / "container_quiescence.json",
            )
        except Exception as exc:
            lease_restore_error = exc
            outcome.status = "ERROR"
            outcome.execution = "FAILED"
            outcome.blockers.append(f"candidate container recovery failed: {_safe_error(exc)}")
            cleanup_rows.append({"target": run_id, "status": "CONTAINER_RECOVERY_REQUIRED", "error": _safe_error(exc)})
        if worktree.exists() and lease_restore_error is None:
            removal = git(
                config,
                ["worktree", "remove", "--force", worktree],
                timeout=min(180, max(1, int(deadline - time.monotonic()))),
                evidence=cycle_dir / "worktree_remove.json",
                require_success=False,
            )
            cleanup_rows.append({"target": str(worktree), "status": "REMOVED" if removal.return_code == 0 else "REMOVE_FAILED", "return_code": removal.return_code})
            if removal.return_code != 0:
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append("candidate worktree Git cleanup failed; forcing disposable lease cleanup")
                try:
                    runtime.safe_remove_tree(worktree, lease_root)
                    git(config, ["worktree", "prune"], timeout=60, require_success=False)
                    cleanup_rows.append({"target": str(worktree), "status": "FORCE_REMOVED"})
                except Exception as exc:
                    lease_restore_error = exc
                    cleanup_rows.append({"target": str(worktree), "status": "QUARANTINED", "error": _safe_error(exc)})
        elif worktree.exists() and lease_restore_error is not None:
            cleanup_rows.append({"target": str(worktree), "status": "QUARANTINED_FOR_CONTAINER_RECOVERY"})
        if outcome.candidate_commit is None:
            deletion = git(config, ["branch", "-D", branch], timeout=60, require_success=False)
            cleanup_rows.append({"target": branch, "status": "DELETED" if deletion.return_code == 0 else "RETAINED", "return_code": deletion.return_code})

        if acl_lease is not None and lease_restore_error is None:
            try:
                runtime.empty_directory_contents(
                    lease_root,
                    workspace_root,
                    expected_identity=acl_lease.record["root_identity"],
                )
                runtime.restore_candidate_acl_lease(
                    acl_lease,
                    timeout=min(120, max(1, int(deadline - time.monotonic()))),
                    cleanup=False,
                )
                atomic(cycle_dir / "sandbox" / "acl_lease_final.json", acl_lease.record)
                if _ACTIVE_RUN is not None and acl_lease in _ACTIVE_RUN.acl_leases:
                    _ACTIVE_RUN.acl_leases.remove(acl_lease)
                runtime.safe_remove_tree(lease_root, workspace_root)
                cleanup_rows.append({"target": str(lease_root), "status": "ACL_RESTORED_AND_REMOVED"})
            except Exception as exc:
                lease_restore_error = exc
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append(f"ACL lease restoration failed: {_safe_error(exc)}")
                cleanup_rows.append({"target": str(lease_root), "status": "RECOVERY_REQUIRED", "error": _safe_error(exc)})
        elif acl_lease is None and lease_root.exists() and lease_restore_error is None:
            try:
                runtime.safe_remove_tree(lease_root, workspace_root)
                cleanup_rows.append({"target": str(lease_root), "status": "REMOVED_AFTER_PREACTIVE_FAILURE"})
            except Exception as exc:
                lease_restore_error = exc
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append(f"pre-active lease cleanup failed: {_safe_error(exc)}")

        for target, label in ((candidate_isolation, "candidate control"), (role_isolation_root, "role isolation")):
            if target.exists():
                try:
                    runtime.safe_remove_tree(target, workspace_root)
                    cleanup_rows.append({"target": str(target), "status": "REMOVED"})
                except Exception as exc:
                    outcome.status = "ERROR"
                    outcome.execution = "FAILED"
                    outcome.blockers.append(f"{label} cleanup quarantined: {_safe_error(exc)}")
                    cleanup_rows.append({"target": str(target), "status": "QUARANTINED", "error": _safe_error(exc)})

        try:
            current = production_snapshot(config)
            passed = compare_protection(protected_snapshot, current, cycle_dir / "production_guard.json")
            set_gate(gates, "production_guard", "PASS" if passed else "FAIL", "production_guard.json")
            if not passed:
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append("protected checkout or retained production artifacts changed")
        except Exception as exc:  # fail closed while still retaining terminal evidence
            outcome.status = "ERROR"
            outcome.execution = "FAILED"
            outcome.blockers.append(_safe_error(exc))
            set_gate(gates, "production_guard", "FAIL", "production_guard.json")

        atomic(cycle_dir / "cleanup.json", {"entries": cleanup_rows})
        if lease_restore_error is not None:
            raise runtime.RuntimeFailure(f"ACL lease remains recovery-required: {_safe_error(lease_restore_error)}") from lease_restore_error

        transition = {
            "ACCEPTED": "CYCLE_ACCEPTED",
            "REJECTED": "CYCLE_REJECTED",
            "TIMEOUT": "CYCLE_TIMEOUT",
            "ERROR": "CYCLE_ERROR",
        }.get(outcome.status, "CYCLE_ERROR")
        journal.add(
            transition,
            cycle=cycle,
            status=outcome.status,
            candidate_commit=outcome.candidate_commit,
            reasons=outcome.blockers,
            rubric=(outcome.rubric or {}).get("total", 0),
        )

        review_status = "PASS" if outcome.status == "ACCEPTED" else ("CHANGES_REQUIRED" if outcome.execution == "SUCCESS" else "BLOCK")
        cycle_decision = operator_decision(
            run_id=run_id,
            cycle=cycle,
            execution=outcome.execution,
            review=review_status,
            promotion="NOT_ELIGIBLE",
            gates=gates,
            base_commit=base_commit,
            candidate_commit=outcome.candidate_commit,
            diff_sha256=outcome.diff_sha256,
            worktree=str(worktree),
            reviews=decision_reviews(outcome.reviews, outcome.review_artifacts, "final_qa.json" if outcome.final_qa else None, outcome.final_qa),
            rubric_value=outcome.rubric or empty_rubric(),
            blockers=outcome.blockers,
            warnings=outcome.warnings,
        )
        atomic(cycle_dir / "operator_decision.json", cycle_decision)
        outcome.manifest_sha256 = seal_cycle(cycle_dir, previous_manifest_sha256)
    return outcome


def source_at_commit(config: Config, commit: str, path: str, deadline: float) -> str:
    return git(config, ["show", f"{commit}:{path}"], timeout=remaining_timeout(deadline, 120)).stdout


def selected_evidence_summary(run_dir: Path, selected: CycleOutcome) -> dict[str, Any]:
    cycle_dir = run_dir / f"cycle_{selected.cycle:03d}"
    rows: dict[str, Any] = {}
    for name in CORE_GATES:
        gate = selected.gates.get(name, {})
        relative = gate.get("evidence")
        row: dict[str, Any] = {"status": gate.get("status"), "artifact": relative}
        if isinstance(relative, str):
            path = cycle_dir / relative
            resolved = path.resolve(strict=False)
            if cycle_dir.resolve() not in resolved.parents or not path.is_file() or path.is_symlink():
                raise V2Error(f"selected gate evidence is missing or unsafe: {name}")
            row.update({"sha256": legacy.sha256_file(path), "bytes": path.stat().st_size})
            if path.suffix == ".json" and path.stat().st_size <= 2_000_000:
                value = strict_json(path, max_bytes=2_000_000)
                row["assertions"] = {key: value.get(key) for key in ("pass", "return_code", "timed_out", "diff_sha256", "changed_files") if key in value}
        rows[name] = row
    for name in ("final_qa.json", "rubric.json"):
        path = cycle_dir / name
        if path.is_file() and not path.is_symlink():
            rows[name] = {"sha256": legacy.sha256_file(path), "bytes": path.stat().st_size}
    return rows


def append_local_ledger(artifact_root: Path, record: dict[str, Any]) -> str:
    """Append a local hash chain. It is tamper-evident, not an external signature."""
    path = artifact_root / "audit_ledger.jsonl"
    previous = "0" * 64
    sequence = 0
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            supplied = row.pop("ledger_hash")
            if row.get("previous_ledger_hash") != previous or digest(row) != supplied:
                raise V2Error("local audit ledger chain is invalid")
            previous = supplied
            sequence = int(row["sequence"])
            if row.get("run_id") == record.get("run_id"):
                raise V2Error(f"run is already present in the local audit ledger: {record.get('run_id')}")
    unsigned = {"schema_version": "blast-pit.improvement-ledger.v1", "sequence": sequence + 1, "previous_ledger_hash": previous, **record}
    row = {**unsigned, "ledger_hash": digest(unsigned)}
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical(row) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return row["ledger_hash"]


def recover_persisted_candidate_containers(config: Config, *, run_id: str | None = None) -> list[dict[str, Any]]:
    """Quiesce only authorization-labeled candidate containers and seal the result."""

    parent = config.artifact_root / "container_recovery"
    parent.mkdir(parents=True, exist_ok=True)
    event_id = datetime.now(timezone.utc).strftime("recovery_%Y%m%dT%H%M%SZ_") + secrets.token_hex(4)
    event_dir = parent / event_id
    event_dir.mkdir(parents=False, exist_ok=False)
    rows: list[dict[str, Any]] = []
    error: BaseException | None = None
    try:
        rows = runtime.recover_governed_containers(
            docker=config.docker,
            worktree_root=config.worktree_root,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=120,
            evidence_dir=event_dir / "operations",
            run_id=run_id,
        )
    except BaseException as exc:
        error = exc
    status = "RECOVERY_REQUIRED" if error is not None else ("RECOVERED" if rows else "QUIESCENT")
    atomic(
        event_dir / "recovery_summary.json",
        {
            "schema_version": "blast-pit.container-recovery-summary.v1",
            "pass": error is None,
            "status": status,
            "run_id": run_id,
            "containers": rows,
            "error": _safe_error(error) if error else None,
        },
    )
    decision = {
        "schema_version": "blast-pit.container-recovery-decision.v1",
        "event_id": event_id,
        "status": status,
        "run_id": run_id,
        "automatic_promotion": False,
        "error": _safe_error(error) if error else None,
    }
    atomic(event_dir / "recovery_decision.json", decision)
    manifest = {
        "schema_version": "blast-pit.container-recovery-manifest.v1",
        "event_id": event_id,
        "status": status,
        "sealed_at": utc_now(),
        "files": runtime.strict_manifest(event_dir),
    }
    atomic(event_dir / "recovery_manifest.json", manifest)
    ledger_path = config.artifact_root / "container_recovery_ledger.jsonl"
    previous = "0" * 64
    sequence = 0
    if ledger_path.exists():
        if ledger_path.is_symlink() or ledger_path.stat().st_size > 8_000_000:
            raise V2Error("container recovery ledger is unsafe")
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            prior = json.loads(line)
            supplied = prior.pop("ledger_hash")
            if prior.get("previous_ledger_hash") != previous or digest(prior) != supplied:
                raise V2Error("container recovery ledger chain is invalid")
            previous = supplied
            sequence = int(prior["sequence"])
    unsigned = {
        "schema_version": "blast-pit.container-recovery-ledger.v1",
        "sequence": sequence + 1,
        "previous_ledger_hash": previous,
        "event_id": event_id,
        "event_path": f"container_recovery/{event_id}",
        "status": status,
        "recovery_manifest_sha256": legacy.sha256_file(event_dir / "recovery_manifest.json"),
        "recovery_decision_sha256": legacy.sha256_file(event_dir / "recovery_decision.json"),
        "recorded_at": utc_now(),
    }
    ledger_row = {**unsigned, "ledger_hash": digest(unsigned)}
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical(ledger_row) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    atomic(
        config.artifact_root / "container_recovery_latest.json",
        {
            "schema_version": "blast-pit.container-recovery-latest.v1",
            "event_id": event_id,
            "event_path": f"container_recovery/{event_id}",
            "status": status,
            "ledger_hash": ledger_row["ledger_hash"],
            "recovery_manifest_sha256": unsigned["recovery_manifest_sha256"],
            "recovery_decision_sha256": unsigned["recovery_decision_sha256"],
        },
    )
    if error is not None:
        raise runtime.RuntimeFailure(f"candidate container recovery failed: {_safe_error(error)}") from error
    return rows


def reject_stale_private_folds(worktree_root: Path) -> None:
    if not worktree_root.exists():
        return
    runtime.validate_no_reparse_ancestors(worktree_root, require_exists=True)
    for child in worktree_root.iterdir():
        if child.name == ".controller-v2.lock":
            if runtime.is_reparse(child) or not child.is_file() or child.stat(follow_symlinks=False).st_nlink != 1:
                raise V2Error(f"unsafe controller lock entry requires quarantine: {child}")
            continue
        if runtime.is_reparse(child) or not child.is_dir():
            raise V2Error(f"unsafe stale worktree entry requires quarantine: {child}")
        private = child / "private_folds"
        if private.exists():
            if runtime.is_reparse(private) or not private.is_dir() or any(private.iterdir()):
                raise V2Error(f"stale private hidden-fold material must be quarantined before a new run: {private}")


def dry_run(
    config: Config,
    run_dir: Path,
    journal: Journal,
    base_commit: str,
    protected: dict[str, Any],
    authorization: dict[str, Any],
    authorization_sha256: str,
    deadline: float,
) -> tuple[str, dict[str, Any], int]:
    workspace_root = config.worktree_root / run_dir.name
    workspace_root.mkdir(parents=True, exist_ok=True)
    lease_root = workspace_root / "dry_candidate_lease"
    isolation = workspace_root / "dry_candidate_control"
    lease_root.mkdir()
    evidence = run_dir / "sandbox"
    evidence.mkdir()
    gates = gate_template()
    set_gate(gates, "authorization", "PASS", "authorization_evidence.json")
    environment, scratch = runtime.prepare_candidate_sandbox(
        isolation,
        workspace_root,
        [lease_root],
        scratch=lease_root / "temp",
        profile="candidate",
        implementation=config.sandbox_implementation,
    )
    acl_lease: runtime.AclLease | None = None
    cleanup_error: BaseException | None = None
    try:
        acl_lease = runtime.start_candidate_acl_lease(
            lease_path=workspace_root / "acl_lease_dry_run.json",
            root=lease_root,
            authorized_parent=workspace_root,
            helper=config.repo / "improvement_acl_helper.ps1",
            control_dir=isolation,
            evidence_dir=evidence,
            authorization_sha256=authorization_sha256,
            worktree_path=lease_root / "worktree-not-created",
            codex=config.codex,
            python=config.python,
            profile="candidate",
            environment=environment,
            canary_source=config.repo / "improvement_sandbox_canary.py",
            forbidden=[config.repo, Path.home().resolve()],
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            token=secrets.token_hex(16),
            registry=_ACTIVE_RUN.acl_leases if _ACTIVE_RUN is not None else None,
        )
        container_qualification = runtime.qualify_candidate_container(
            docker=config.docker,
            image_id=str(authorization["candidate_image_id"]),
            policy_path=config.repo / "candidate_container_policy_v1.json",
            workspace_root=lease_root,
            canary_source=config.repo / "improvement_container_canary.py",
            run_id=run_dir.name,
            cycle=0,
            authorization_sha256=authorization_sha256,
            registry_dir=workspace_root,
            cwd=config.repo,
            environment=trusted_environment(),
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            evidence_dir=evidence,
            token=secrets.token_hex(16),
        )
        atomic(
            evidence / "isolation_qualification.json",
            {
                "schema_version": "blast-pit.composite-isolation-qualification.v1",
                "pass": True,
                "windows_patch_boundary": "sandbox_qualification.json",
                "candidate_execution_boundary": "container_qualification.json",
                "container_image_id": container_qualification["image_id"],
                "python_audit_hook_security_boundary": False,
            },
        )
        set_gate(gates, "sandbox_canary", "PASS", "sandbox/isolation_qualification.json")
    finally:
        try:
            runtime.recover_governed_containers(
                docker=config.docker,
                worktree_root=config.worktree_root,
                cwd=config.repo,
                environment=trusted_environment(),
                timeout=min(120, max(15, int(deadline - time.monotonic()))),
                evidence_dir=evidence / "container_cleanup",
                run_id=run_dir.name,
            )
            runtime.assert_governed_containers_quiescent(
                docker=config.docker,
                worktree_root=config.worktree_root,
                run_id=run_dir.name,
                cwd=config.repo,
                environment=trusted_environment(),
                timeout=min(120, max(15, int(deadline - time.monotonic()))),
                evidence=evidence / "container_quiescence.json",
            )
        except Exception as exc:
            cleanup_error = exc
        if acl_lease is not None and cleanup_error is None:
            try:
                runtime.empty_directory_contents(
                    lease_root,
                    workspace_root,
                    expected_identity=acl_lease.record["root_identity"],
                )
                runtime.restore_candidate_acl_lease(
                    acl_lease,
                    timeout=min(120, max(1, int(deadline - time.monotonic()))),
                    cleanup=False,
                )
                atomic(evidence / "acl_lease_final.json", acl_lease.record)
                if _ACTIVE_RUN is not None and acl_lease in _ACTIVE_RUN.acl_leases:
                    _ACTIVE_RUN.acl_leases.remove(acl_lease)
                runtime.safe_remove_tree(lease_root, workspace_root)
            except Exception as exc:
                cleanup_error = exc
        elif acl_lease is None and lease_root.exists() and cleanup_error is None:
            try:
                runtime.safe_remove_tree(lease_root, workspace_root)
            except Exception as exc:
                cleanup_error = exc
        if isolation.exists() and cleanup_error is None:
            try:
                runtime.safe_remove_tree(isolation, workspace_root)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is None:
            try:
                if _ACTIVE_RUN is None:
                    raise runtime.RuntimeFailure("dry-run ACL context is unavailable")
                assert_acl_quiescent(config, run_dir.name, _ACTIVE_RUN, run_dir / "acl_restoration_gate.json")
                if workspace_root.exists():
                    runtime.safe_remove_tree(workspace_root, config.worktree_root)
            except Exception as exc:
                cleanup_error = exc
        atomic(
            run_dir / "dry_cleanup.json",
            {
                "pass": cleanup_error is None and not workspace_root.exists(),
                "error": _safe_error(cleanup_error) if cleanup_error else None,
                "workspace_root": str(workspace_root),
                "exists_after": workspace_root.exists(),
            },
        )
    if cleanup_error is not None:
        raise runtime.RuntimeFailure(f"dry-run isolation cleanup failed: {_safe_error(cleanup_error)}") from cleanup_error
    passed = compare_protection(protected, production_snapshot(config), run_dir / "production_guard.json")
    set_gate(gates, "external_guard", "PASS" if passed else "FAIL", "production_guard.json")
    set_gate(gates, "production_guard", "PASS" if passed else "FAIL", "production_guard.json")
    state = "DRY_RUN_COMPLETE" if passed else "ERROR"
    journal.add(state, sandbox_canary=passed, production_modified=not passed)
    decision = operator_decision(
        run_id=run_dir.name,
        cycle=1,
        execution="NOT_RUN" if passed else "FAILED",
        review="NOT_RUN",
        promotion="NOT_RUN",
        gates=gates,
        base_commit=base_commit,
        candidate_commit=None,
        diff_sha256=None,
        worktree=str(lease_root / "worktree-not-created"),
        reviews=[],
        rubric_value=empty_rubric("dry run does not score candidates"),
        blockers=[] if passed else ["production guard failed"],
        warnings=["dry run: candidate build, tests, evaluation, and reviews were not executed"],
        production_modified=not passed,
    )
    return state, decision, 0 if passed else 2


def seal_acl_recovery_event(
    config: Config,
    event_dir: Path,
    *,
    status: str,
    leases: Sequence[dict[str, Any]],
    error: str | None,
) -> dict[str, Any]:
    if status not in {"RECOVERED", "RECOVERY_REQUIRED"}:
        raise V2Error("invalid ACL recovery event status")
    decision = {
        "schema_version": "blast-pit.acl-recovery-decision.v1",
        "event_id": event_dir.name,
        "status": status,
        "leases": list(leases),
        "error": error,
        "candidate_run_started": False,
        "promotion_authorized": False,
        "release_authorized": False,
        "recorded_at": utc_now(),
    }
    atomic(event_dir / "recovery_decision.json", decision)
    manifest = {
        "schema_version": "blast-pit.acl-recovery-manifest.v1",
        "event_id": event_dir.name,
        "status": status,
        "sealed_at": utc_now(),
        "files": runtime.strict_manifest(event_dir),
    }
    atomic(event_dir / "recovery_manifest.json", manifest)
    manifest_sha256 = legacy.sha256_file(event_dir / "recovery_manifest.json")
    decision_sha256 = legacy.sha256_file(event_dir / "recovery_decision.json")
    ledger_path = config.artifact_root / "acl_recovery_ledger.jsonl"
    previous = "0" * 64
    sequence = 0
    if ledger_path.exists():
        if ledger_path.is_symlink() or not ledger_path.is_file() or ledger_path.stat().st_size > 4_000_000:
            raise V2Error("ACL recovery ledger is unsafe")
        for number, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise V2Error(f"ACL recovery ledger JSON is invalid at line {number}") from exc
            supplied = row.get("ledger_hash")
            unsigned = dict(row); unsigned.pop("ledger_hash", None)
            if row.get("sequence") != sequence + 1 or row.get("previous_ledger_hash") != previous or digest(unsigned) != supplied:
                raise V2Error(f"ACL recovery ledger chain mismatch at line {number}")
            sequence += 1
            previous = str(supplied)
            if row.get("event_id") == event_dir.name:
                raise V2Error("ACL recovery event is already ledgered")
    relative = event_dir.resolve().relative_to(config.artifact_root.resolve()).as_posix()
    unsigned = {
        "schema_version": "blast-pit.acl-recovery-ledger.v1",
        "sequence": sequence + 1,
        "previous_ledger_hash": previous,
        "event_id": event_dir.name,
        "event_path": relative,
        "status": status,
        "recovery_manifest_sha256": manifest_sha256,
        "recovery_decision_sha256": decision_sha256,
        "recorded_at": utc_now(),
    }
    ledger_row = {**unsigned, "ledger_hash": digest(unsigned)}
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical(ledger_row) + "\n")
        handle.flush(); os.fsync(handle.fileno())
    latest = {
        "schema_version": "blast-pit.acl-recovery-latest.v1",
        "event_id": event_dir.name,
        "event_path": relative,
        "status": status,
        "ledger_hash": ledger_row["ledger_hash"],
        "recovery_manifest_sha256": manifest_sha256,
        "recovery_decision_sha256": decision_sha256,
        "active_leases": [item.get("lease_path") for item in leases if item.get("state") not in runtime.ACL_RESTORED_STATES],
    }
    atomic(config.artifact_root / "acl_recovery_latest.json", latest)
    return latest


def recover_persisted_acl_leases(
    config: Config,
    *,
    current_authorization_sha256: str,
    run_id: str | None = None,
    context: ActiveRunContext | None = None,
) -> list[dict[str, Any]]:
    """Restore every validated durable lease while the controller lock is held."""

    paths = runtime.discover_acl_lease_paths(config.worktree_root, run_id)
    if not paths:
        return []
    retained_parent = (context.run_dir / "acl_recovery") if context is not None else (config.artifact_root / "acl_recovery")
    retained_parent.mkdir(parents=True, exist_ok=True)
    event_id = datetime.now(timezone.utc).strftime("recovery_%Y%m%dT%H%M%SZ_") + secrets.token_hex(4)
    event_dir = retained_parent / event_id
    event_dir.mkdir(parents=False, exist_ok=False)
    recovered: list[dict[str, Any]] = []
    failure: BaseException | None = None
    for lease_path in paths:
        workspace = lease_path.parent
        attempt = f"{workspace.name}-{lease_path.stem}-{secrets.token_hex(4)}"
        evidence_dir = event_dir / attempt
        control_dir = workspace / f".acl-recovery-{secrets.token_hex(8)}"
        evidence_dir.mkdir(parents=False, exist_ok=False)
        control_dir.mkdir(parents=False, exist_ok=False)
        try:
            lease = runtime.load_acl_lease(
                lease_path,
                worktree_root=config.worktree_root,
                helper=config.repo / "improvement_acl_helper.ps1",
                recovery_control_dir=control_dir,
                recovery_evidence_dir=evidence_dir,
            )
            retained_helper = evidence_dir / "recovery_helper.ps1"
            shutil.copyfile(lease.helper, retained_helper, follow_symlinks=False)
            with retained_helper.open("rb+") as handle:
                os.fsync(handle.fileno())
            if retained_helper.stat(follow_symlinks=False).st_nlink != 1 or legacy.sha256_file(retained_helper) != lease.record["helper_sha256"]:
                raise runtime.RuntimeFailure("retained ACL recovery helper evidence failed hash verification")
            atomic(
                evidence_dir / "recovery_preflight.json",
                {
                    "schema_version": "blast-pit.acl-recovery-preflight.v1",
                    "lease_path": str(lease_path),
                    "lease_state": lease.record["state"],
                    "current_authorization_sha256": current_authorization_sha256,
                    "lease_authorization_sha256": lease.record["authorization_sha256"],
                    "authorization_matches_current": lease.record["authorization_sha256"] == current_authorization_sha256,
                    "helper_sha256": lease.record["helper_sha256"],
                    "root_identity": lease.record["root_identity"],
                },
            )
            if lease.root.exists():
                worktree = Path(lease.record["worktree_path"])
                if worktree.exists():
                    removal = git(
                        config,
                        ["worktree", "remove", "--force", worktree],
                        timeout=120,
                        evidence=evidence_dir / "worktree_remove.json",
                        require_success=False,
                    )
                    if removal.return_code != 0 and worktree.exists():
                        runtime.safe_remove_tree(worktree, lease.root)
                runtime.restore_candidate_acl_lease(lease, timeout=120, cleanup=True, recovered=True)
                atomic(evidence_dir / "acl_lease_final.json", lease.record)
                runtime.safe_remove_tree(lease.root, lease.authorized_parent)
            else:
                atomic(evidence_dir / "acl_lease_final.json", lease.record)
            if context is not None:
                context.acl_leases[:] = [item for item in context.acl_leases if item.path != lease_path]
            row = {
                "lease_path": str(lease_path),
                "state": lease.record["state"],
                "root_removed": not lease.root.exists(),
                "evidence": str(evidence_dir),
            }
            atomic(evidence_dir / "recovery_outcome.json", {"pass": True, **row})
            recovered.append(row)
        except Exception as exc:
            failure = exc
            failed_row = {
                "lease_path": str(lease_path),
                "state": "RECOVERY_REQUIRED",
                "root_removed": False,
                "evidence": str(evidence_dir),
                "error": _safe_error(exc),
            }
            atomic(
                evidence_dir / "recovery_outcome.json",
                {"pass": False, **failed_row},
            )
            recovered.append(failed_row)
        finally:
            if control_dir.exists():
                try:
                    runtime.safe_remove_tree(control_dir, workspace)
                except Exception:
                    # Retain the bounded recovery control directory for diagnosis.
                    pass
        if failure is not None:
            break
    if failure is not None:
        atomic(event_dir / "recovery_summary.json", {"pass": False, "leases": recovered, "error": _safe_error(failure)})
        seal_acl_recovery_event(
            config,
            event_dir,
            status="RECOVERY_REQUIRED",
            leases=recovered,
            error=_safe_error(failure),
        )
        raise runtime.RuntimeFailure(
            f"persisted ACL lease recovery failed for {recovered[-1]['lease_path']}: {_safe_error(failure)}"
        ) from failure
    git(config, ["worktree", "prune"], timeout=60, require_success=False)
    workspace_cleanup: list[dict[str, Any]] = []
    for workspace in sorted({path.parent for path in paths}):
        try:
            if workspace.exists():
                runtime.safe_remove_tree(workspace, config.worktree_root)
            workspace_cleanup.append({"workspace": str(workspace), "removed": not workspace.exists()})
        except Exception as exc:
            cleanup_failure = {
                "lease_path": str(workspace),
                "state": "RECOVERY_REQUIRED",
                "root_removed": True,
                "evidence": str(event_dir),
                "error": _safe_error(exc),
            }
            recovered.append(cleanup_failure)
            atomic(
                event_dir / "recovery_summary.json",
                {"pass": False, "leases": recovered, "workspace_cleanup": workspace_cleanup, "error": _safe_error(exc)},
            )
            seal_acl_recovery_event(
                config,
                event_dir,
                status="RECOVERY_REQUIRED",
                leases=recovered,
                error=_safe_error(exc),
            )
            raise runtime.RuntimeFailure(f"ACL recovery workspace cleanup failed: {_safe_error(exc)}") from exc
    atomic(event_dir / "recovery_summary.json", {"pass": True, "leases": recovered, "workspace_cleanup": workspace_cleanup})
    latest = seal_acl_recovery_event(config, event_dir, status="RECOVERED", leases=recovered, error=None)
    for row in recovered:
        row["recovery_event_id"] = event_id
        row["recovery_ledger_hash"] = latest["ledger_hash"]
    return recovered


def assert_acl_quiescent(config: Config, run_id: str, context: ActiveRunContext, evidence_path: Path) -> None:
    if context.acl_leases:
        raise runtime.RuntimeFailure("in-memory ACL lease registry is not empty")
    rows: list[dict[str, Any]] = []
    for path in runtime.discover_acl_lease_paths(config.worktree_root, run_id):
        record = strict_json(path)
        state = record.get("state")
        if state not in runtime.ACL_RESTORED_STATES:
            raise runtime.RuntimeFailure(f"ACL lease is not restored: {path} ({state})")
        rows.append({"path": str(path), "state": state, "sha256": legacy.sha256_file(path)})
    atomic(
        evidence_path,
        {
            "schema_version": "blast-pit.acl-restoration-gate.v1",
            "pass": True,
            "active_leases": [],
            "restored_records": rows,
        },
    )


def _run_unfinalized(config: Config) -> int:
    global _ACTIVE_RUN
    deadline = time.monotonic() + config.max_runtime_seconds
    base_status = git(config, ["status", "--porcelain=v1", "--untracked-files=all"], timeout=60).stdout
    if base_status.strip():
        raise V2Error(f"protected checkout must be clean before autonomous work:\n{base_status[:4000]}")
    base_commit = git(config, ["rev-parse", "HEAD"], timeout=60).stdout.strip()
    top = Path(git(config, ["rev-parse", "--show-toplevel"], timeout=60).stdout.strip()).resolve()
    if top != config.repo:
        raise V2Error("configured repository is not the active Git top level")
    authorization, authorization_sha256, cli_version = load_authorization(config)

    config.artifact_root.mkdir(parents=True, exist_ok=True)
    config.worktree_root.mkdir(parents=True, exist_ok=True)
    runtime.validate_no_reparse_ancestors(config.artifact_root, require_exists=True)
    runtime.validate_no_reparse_ancestors(config.worktree_root, require_exists=True)
    reject_stale_private_folds(config.worktree_root)

    if config.resume_run:
        run_dir = config.artifact_root / config.resume_run
        if not run_dir.is_dir() or run_dir.is_symlink():
            raise V2Error("resume run does not exist")
        journal = Journal(run_dir)
        if journal.last_state not in TERMINAL_STATES:
            raise V2Error("partial runs are immutable and cannot resume in place; start a fresh recovery run")
        improvement_operator.verify_record(config.artifact_root, config.resume_run)
        decision = strict_json(run_dir / "operator_decision.json")
        return 0 if decision.get("promotion") == "HUMAN_REVIEW_PENDING" or journal.last_state == "DRY_RUN_COMPLETE" else 2

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4)
    if not runtime.RUN_ID_RE.fullmatch(run_id):
        raise V2Error("generated run ID is invalid")
    run_dir = config.artifact_root / run_id
    run_dir.mkdir(parents=False, exist_ok=False)
    journal = Journal(run_dir)
    journal.add("AUTHORIZED", authorization_sha256=authorization_sha256, controller_version=VERSION)
    protected = production_snapshot(config)
    _ACTIVE_RUN = ActiveRunContext(config, run_dir, journal, base_commit, protected, authorization_sha256)
    atomic(run_dir / "protection_before.json", protected)
    atomic(
        run_dir / "authorization_evidence.json",
        {
            "schema_version": "blast-pit.improvement-authorization-evidence.v2",
            "authorization_sha256": authorization_sha256,
            "authorization_path": config.authorization.name,
            "control_hashes": expected_control_hashes(config),
            "codex_cli_version": cli_version,
            "codex_launcher_sha256": legacy.sha256_file(config.codex),
            "model": config.model,
            "role_policy_version": runtime.ROLE_POLICY_VERSION,
            "sandbox_implementation": config.sandbox_implementation,
            "candidate_execution_boundary": authorization["candidate_execution_boundary"],
            "candidate_container_runtime": authorization["candidate_container_runtime"],
            "candidate_image_id": authorization["candidate_image_id"],
            "docker_host_identity": authorization["docker_host_identity"],
            "automatic_push": False,
            "automatic_merge": False,
            "automatic_release": False,
        },
    )
    runtime.verify_candidate_container_host(
        docker=config.docker,
        cwd=config.repo,
        environment=trusted_environment(),
        timeout=remaining_timeout(deadline, 120),
        image_id=str(authorization["candidate_image_id"]),
        expected_identity=authorization["docker_host_identity"],
        policy_path=config.repo / "candidate_container_policy_v1.json",
        evidence=run_dir / "container_host_preflight.json",
    )

    if config.dry_run:
        state, decision, exit_code = dry_run(
            config,
            run_dir,
            journal,
            base_commit,
            protected,
            authorization,
            authorization_sha256,
            deadline,
        )
        atomic(run_dir / "operator_decision.json", decision)
        seal_run(run_dir, base_commit, state)
        publish_run(config, run_dir, state)
        return exit_code

    protected_full_suite = run_protected_harness_preflight(config, run_dir, deadline)
    private_fold_root = config.worktree_root / run_id / "private_folds"
    private_fold_root.mkdir(parents=True, exist_ok=False)
    outcomes: list[CycleOutcome] = []
    previous_cycle_hash = "0" * 64
    selected: CycleOutcome | None = None
    original_baseline: Path | None = None
    base = base_commit
    fatal_execution: str | None = None

    for cycle in range(1, config.cycles + 1):
        if time.monotonic() >= deadline:
            fatal_execution = "TIMEOUT"
            break
        outcome = execute_cycle(
            config,
            run_id=run_id,
            run_dir=run_dir,
            journal=journal,
            cycle=cycle,
            base_commit=base,
            protected_snapshot=protected,
            previous_manifest_sha256=previous_cycle_hash,
            prior_outcomes=outcomes,
            private_fold_root=private_fold_root,
            protected_full_suite=protected_full_suite,
            authorization=authorization,
            authorization_sha256=authorization_sha256,
            deadline=deadline,
        )
        outcomes.append(outcome)
        previous_cycle_hash = outcome.manifest_sha256 or previous_cycle_hash
        if original_baseline is None and outcome.base_commit == base_commit and outcome.baseline_checkpoint:
            original_baseline = outcome.baseline_checkpoint
        if outcome.status == "ACCEPTED":
            selected = outcome
            base = outcome.candidate_commit or base
        elif outcome.execution in {"FAILED", "TIMEOUT"}:
            fatal_execution = outcome.execution
            break

    # No builder or remediator is invoked after this point. Hidden folds may now be disclosed.
    disclosure = run_dir / "hidden_evaluation_disclosure"
    disclosure.mkdir()
    for outcome in outcomes:
        if outcome.private_fold_record:
            atomic(disclosure / f"cycle_{outcome.cycle:03d}_fold_b.json", outcome.private_fold_record)
        if outcome.raw_evaluation:
            atomic(disclosure / f"cycle_{outcome.cycle:03d}_raw_scores.json", outcome.raw_evaluation)

    root_gates = gate_template()
    set_gate(root_gates, "authorization", "PASS", "authorization_evidence.json")
    root_reviews: list[dict[str, Any]] = []
    root_review_artifacts: dict[str, str] = {}
    root_final_qa: dict[str, Any] | None = None
    root_evaluation: dict[str, Any] | None = None
    root_blockers: list[str] = []
    root_warnings = [f"cycle {item.cycle:03d}: {reason}" for item in outcomes if item.status != "ACCEPTED" for reason in item.blockers]
    selected_diff = ""
    selected_diff_sha256: str | None = None
    root_candidate_commit = selected.candidate_commit if selected else None

    if selected and root_candidate_commit and original_baseline and selected.candidate_checkpoint and fatal_execution is None:
        try:
            selected_diff = git(
                config,
                ["diff", "--no-ext-diff", "--binary", base_commit, root_candidate_commit, "--", *sorted(ALLOWED_CHANGED_FILES)],
                timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            ).stdout
            cumulative_paths = runtime.parse_patch_paths(selected_diff, ALLOWED_CHANGED_FILES, config.max_diff_bytes)
            selected_diff_sha256 = hashlib.sha256(selected_diff.encode("utf-8")).hexdigest()
            runtime.atomic_text(run_dir / "selected_candidate.patch", selected_diff)
            cumulative_reasons = diff_policy_reasons(selected_diff, cumulative_paths)
            atomic(
                run_dir / "cumulative_security_gate.json",
                {
                    "pass": not cumulative_reasons,
                    "changed_files": cumulative_paths,
                    "diff_sha256": selected_diff_sha256,
                    "diff_bytes": len(selected_diff.encode("utf-8")),
                    "reasons": cumulative_reasons,
                },
            )
            if cumulative_reasons:
                raise V2Error("cumulative candidate security gate failed: " + "; ".join(cumulative_reasons))
            source_packet_dir = run_dir / "selected_source"
            source_packet_dir.mkdir()
            for name in sorted(ALLOWED_CHANGED_FILES):
                runtime.atomic_text(source_packet_dir / name, source_at_commit(config, root_candidate_commit, name, deadline))
            final_packet = bounded_source_packet(
                config,
                source_packet_dir,
                diff=selected_diff,
                extra={
                    "selected_cycle": selected.cycle,
                    "cycle_evaluation": selected.evaluation,
                    "selected_gate_evidence": selected_evidence_summary(run_dir, selected),
                    "cumulative_security_gate": strict_json(run_dir / "cumulative_security_gate.json"),
                    "automatic_promotion": False,
                },
            )
            final_role_isolation = config.worktree_root / run_id / "root_role_isolations"
            final_role_isolation.mkdir()
            root_reviews, _ = run_specialist_panel(
                config,
                packet=final_packet,
                diff_sha256=selected_diff_sha256,
                evidence_root=run_dir / "roles",
                isolation_root=final_role_isolation,
                attempt_name="final_review",
                deadline=deadline,
            )
            root_review_artifacts = {role: f"roles/{role}/final_review/final.json" for role in ROLES}
            root_adjudication = adjudicate(root_reviews)
            atomic(run_dir / "selected_adjudication.json", root_adjudication)
            if root_adjudication["verdict"] == "PASS":
                set_gate(root_gates, "specialist_consensus", "PASS", "selected_adjudication.json")
            else:
                set_gate(root_gates, "specialist_consensus", "FAIL", "selected_adjudication.json")
                root_blockers.append("final aggregate specialist panel requires changes")

            final_fold = private_fold_root / "final_fold_c.json"
            final_fold_record = create_hidden_fold(final_fold)
            try:
                final_baseline_score, final_candidate_score = root_fold_scores(
                    config,
                    run_id=run_id,
                    baseline_checkpoint=original_baseline,
                    candidate_checkpoint=selected.candidate_checkpoint,
                    fold=final_fold,
                    authorization=authorization,
                    authorization_sha256=authorization_sha256,
                    run_dir=run_dir,
                    deadline=deadline,
                )
            finally:
                final_fold.unlink(missing_ok=True)
            final_paired = paired_metric_gate(final_baseline_score, final_candidate_score, "algorithm", 0)
            root_evaluation = {
                "schema_version": "blast-pit.final-paired-evaluation.v2",
                "pass": final_paired["pass"],
                "fold_id": final_baseline_score["fold_id"],
                "fold_sha256": final_baseline_score["fold_sha256"],
                "baseline": aggregate_score(final_baseline_score),
                "candidate": aggregate_score(final_candidate_score),
                "paired": final_paired,
            }
            atomic(run_dir / "final_evaluation_summary.json", root_evaluation)
            atomic(disclosure / "final_fold_c.json", final_fold_record)
            atomic(disclosure / "final_raw_scores.json", {"baseline": final_baseline_score, "candidate": final_candidate_score})
            set_gate(root_gates, "evaluation", "PASS" if final_paired["pass"] else "FAIL", "final_evaluation_summary.json")
            if not final_paired["pass"]:
                root_blockers.append("final held-out Fold C did not prove aggregate improvement")

            for name in ("sandbox_canary", "compile", "focused_tests", "full_tests"):
                selected_gate = selected.gates[name]
                evidence = selected_gate.get("evidence")
                set_gate(root_gates, name, selected_gate["status"], f"cycle_{selected.cycle:03d}/{evidence}" if evidence else None)
            set_gate(root_gates, "filesystem", "PASS", "cumulative_security_gate.json")
            set_gate(root_gates, "security", "PASS", "cumulative_security_gate.json")
            set_gate(root_gates, "external_guard", "PASS", "production_guard.json")
            set_gate(root_gates, "production_guard", "PASS", "production_guard.json")

            mandatory = sorted({finding["id"] for review in root_reviews for finding in review.get("findings", [])})
            qa_packet = bounded_source_packet(
                config,
                source_packet_dir,
                diff=selected_diff,
                extra={
                    "specialist_reviews": root_reviews,
                    "evaluation": root_evaluation,
                    "gates": gate_bools(root_gates),
                    "selected_gate_evidence": selected_evidence_summary(run_dir, selected),
                    "cumulative_security_gate": strict_json(run_dir / "cumulative_security_gate.json"),
                    "mandatory_findings": mandatory,
                },
            )
            root_final_qa = run_role(
                config,
                role="final_qa",
                prompt=final_qa_prompt(selected_diff_sha256, qa_packet, mandatory),
                schema=config.repo / "schemas" / "final_qa_v2.schema.json",
                evidence_dir=run_dir / "root_final_qa_role",
                isolation=final_role_isolation / "final-qa",
                isolation_root=final_role_isolation,
                deadline=deadline,
            )
            verify_final_qa(config, root_final_qa, selected_diff_sha256, mandatory)
            atomic(run_dir / "final_qa.json", root_final_qa)
            set_gate(root_gates, "final_qa", "PASS" if root_final_qa["verdict"] == "PASS" else "FAIL", "final_qa.json")
            if root_final_qa["verdict"] != "PASS":
                root_blockers.append("independent root final QA did not pass")
            if final_role_isolation.exists():
                runtime.safe_remove_tree(final_role_isolation, config.worktree_root / run_id)
        except runtime.RuntimeTimeout as exc:
            fatal_execution = "TIMEOUT"
            root_blockers.append(_safe_error(exc))
        except (V2Error, runtime.RuntimeFailure, OSError, subprocess.SubprocessError) as exc:
            fatal_execution = "FAILED"
            root_blockers.append(_safe_error(exc))
    else:
        if fatal_execution is None:
            root_blockers.append("no accepted candidate completed baseline, evaluation, specialist, and QA gates")

    if _ACTIVE_RUN is None:
        raise runtime.RuntimeFailure("root isolation context is unavailable before terminalization")
    runtime.assert_governed_containers_quiescent(
        docker=config.docker,
        worktree_root=config.worktree_root,
        run_id=run_id,
        cwd=config.repo,
        environment=trusted_environment(),
        timeout=remaining_timeout(deadline, 120),
        evidence=run_dir / "container_quiescence.json",
    )
    assert_acl_quiescent(config, run_id, _ACTIVE_RUN, run_dir / "acl_restoration_gate.json")

    workspace_cleanup_pass = True
    workspace_run_root = config.worktree_root / run_id
    try:
        if workspace_run_root.exists():
            retained_worktrees = [path for path in workspace_run_root.glob("cycle_*_worktree") if path.exists()]
            if retained_worktrees:
                raise runtime.RuntimeFailure(f"registered or retained worktrees require quarantine: {retained_worktrees}")
            runtime.safe_remove_tree(workspace_run_root, config.worktree_root)
    except runtime.RuntimeFailure as exc:
        workspace_cleanup_pass = False
        fatal_execution = "FAILED"
        root_blockers.append(f"run workspace cleanup quarantined: {_safe_error(exc)}")
    atomic(run_dir / "workspace_cleanup.json", {"pass": workspace_cleanup_pass, "root": str(workspace_run_root), "exists_after": workspace_run_root.exists()})

    production_pass = compare_protection(protected, production_snapshot(config), run_dir / "production_guard.json")
    set_gate(root_gates, "external_guard", "PASS" if production_pass else "FAIL", "production_guard.json")
    set_gate(root_gates, "production_guard", "PASS" if production_pass else "FAIL", "production_guard.json")
    if not production_pass:
        fatal_execution = "FAILED"
        root_blockers.append("protected checkout or retained production artifacts changed")

    rubric_evidence = {
        "architecture": "roles/architecture_state/final_review/final.json",
        "workflow": "roles/workflow_state/final_review/final.json",
        "security": "roles/security_sandbox/final_review/final.json",
        "algorithm": "roles/algorithm_objective/final_review/final.json",
        "determinism": "roles/testing_reliability/final_review/final.json",
        "testing": "roles/testing_reliability/final_review/final.json",
        "evaluation": "final_evaluation_summary.json",
        "evidence": "roles/governance_evidence/final_review/final.json",
        "maintainability": "roles/docs_ux/final_review/final.json",
        "specialist_consensus": "final_qa.json",
    }
    root_rubric = rubric(root_reviews, gate_bools(root_gates), root_evaluation, root_final_qa, rubric_evidence)
    atomic(run_dir / "rubric.json", root_rubric)
    ready = (
        fatal_execution is None
        and production_pass
        and selected is not None
        and root_rubric["ten_out_of_ten"]
        and not root_blockers
        and all(root_gates[name]["status"] == "PASS" for name in CORE_GATES)
    )
    if fatal_execution == "TIMEOUT":
        execution = "TIMEOUT"
        terminal = "TIMEOUT"
    elif fatal_execution == "FAILED":
        execution = "FAILED"
        terminal = "COMPLETE_WITH_ERRORS"
    else:
        execution = "SUCCESS"
        terminal = "COMPLETE" if ready and all(item.status == "ACCEPTED" for item in outcomes) else "COMPLETE_WITH_REJECTIONS"
    review_status = "PASS" if ready else ("BLOCK" if fatal_execution is not None or selected is None else "CHANGES_REQUIRED")
    promotion = "HUMAN_REVIEW_PENDING" if ready else ("REJECTED" if selected else "NOT_ELIGIBLE")
    if ready:
        root_blockers = []
    journal.add(terminal, accepted=sum(item.status == "ACCEPTED" for item in outcomes), rejected=sum(item.status == "REJECTED" for item in outcomes), ready_for_human_review=ready)
    root_decision = operator_decision(
        run_id=run_id,
        cycle=selected.cycle if selected else max(1, len(outcomes)),
        execution=execution,
        review=review_status,
        promotion=promotion,
        gates=root_gates,
        base_commit=base_commit,
        candidate_commit=root_candidate_commit,
        diff_sha256=selected_diff_sha256,
        worktree=selected.worktree if selected else str(config.worktree_root / run_id),
        reviews=decision_reviews(root_reviews, root_review_artifacts, "final_qa.json" if root_final_qa else None, root_final_qa),
        rubric_value=root_rubric,
        blockers=root_blockers,
        warnings=root_warnings,
        production_modified=not production_pass,
    )
    validate_schema(config.repo / "schemas" / "improvement_operator_decision_v2.schema.json", root_decision)
    atomic(run_dir / "operator_decision.json", root_decision)
    seal_run(run_dir, base_commit, terminal)
    publish_run(config, run_dir, terminal)
    return 0 if ready else 2


def publish_run(config: Config, run_dir: Path, status: str) -> None:
    manifest_path = run_dir / "evidence_manifest.json"
    decision_path = run_dir / "operator_decision.json"
    manifest_hash = legacy.sha256_file(manifest_path)
    decision_hash = legacy.sha256_file(decision_path)
    ledger_path = config.artifact_root / "audit_ledger.jsonl"

    def append_record() -> str:
        if ledger_path.is_symlink():
            raise V2Error("local audit ledger path is an unsafe symlink")
        ledger_hash = append_local_ledger(
            config.artifact_root,
            {
                "run_id": run_dir.name,
                "evidence_manifest_sha256": manifest_hash,
                "operator_decision_sha256": decision_hash,
                "recorded_at": utc_now(),
            },
        )
        return ledger_hash

    if not ledger_path.exists():
        ledger_hash = append_record()
    else:
        try:
            ledger_entry, _ = improvement_operator._local_ledger_entry(config.artifact_root, run_dir.name)
            if ledger_entry.get("evidence_manifest_sha256") != manifest_hash or ledger_entry.get("operator_decision_sha256") != decision_hash:
                raise V2Error("existing local-ledger record disagrees with the sealed run")
            ledger_hash = ledger_entry["ledger_hash"]
        except improvement_operator.OperatorError as exc:
            if "not anchored" not in str(exc):
                raise
            ledger_hash = append_record()

    # Verify the sealed bundle against the ledger before publishing it as latest.
    improvement_operator.verify_record(config.artifact_root, run_dir.name)
    latest_path = config.artifact_root / "latest.json"
    previous_latest = latest_path.read_bytes() if latest_path.is_file() and not latest_path.is_symlink() else None
    atomic(
        latest_path,
        {
            "run_id": run_dir.name,
            "status": status,
            "evidence_manifest_sha256": manifest_hash,
            "operator_decision_sha256": decision_hash,
            "ledger_hash": ledger_hash,
        },
    )
    try:
        improvement_operator.verify_record(config.artifact_root, run_dir.name)
    except Exception:
        if previous_latest is None:
            latest_path.unlink(missing_ok=True)
        else:
            temporary = latest_path.with_name(f".{latest_path.name}.{os.getpid()}.rollback")
            temporary.write_bytes(previous_latest)
            os.replace(temporary, latest_path)
        raise


def emergency_finalize(context: ActiveRunContext, cause: BaseException) -> int:
    config = context.config
    run_dir = context.run_dir
    journal = context.journal
    error_text = _safe_error(cause)
    atomic(run_dir / "emergency_error.json", {"error": error_text, "recorded_at": utc_now()})
    try:
        recovered_containers = recover_persisted_candidate_containers(config, run_id=run_dir.name)
        recovered = recover_persisted_acl_leases(
            config,
            current_authorization_sha256=context.authorization_sha256
            or (legacy.canonical_text_sha256(config.authorization) if config.authorization.is_file() else "0" * 64),
            run_id=run_dir.name,
            context=context,
        )
        assert_acl_quiescent(config, run_dir.name, context, run_dir / "acl_restoration_gate.json")
    except Exception as recovery_error:
        atomic(
            run_dir / "emergency_recovery_required.json",
            {
                "schema_version": "blast-pit.emergency-recovery-required.v1",
                "pass": False,
                "original_error": error_text,
                "recovery_error": _safe_error(recovery_error),
                "candidate_container_recovery": "RECOVERY_REQUIRED",
                "active_leases": [str(item.path) for item in context.acl_leases],
                "sealed": False,
                "published": False,
            },
        )
        raise runtime.RuntimeFailure("emergency container or ACL restoration is incomplete; evidence remains unsealed and unpublished") from recovery_error
    manifest_path = run_dir / "evidence_manifest.json"
    if manifest_path.is_file():
        state = strict_json(run_dir / "state.json").get("status", "COMPLETE_WITH_ERRORS")
        publish_run(config, run_dir, str(state))
        return 2

    workspace_error: str | None = None
    workspace = config.worktree_root / run_dir.name
    try:
        if workspace.exists():
            runtime.safe_remove_tree(workspace, config.worktree_root)
    except Exception as exc:
        workspace_error = _safe_error(exc)
    atomic(
        run_dir / "emergency_workspace_cleanup.json",
        {
            "pass": workspace_error is None and not workspace.exists(),
            "root": str(workspace),
            "exists_after": workspace.exists(),
            "error": workspace_error,
            "recovered_leases": recovered,
            "recovered_containers": recovered_containers,
        },
    )
    if workspace_error:
        error_text = f"{error_text}; emergency workspace cleanup: {workspace_error}"
    previous_cycle_hash = "0" * 64
    cycle_dirs = sorted(path for path in run_dir.iterdir() if path.is_dir() and re.fullmatch(r"cycle_[0-9]{3}", path.name))
    for cycle_dir in cycle_dirs:
        cycle_manifest = cycle_dir / "cycle_manifest.json"
        if cycle_manifest.is_file():
            record = strict_json(cycle_manifest)
            if record.get("previous_cycle_manifest_sha256") != previous_cycle_hash:
                raise V2Error("emergency finalizer found a broken cycle-manifest chain")
            previous_cycle_hash = legacy.sha256_file(cycle_manifest)
        elif (cycle_dir / "operator_decision.json").is_file():
            previous_cycle_hash = seal_cycle(cycle_dir, previous_cycle_hash)
        else:
            cycle_number = int(cycle_dir.name.split("_")[-1])
            gates = gate_template()
            if (run_dir / "authorization_evidence.json").is_file():
                set_gate(gates, "authorization", "PASS", "../authorization_evidence.json")
            if (cycle_dir / "sandbox" / "sandbox_canary.json").is_file():
                set_gate(gates, "sandbox_canary", "PASS", "sandbox/sandbox_canary.json")
            atomic(
                cycle_dir / "emergency_cycle_error.json",
                {"error": error_text, "acl_restored": True, "recorded_at": utc_now()},
            )
            decision = operator_decision(
                run_id=run_dir.name,
                cycle=cycle_number,
                execution="FAILED",
                review="BLOCK",
                promotion="NOT_ELIGIBLE",
                gates=gates,
                base_commit=context.base_commit,
                candidate_commit=None,
                diff_sha256=None,
                worktree=str(config.worktree_root / run_dir.name / f"cycle_{cycle_number:03d}_candidate_lease" / "worktree"),
                reviews=decision_reviews([], {}),
                rubric_value=empty_rubric("emergency cycle finalization after verified ACL restoration"),
                blockers=[error_text],
                warnings=[],
            )
            atomic(cycle_dir / "operator_decision.json", decision)
            previous_cycle_hash = seal_cycle(cycle_dir, previous_cycle_hash)

    production_pass = compare_protection(context.protected_snapshot, production_snapshot(config), run_dir / "production_guard.json")
    gates = gate_template()
    if (run_dir / "authorization_evidence.json").is_file():
        set_gate(gates, "authorization", "PASS", "authorization_evidence.json")
    set_gate(gates, "external_guard", "PASS" if production_pass else "FAIL", "production_guard.json")
    set_gate(gates, "production_guard", "PASS" if production_pass else "FAIL", "production_guard.json")
    journal.emergency_terminal("COMPLETE_WITH_ERRORS", cause=error_text, production_modified=not production_pass)
    decision = operator_decision(
        run_id=run_dir.name,
        cycle=max(1, len(cycle_dirs)),
        execution="FAILED",
        review="BLOCK",
        promotion="NOT_ELIGIBLE",
        gates=gates,
        base_commit=context.base_commit,
        candidate_commit=None,
        diff_sha256=None,
        worktree=str(config.worktree_root / run_dir.name),
        reviews=[],
        rubric_value=empty_rubric("root emergency finalization after a fail-closed error"),
        blockers=[error_text],
        warnings=[],
        production_modified=not production_pass,
    )
    atomic(run_dir / "operator_decision.json", decision)
    seal_run(run_dir, context.base_commit, "COMPLETE_WITH_ERRORS")
    # A protected-state mismatch is the highest-risk failure and must remain
    # discoverable.  The sealed failed decision records the mismatch; publish
    # its ledger/latest pointer regardless of the guard outcome.
    publish_run(config, run_dir, "COMPLETE_WITH_ERRORS")
    return 2


def run(config: Config) -> int:
    global _ACTIVE_RUN
    config.artifact_root.mkdir(parents=True, exist_ok=True)
    config.worktree_root.mkdir(parents=True, exist_ok=True)
    runtime.validate_no_reparse_ancestors(config.artifact_root, require_exists=True)
    runtime.validate_no_reparse_ancestors(config.worktree_root, require_exists=True)
    authorization_sha256 = legacy.canonical_text_sha256(config.authorization)
    lock_metadata = {
        "controller_pid": os.getpid(),
        "acquired_at": utc_now(),
        "repo": str(config.repo),
        "controller_sha256": legacy.canonical_text_sha256(Path(__file__)),
        "acl_helper_sha256": legacy.canonical_text_sha256(config.repo / "improvement_acl_helper.ps1"),
        "container_policy_sha256": (
            legacy.canonical_text_sha256(config.repo / "candidate_container_policy_v1.json")
            if (config.repo / "candidate_container_policy_v1.json").is_file()
            else None
        ),
    }
    with runtime.ControllerLock(config.worktree_root / ".controller-v2.lock", lock_metadata):
        _ACTIVE_RUN = None
        try:
            recover_persisted_candidate_containers(config)
            recover_persisted_acl_leases(
                config,
                current_authorization_sha256=authorization_sha256,
            )
            host_recovery = improvement_operator.recovery_status(config.artifact_root)
            if host_recovery["status"] == "RECOVERY_REQUIRED":
                raise runtime.RuntimeFailure("unresolved ACL recovery-required hazard blocks controller startup")
            container_recovery = improvement_operator.container_recovery_status(config.artifact_root)
            if container_recovery["status"] == "RECOVERY_REQUIRED":
                raise runtime.RuntimeFailure("unresolved candidate-container recovery hazard blocks controller startup")
            if config.recover_only:
                return 0
            result = _run_unfinalized(config)
            _ACTIVE_RUN = None
            return result
        except Exception as exc:
            context = _ACTIVE_RUN
            if context is None:
                raise
            try:
                return emergency_finalize(context, exc)
            except Exception as finalization_error:
                raise V2Error(
                    f"root failure {_safe_error(exc)}; emergency finalization also failed: {_safe_error(finalization_error)}"
                ) from finalization_error
            finally:
                _ACTIVE_RUN = None


def parse(argv: Sequence[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(description="Governed tool-less Codex improvement controller v2")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--codex", type=Path, default=Path(os.environ.get("APPDATA", "")) / "npm" / "codex.cmd")
    parser.add_argument("--docker", type=Path, default=Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"))
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--worktree-root", type=Path)
    parser.add_argument("--evaluator", type=Path)
    parser.add_argument("--real-codex-home", type=Path)
    parser.add_argument("--model", default=MODEL_DEFAULT)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--max-runtime-seconds", type=int, default=28_800)
    parser.add_argument("--role-timeout-seconds", type=int, default=1_200)
    parser.add_argument("--command-timeout-seconds", type=int, default=600)
    parser.add_argument("--evaluation-timeout-seconds", type=int, default=900)
    parser.add_argument("--remediation-cap", type=int, default=2)
    parser.add_argument("--max-parallel-specialists", type=int, default=3)
    parser.add_argument("--max-diff-bytes", type=int, default=120_000)
    parser.add_argument("--sandbox-implementation", choices=["unelevated"], default="unelevated")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume-run")
    parser.add_argument("--recover-only", action="store_true")
    args = parser.parse_args(argv)

    numeric = {
        "cycles": (args.cycles, 1, 10),
        "max runtime": (args.max_runtime_seconds, 300, 28_800),
        "role timeout": (args.role_timeout_seconds, 60, 3_600),
        "command timeout": (args.command_timeout_seconds, 30, 1_800),
        "evaluation timeout": (args.evaluation_timeout_seconds, 60, 1_800),
        "remediation cap": (args.remediation_cap, 0, 2),
        "parallel specialists": (args.max_parallel_specialists, 1, len(ROLES)),
        "diff bytes": (args.max_diff_bytes, 1_000, 120_000),
    }
    for label, (value, minimum, maximum) in numeric.items():
        if isinstance(value, bool) or not minimum <= value <= maximum:
            raise V2Error(f"invalid {label}: expected {minimum}..{maximum}")
    if args.resume_run and not runtime.RUN_ID_RE.fullmatch(args.resume_run):
        raise V2Error("invalid resume run ID")
    if args.recover_only and (args.resume_run or args.dry_run):
        raise V2Error("recover-only cannot be combined with resume or dry-run")
    if args.model != MODEL_DEFAULT:
        raise V2Error(f"v2 model must be authorization-bound to {MODEL_DEFAULT}")

    repo = runtime.validate_no_reparse_ancestors(args.repo, require_exists=True)
    artifact_root = (args.artifact_root or repo.parent / f"_codex_improvement_evidence_{repo.name}").resolve()
    worktree_root = (args.worktree_root or repo.parent / f"_codex_improvement_worktrees_{repo.name}").resolve()
    evaluator = (args.evaluator or repo / "improvement_score_checkpoint_v2.py").resolve()
    authorization = (args.authorization or repo / "approval_codex_improvement_v2.json").resolve()
    real_codex_home = (args.real_codex_home or Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))).resolve()
    config = Config(
        repo=repo,
        python=args.python.resolve(),
        codex=args.codex.resolve(),
        docker=args.docker.resolve(),
        authorization=authorization,
        artifact_root=artifact_root,
        worktree_root=worktree_root,
        evaluator=evaluator,
        real_codex_home=real_codex_home,
        model=args.model,
        cycles=args.cycles,
        max_runtime_seconds=args.max_runtime_seconds,
        role_timeout_seconds=args.role_timeout_seconds,
        command_timeout_seconds=args.command_timeout_seconds,
        evaluation_timeout_seconds=args.evaluation_timeout_seconds,
        remediation_cap=args.remediation_cap,
        max_parallel_specialists=args.max_parallel_specialists,
        max_diff_bytes=args.max_diff_bytes,
        sandbox_implementation=args.sandbox_implementation,
        dry_run=bool(args.dry_run),
        resume_run=args.resume_run,
        recover_only=bool(args.recover_only),
    )
    expected_evaluator = repo / "improvement_score_checkpoint_v2.py"
    expected_authorization = repo / "approval_codex_improvement_v2.json"
    if config.evaluator != expected_evaluator or config.authorization != expected_authorization:
        raise V2Error("evaluator and authorization must be the exact repo-bound v2 files")
    for path, label in (
        (config.python, "Python interpreter"),
        (config.codex, "Codex launcher"),
        (config.docker, "Docker CLI"),
        (config.authorization, "v2 authorization"),
        (config.evaluator, "v2 evaluator"),
        (config.real_codex_home / "auth.json", "Codex authentication"),
    ):
        runtime.validate_no_reparse_ancestors(path, require_exists=True)
        if not path.is_file() or path.is_symlink():
            raise V2Error(f"missing or unsafe {label}: {path}")
    for root, label in ((artifact_root, "artifact root"), (worktree_root, "worktree root")):
        runtime.validate_no_reparse_ancestors(root.parent, require_exists=True)
        if root.exists() and (not root.is_dir() or runtime.is_reparse(root)):
            raise V2Error(f"unsafe {label}: {root}")
    if not runtime.roots_are_disjoint([repo, artifact_root, worktree_root, Path.home().resolve()]):
        raise V2Error("repo, evidence, worktree, and user-home roots must be pairwise non-nested")
    return config


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse(argv))
    except KeyboardInterrupt:
        print("[controller-v2] interrupted; the supervisor must retain KILLED evidence", file=sys.stderr)
        return 130
    except (V2Error, runtime.RuntimeFailure, improvement_operator.OperatorError, OSError, subprocess.SubprocessError) as exc:
        print(f"[controller-v2] {_safe_error(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
