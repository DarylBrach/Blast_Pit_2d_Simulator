from __future__ import annotations

"""Governed, candidate-only, multi-specialist improvement controller.

The controller never pushes, merges, releases, or changes the protected checkout.
Codex roles are tool-less and receive only bounded inline packets.  Candidate
patches and candidate Python are applied/executed through the separately
qualified Windows sandbox in ``improvement_harness_runtime_v2``.
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


VERSION = "2.0.0"
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
    "v2_scorer_source_sha256": "improvement_score_checkpoint_v2.py",
    "operator_source_sha256": "improvement_operator.py",
    "canary_source_sha256": "improvement_sandbox_canary.py",
    "simulator_source_sha256": "tmp_2d_simulator_v37.py",
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
        "role_policy_version": runtime.ROLE_POLICY_VERSION,
        "sandbox_implementation": "unelevated",
        "model": config.model,
        "artifact_root": str(config.artifact_root),
        "worktree_root": str(config.worktree_root),
        "codex_cli_version": version,
        "codex_launcher_sha256": legacy.sha256_file(config.codex),
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
    sandbox_environment: dict[str, str],
    attempt_dir: Path,
    deadline: float,
) -> None:
    validation = attempt_dir / "validation"
    validation.mkdir(parents=True, exist_ok=False)
    commands = {
        "compile": [config.python, "-m", "py_compile", "tmp_2d_simulator_v37.py", "test_tmp_2d_simulator_v37.py"],
        "focused_tests": [config.python, "-m", "pytest", "-q", "test_tmp_2d_simulator_v37.py"],
        "full_tests": [config.python, "-m", "pytest", "-q"],
    }
    for name, values in commands.items():
        try:
            runtime.run_sandboxed(
                codex=config.codex,
                profile="candidate",
                cwd=worktree,
                command=values,
                timeout=remaining_timeout(deadline, config.command_timeout_seconds),
                environment=sandbox_environment,
                evidence=validation / f"{name}.json",
            )
        except (runtime.RuntimeFailure, runtime.RuntimeTimeout) as exc:
            raise CandidateRejected(f"{name} failed in candidate sandbox: {exc}") from exc


def candidate_train(
    config: Config,
    source_root: Path,
    output_root: Path,
    experiment_id: str,
    sandbox_environment: dict[str, str],
    evidence: Path,
    deadline: float,
) -> Path:
    args: list[str | Path] = [
        config.python,
        "-u",
        source_root / "improvement_candidate_driver_v2.py",
        "--experiment-id",
        experiment_id,
        "--artifact-root",
        output_root,
        "--source-v36",
        source_root / "artifacts" / "v36" / "qdppo-evaluation-001" / "evolution_state_v36.npz",
        "--seed-file",
        source_root / "improvement_dev_seeds_v1.txt",
        "--parent-authorization",
        source_root / config.authorization.name,
        "--generations",
        "4",
        "--max-frames",
        "64",
        "--rollout-frames",
        "64",
        "--max-runtime-seconds",
        str(min(600, config.evaluation_timeout_seconds)),
    ]
    try:
        runtime.run_sandboxed(
            codex=config.codex,
            profile="candidate",
            cwd=source_root,
            command=args,
            timeout=remaining_timeout(deadline, config.evaluation_timeout_seconds),
            environment=sandbox_environment,
            evidence=evidence,
        )
    except (runtime.RuntimeFailure, runtime.RuntimeTimeout) as exc:
        raise CandidateRejected(f"candidate development training failed: {exc}") from exc
    checkpoint = output_root / experiment_id / "evolution_state_v37.npz"
    runtime.validate_no_reparse_ancestors(checkpoint, require_exists=True)
    if not checkpoint.is_file() or checkpoint.stat(follow_symlinks=False).st_nlink != 1:
        raise CandidateRejected("candidate training did not produce a safe checkpoint")
    runtime.strict_manifest(output_root, max_files=2_000, max_bytes=128_000_000)
    return checkpoint


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


def trusted_score(config: Config, checkpoint: Path, fold: Path, deadline: float) -> dict[str, Any]:
    result = command(
        [config.python, config.evaluator, "--checkpoint", checkpoint, "--fold-file", fold],
        config.repo,
        remaining_timeout(deadline, config.evaluation_timeout_seconds),
        environment=trusted_environment(),
    )
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
    deadline: float,
) -> CycleOutcome:
    cycle_dir = run_dir / f"cycle_{cycle:03d}"
    cycle_dir.mkdir(parents=True, exist_ok=False)
    gates = gate_template()
    set_gate(gates, "authorization", "PASS", "../authorization_evidence.json")
    workspace_root = config.worktree_root / run_id
    workspace_root.mkdir(parents=True, exist_ok=True)
    worktree = workspace_root / f"cycle_{cycle:03d}_worktree"
    candidate_isolation = workspace_root / f"cycle_{cycle:03d}_candidate_isolation"
    role_isolation_root = workspace_root / f"cycle_{cycle:03d}_role_isolations"
    baseline_output = cycle_dir / "baseline_training"
    candidate_output = cycle_dir / "candidate_training"
    baseline_output.mkdir()
    candidate_output.mkdir()
    role_isolation_root.mkdir()
    branch = f"codex/v2-{run_id.lower()}-c{cycle:03d}"
    outcome = CycleOutcome(cycle, "RUNNING", "RUNNING", base_commit, str(worktree), gates)
    sandbox_environment: dict[str, str] | None = None
    remediation_attempts = 0
    latest_attempt_dir: Path | None = None
    latest_adjudication: dict[str, Any] | None = None
    build_summary: dict[str, Any] | None = None
    cleanup_rows: list[dict[str, Any]] = []
    journal.add("CYCLE_STARTING", cycle=cycle, base_commit=base_commit)

    try:
        git(
            config,
            ["worktree", "add", "-b", branch, worktree, base_commit],
            timeout=remaining_timeout(deadline, 180),
            evidence=cycle_dir / "worktree_create.json",
        )
        baseline_manifest = legacy.directory_manifest(worktree, exclude_volatile=True)
        atomic(cycle_dir / "worktree_baseline_manifest.json", {"root": str(worktree), "files": baseline_manifest})

        sandbox_environment, sandbox_temp = runtime.prepare_candidate_sandbox(
            candidate_isolation,
            workspace_root,
            [worktree, baseline_output, candidate_output],
            profile="candidate",
            implementation=config.sandbox_implementation,
        )
        sandbox_evidence = cycle_dir / "sandbox"
        sandbox_evidence.mkdir()
        runtime.qualify_candidate_sandbox(
            codex=config.codex,
            python=config.python,
            canary_source=config.repo / "improvement_sandbox_canary.py",
            profile="candidate",
            cwd=worktree,
            allowed=[worktree, baseline_output, candidate_output, sandbox_temp],
            forbidden=[config.repo, Path.home().resolve()],
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            environment=sandbox_environment,
            scratch=sandbox_temp,
            evidence_dir=sandbox_evidence,
            token=secrets.token_hex(16),
        )
        set_gate(gates, "sandbox_canary", "PASS", "sandbox/sandbox_canary.json")
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
            baseline_output,
            f"baseline-c{cycle:03d}",
            sandbox_environment,
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
        run_validations(config, worktree, sandbox_environment, apply_dir, deadline)
        outcome.diff_sha256 = diff_sha256
        outcome.category = category

        packet = bounded_source_packet(
            config,
            worktree,
            diff=diff,
            extra={"build_summary": build_summary, "validation": "compile, focused v37, and full suite passed in the qualified sandbox"},
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
            run_validations(config, worktree, sandbox_environment, attempt_dir, deadline)
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
            candidate_output,
            f"candidate-c{cycle:03d}",
            sandbox_environment,
            cycle_dir / "candidate_training_command.json",
            deadline,
        )
        outcome.candidate_checkpoint = candidate_checkpoint
        fold = private_fold_root / f"cycle_{cycle:03d}_fold_b.json"
        outcome.private_fold_record = create_hidden_fold(fold)
        try:
            baseline_score = trusted_score(config, baseline_checkpoint, fold, deadline)
            candidate_score = trusted_score(config, candidate_checkpoint, fold, deadline)
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

        if candidate_isolation.exists():
            try:
                runtime.safe_remove_tree(candidate_isolation, workspace_root)
                cleanup_rows.append({"target": str(candidate_isolation), "status": "REMOVED"})
            except Exception as exc:
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append(f"candidate isolation cleanup quarantined: {_safe_error(exc)}")
                cleanup_rows.append({"target": str(candidate_isolation), "status": "QUARANTINED", "error": _safe_error(exc)})
        if role_isolation_root.exists():
            try:
                runtime.safe_remove_tree(role_isolation_root, workspace_root)
                cleanup_rows.append({"target": str(role_isolation_root), "status": "REMOVED"})
            except Exception as exc:
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append(f"role isolation cleanup quarantined: {_safe_error(exc)}")
                cleanup_rows.append({"target": str(role_isolation_root), "status": "QUARANTINED", "error": _safe_error(exc)})
        if worktree.exists():
            removal = git(
                config,
                ["worktree", "remove", "--force", worktree],
                timeout=min(180, max(1, int(deadline - time.monotonic()))),
                evidence=cycle_dir / "worktree_remove.json",
                require_success=False,
            )
            cleanup_rows.append({"target": str(worktree), "status": "REMOVED" if removal.return_code == 0 else "RETAINED", "return_code": removal.return_code})
            if removal.return_code != 0:
                outcome.status = "ERROR"
                outcome.execution = "FAILED"
                outcome.blockers.append("candidate worktree cleanup failed; path retained for manual quarantine review")
        if outcome.candidate_commit is None:
            deletion = git(config, ["branch", "-D", branch], timeout=60, require_success=False)
            cleanup_rows.append({"target": branch, "status": "DELETED" if deletion.return_code == 0 else "RETAINED", "return_code": deletion.return_code})
        atomic(cycle_dir / "cleanup.json", {"entries": cleanup_rows})

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


def reject_stale_private_folds(worktree_root: Path) -> None:
    if not worktree_root.exists():
        return
    runtime.validate_no_reparse_ancestors(worktree_root, require_exists=True)
    for child in worktree_root.iterdir():
        if runtime.is_reparse(child) or not child.is_dir():
            raise V2Error(f"unsafe stale worktree entry requires quarantine: {child}")
        private = child / "private_folds"
        if private.exists():
            if runtime.is_reparse(private) or not private.is_dir() or any(private.iterdir()):
                raise V2Error(f"stale private hidden-fold material must be quarantined before a new run: {private}")


def dry_run(config: Config, run_dir: Path, journal: Journal, base_commit: str, protected: dict[str, Any], deadline: float) -> tuple[str, dict[str, Any], int]:
    workspace_root = config.worktree_root / run_dir.name
    workspace_root.mkdir(parents=True, exist_ok=True)
    workspace = workspace_root / "dry_workspace"
    output = workspace_root / "dry_output"
    isolation = workspace_root / "dry_isolation"
    workspace.mkdir()
    output.mkdir()
    evidence = run_dir / "sandbox"
    evidence.mkdir()
    gates = gate_template()
    set_gate(gates, "authorization", "PASS", "authorization_evidence.json")
    environment, scratch = runtime.prepare_candidate_sandbox(
        isolation,
        workspace_root,
        [workspace, output],
        profile="candidate",
        implementation=config.sandbox_implementation,
    )
    try:
        runtime.qualify_candidate_sandbox(
            codex=config.codex,
            python=config.python,
            canary_source=config.repo / "improvement_sandbox_canary.py",
            profile="candidate",
            cwd=workspace,
            allowed=[workspace, output, scratch],
            forbidden=[config.repo, Path.home().resolve()],
            timeout=remaining_timeout(deadline, config.command_timeout_seconds),
            environment=environment,
            scratch=scratch,
            evidence_dir=evidence,
            token=secrets.token_hex(16),
        )
        set_gate(gates, "sandbox_canary", "PASS", "sandbox/sandbox_canary.json")
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
            worktree=str(workspace),
            reviews=[],
            rubric_value=empty_rubric("dry run does not score candidates"),
            blockers=[] if passed else ["production guard failed"],
            warnings=["dry run: candidate build, tests, evaluation, and reviews were not executed"],
            production_modified=not passed,
        )
        return state, decision, 0 if passed else 2
    finally:
        for target in (isolation, workspace, output):
            if target.exists():
                runtime.safe_remove_tree(target, workspace_root)
        atomic(run_dir / "dry_cleanup.json", {"pass": not any(target.exists() for target in (isolation, workspace, output))})


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
    _ACTIVE_RUN = ActiveRunContext(config, run_dir, journal, base_commit, protected)
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
            "automatic_push": False,
            "automatic_merge": False,
            "automatic_release": False,
        },
    )

    if config.dry_run:
        state, decision, exit_code = dry_run(config, run_dir, journal, base_commit, protected, deadline)
        atomic(run_dir / "operator_decision.json", decision)
        seal_run(run_dir, base_commit, state)
        publish_run(config, run_dir, state)
        return exit_code

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
                final_baseline_score = trusted_score(config, original_baseline, final_fold, deadline)
                final_candidate_score = trusted_score(config, selected.candidate_checkpoint, final_fold, deadline)
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
    try:
        ledger_entry, _ = improvement_operator._local_ledger_entry(config.artifact_root, run_dir.name)
        if ledger_entry.get("evidence_manifest_sha256") != manifest_hash or ledger_entry.get("operator_decision_sha256") != decision_hash:
            raise V2Error("existing local-ledger record disagrees with the sealed run")
        ledger_hash = ledger_entry["ledger_hash"]
    except improvement_operator.OperatorError as exc:
        if "not anchored" not in str(exc):
            raise
        ledger_hash = append_local_ledger(
            config.artifact_root,
            {
                "run_id": run_dir.name,
                "evidence_manifest_sha256": manifest_hash,
                "operator_decision_sha256": decision_hash,
                "recorded_at": utc_now(),
            },
        )

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
    manifest_path = run_dir / "evidence_manifest.json"
    if manifest_path.is_file():
        state = strict_json(run_dir / "state.json").get("status", "COMPLETE_WITH_ERRORS")
        publish_run(config, run_dir, str(state))
        return 2

    atomic(run_dir / "emergency_error.json", {"error": error_text, "recorded_at": utc_now()})
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
            raise V2Error(f"emergency finalizer cannot seal incomplete cycle evidence: {cycle_dir.name}")

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
    _ACTIVE_RUN = None
    try:
        result = _run_unfinalized(config)
        _ACTIVE_RUN = None
        return result
    except Exception as exc:
        context = _ACTIVE_RUN
        _ACTIVE_RUN = None
        if context is None:
            raise
        try:
            return emergency_finalize(context, exc)
        except Exception as finalization_error:
            raise V2Error(
                f"root failure {_safe_error(exc)}; emergency finalization also failed: {_safe_error(finalization_error)}"
            ) from finalization_error


def parse(argv: Sequence[str] | None = None) -> Config:
    parser = argparse.ArgumentParser(description="Governed tool-less Codex improvement controller v2")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--codex", type=Path, default=Path(os.environ.get("APPDATA", "")) / "npm" / "codex.cmd")
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
    )
    expected_evaluator = repo / "improvement_score_checkpoint_v2.py"
    expected_authorization = repo / "approval_codex_improvement_v2.json"
    if config.evaluator != expected_evaluator or config.authorization != expected_authorization:
        raise V2Error("evaluator and authorization must be the exact repo-bound v2 files")
    for path, label in (
        (config.python, "Python interpreter"),
        (config.codex, "Codex launcher"),
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
