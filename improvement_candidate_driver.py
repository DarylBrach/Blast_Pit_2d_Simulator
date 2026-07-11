from __future__ import annotations

"""Run a disposable, approval-bound v37 development training fixture."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import tmp_2d_simulator_v37 as v37


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Disposable v37 improvement evaluation driver")
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-v36", type=Path, required=True)
    parser.add_argument("--seed-file", type=Path, required=True)
    parser.add_argument("--parent-authorization", type=Path, required=True)
    parser.add_argument("--generations", type=int, default=4)
    parser.add_argument("--max-frames", type=int, default=64)
    parser.add_argument("--rollout-frames", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20260712)
    parser.add_argument("--max-runtime-seconds", type=int, default=600)
    return parser


def load_parent_authorization(args: argparse.Namespace) -> tuple[dict[str, object], str]:
    path = args.parent_authorization
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64_000:
        raise ValueError("parent improvement authorization is invalid")
    record = json.loads(path.read_text(encoding="utf-8"))
    if (
        record.get("schema_version") != "blast-pit.codex-improvement-authorization.v1"
        or record.get("project") != "Blast_Pit_2d_Simulator"
        or record.get("status") != "approved"
        or record.get("authority") != "human-owner"
        or record.get("automatic_release") is not False
        or record.get("candidate_network_access") is not False
    ):
        raise ValueError("parent improvement authorization scope mismatch")
    expected = {
        "candidate_driver_source_sha256": v37.canonical_source_sha256(Path(__file__)),
        "development_seed_sha256": v37.canonical_text_evidence(args.seed_file)["sha256"],
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise ValueError("parent improvement authorization hash mismatch")
    expires = datetime.fromisoformat(str(record["expires_utc"]).replace("Z", "+00:00"))
    if datetime.now(timezone.utc) >= expires:
        raise ValueError("parent improvement authorization expired")
    return record, v37.canonical_text_evidence(path)["sha256"]


def create_approval(args: argparse.Namespace, parent_sha256: str) -> Path:
    simulation = v37.v35.SimulationConfig(
        generations=args.generations,
        population_size=8,
        elite_count=2,
        child_count=5,
        immigrant_count=1,
        trials=2,
        challenge_trials=3,
        validation_trials=5,
        max_frames=args.max_frames,
    )
    ppo = v37.v36.PPOConfig(rollout_frames=args.rollout_frames, update_epochs=2, minibatch_size=64)
    robustness = v37.RobustnessConfig(audit_trials=32)
    fingerprint = v37.experiment_fingerprint(args.source_v36, simulation, ppo, robustness, args.seed_file)
    approval = {
        "schema_version": "approval.v37.v1",
        "project": "Blast_Pit",
        "version": "v37",
        "status": "approved",
        "authority": "controller-development-delegation",
        "authorization_source": "Scoped delegation from the retained human-owner controller authorization",
        "parent_authorization_sha256": parent_sha256,
        "delegated_by": "CodexImprovementController_v1.py",
        "issued_utc": datetime.now(timezone.utc).isoformat(),
        "experiment_id": args.experiment_id,
        "lineage_fingerprint": fingerprint,
        "source_v36_checkpoint_sha256": v37.file_evidence(args.source_v36)["sha256"],
        "audit_seed_commitment_sha256": v37.canonical_text_evidence(args.seed_file)["sha256"],
        "v37_source_sha256": v37.canonical_source_sha256(Path(v37.__file__)),
        "approved_total_generations": args.generations,
        "approved_max_runtime_seconds": args.max_runtime_seconds,
        "authorized_actions": ["train"],
        "release_authorized_conditionally": False,
        "development_fixture": True,
        "notes": "Disposable development evaluation only. No audit, export, release, or production promotion authority.",
    }
    path = args.artifact_root / f"{args.experiment_id}.approval.json"
    v37.write_json(path, approval)
    return path


def delegated_load_approval(parent_sha256: str, path: Path, experiment_id: str, fingerprint: str, action: str, *,
                            source: Path | None = None, audit_seed_file: Path | None = None,
                            planned_generations: int | None = None, max_runtime_seconds: int | None = None) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64_000:
        raise ValueError("delegated v37 development approval invalid")
    record = json.loads(path.read_text(encoding="utf-8"))
    actions = record.get("authorized_actions")
    if (
        record.get("schema_version") != "approval.v37.v1"
        or record.get("project") != "Blast_Pit"
        or record.get("version") != v37.APP_VERSION
        or record.get("status") != "approved"
        or record.get("authority") != "controller-development-delegation"
        or record.get("parent_authorization_sha256") != parent_sha256
        or record.get("development_fixture") is not True
        or record.get("release_authorized_conditionally") is not False
        or actions != ["train"]
        or action != "train"
        or record.get("experiment_id") != experiment_id
        or record.get("lineage_fingerprint") != fingerprint
    ):
        raise ValueError("delegated v37 development approval scope mismatch")
    expected = {
        "source_v36_checkpoint_sha256": v37.file_evidence(source)["sha256"] if source else None,
        "audit_seed_commitment_sha256": v37.canonical_text_evidence(audit_seed_file)["sha256"] if audit_seed_file else None,
        "v37_source_sha256": v37.canonical_source_sha256(Path(v37.__file__)),
        "approved_total_generations": planned_generations,
        "approved_max_runtime_seconds": max_runtime_seconds,
    }
    for key, value in expected.items():
        if value is not None and record.get(key) != value:
            raise ValueError(f"delegated v37 development approval {key} mismatch")
    return v37.sha256_json(record)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.artifact_root = args.artifact_root.resolve()
    args.source_v36 = args.source_v36.resolve()
    args.seed_file = args.seed_file.resolve()
    args.parent_authorization = args.parent_authorization.resolve()
    if args.max_runtime_seconds <= 0:
        raise ValueError("development runtime must be positive and bounded")
    args.artifact_root.mkdir(parents=True, exist_ok=True)
    _, parent_sha256 = load_parent_authorization(args)
    approval = create_approval(args, parent_sha256)
    original_loader = v37.load_approval
    v37.load_approval = lambda path, experiment_id, fingerprint, action, **kwargs: delegated_load_approval(
        parent_sha256, path, experiment_id, fingerprint, action, **kwargs
    )
    try:
        rc = v37.main([
            "train",
            "--experiment-id", args.experiment_id,
            "--source-v36", str(args.source_v36),
            "--audit-seed-file", str(args.seed_file),
            "--artifact-root", str(args.artifact_root),
            "--approval-record", str(approval),
            "--generations", str(args.generations),
            "--population", "8",
            "--rollout-frames", str(args.rollout_frames),
            "--max-frames", str(args.max_frames),
            "--audit-trials", "32",
            "--seed", str(args.seed),
            "--max-runtime-seconds", str(args.max_runtime_seconds),
        ])
    finally:
        v37.load_approval = original_loader
    checkpoint = args.artifact_root / args.experiment_id / "evolution_state_v37.npz"
    summary = {
        "schema_version": "blast-pit.improvement-candidate.v1",
        "return_code": rc,
        "experiment_id": args.experiment_id,
        "checkpoint": str(checkpoint),
        "approval": str(approval),
        "configuration": {
            "generations": args.generations,
            "max_frames": args.max_frames,
            "rollout_frames": args.rollout_frames,
            "seed": args.seed,
            "max_runtime_seconds": args.max_runtime_seconds,
            "parent_authorization_sha256": parent_sha256,
        },
    }
    print(json.dumps(summary, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
