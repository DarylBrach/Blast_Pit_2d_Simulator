from __future__ import annotations

"""Run a disposable v37 development fixture under a v2 parent authorization."""

import json
from datetime import datetime, timezone
from pathlib import Path

import improvement_candidate_driver as legacy


v37 = legacy.v37


def load_parent_authorization(args) -> tuple[dict[str, object], str]:
    path = args.parent_authorization
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64_000:
        raise ValueError("parent v2 improvement authorization is invalid")
    record = json.loads(path.read_text(encoding="utf-8"))
    if (
        record.get("schema_version") != "blast-pit.codex-improvement-authorization.v2"
        or record.get("project") != "Blast_Pit_2d_Simulator"
        or record.get("status") != "approved"
        or record.get("authority") != "human-owner"
        or record.get("automatic_release") is not False
        or record.get("candidate_network_access") is not False
    ):
        raise ValueError("parent v2 improvement authorization scope mismatch")
    expected = {
        "candidate_driver_v2_source_sha256": v37.canonical_source_sha256(Path(__file__)),
        "development_seed_sha256": v37.canonical_text_evidence(args.seed_file)["sha256"],
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise ValueError("parent v2 improvement authorization hash mismatch")
    expires = datetime.fromisoformat(str(record["expires_utc"]).replace("Z", "+00:00"))
    if datetime.now(timezone.utc) >= expires:
        raise ValueError("parent v2 improvement authorization expired")
    return record, v37.canonical_text_evidence(path)["sha256"]


def create_approval(args, parent_sha256: str) -> Path:
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
    ppo = v37.v36.PPOConfig(
        rollout_frames=args.rollout_frames,
        update_epochs=2,
        minibatch_size=64,
    )
    robustness = v37.RobustnessConfig(audit_trials=32)
    fingerprint = v37.experiment_fingerprint(
        args.source_v36,
        simulation,
        ppo,
        robustness,
        args.seed_file,
    )
    approval = {
        "schema_version": "approval.v37.v1",
        "project": "Blast_Pit",
        "version": "v37",
        "status": "approved",
        "authority": "controller-development-delegation",
        "authorization_source": "Scoped delegation from the retained v2 human-owner controller authorization",
        "parent_authorization_sha256": parent_sha256,
        "delegated_by": "CodexImprovementController_v2.py",
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
        "notes": "Disposable v2 development evaluation only. No audit, export, release, or production promotion authority.",
    }
    path = args.artifact_root / f"{args.experiment_id}.approval.json"
    v37.write_json(path, approval)
    return path


def main(argv: list[str] | None = None) -> int:
    original_loader = legacy.load_parent_authorization
    original_creator = legacy.create_approval
    legacy.load_parent_authorization = load_parent_authorization
    legacy.create_approval = create_approval
    try:
        return legacy.main(argv)
    finally:
        legacy.load_parent_authorization = original_loader
        legacy.create_approval = original_creator


if __name__ == "__main__":
    raise SystemExit(main())
