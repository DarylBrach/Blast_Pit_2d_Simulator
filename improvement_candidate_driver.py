from __future__ import annotations

"""Run a disposable, approval-bound v37 development training fixture."""

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import tmp_2d_simulator_v37 as v37


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Disposable v37 improvement evaluation driver")
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-v36", type=Path, required=True)
    parser.add_argument("--seed-file", type=Path, required=True)
    parser.add_argument("--generations", type=int, default=4)
    parser.add_argument("--max-frames", type=int, default=64)
    parser.add_argument("--rollout-frames", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20260712)
    return parser


def create_approval(args: argparse.Namespace) -> Path:
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
        "authority": "human-owner",
        "authorization_source": "Direct user authorization for supervised Codex improvement evaluation on 2026-07-11",
        "issued_utc": datetime.now(timezone.utc).isoformat(),
        "experiment_id": args.experiment_id,
        "lineage_fingerprint": fingerprint,
        "source_v36_checkpoint_sha256": v37.file_evidence(args.source_v36)["sha256"],
        "audit_seed_commitment_sha256": v37.canonical_text_evidence(args.seed_file)["sha256"],
        "v37_source_sha256": v37.canonical_source_sha256(Path(v37.__file__)),
        "approved_total_generations": args.generations,
        "approved_max_runtime_seconds": 0,
        "authorized_actions": ["train"],
        "release_authorized_conditionally": False,
        "development_fixture": True,
        "notes": "Disposable development evaluation only. No audit, export, release, or production promotion authority.",
    }
    path = args.artifact_root / f"{args.experiment_id}.approval.json"
    v37.write_json(path, approval)
    return path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.artifact_root = args.artifact_root.resolve()
    args.source_v36 = args.source_v36.resolve()
    args.seed_file = args.seed_file.resolve()
    args.artifact_root.mkdir(parents=True, exist_ok=True)
    approval = create_approval(args)
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
        "--max-runtime-seconds", "0",
    ])
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
        },
    }
    print(json.dumps(summary, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
