from __future__ import annotations

"""Score candidate checkpoints with the trusted repository evaluator."""

import argparse
import json
from pathlib import Path

import numpy as np

import tmp_2d_simulator_v37 as v37


def score(checkpoint: Path) -> dict[str, object]:
    metadata, policy, simulation = v37.load_hof(checkpoint)
    seeds = [v37.stable_seed(20260712, "improvement-score-v1", index) for index in range(32)]
    profiles = ["standard" if index % 2 == 0 else "water_fire_challenge" for index in range(32)]
    trials = v37.evaluate_brain(policy.brain, simulation, seeds, profiles)
    metrics = v37.aggregate(trials, 0.25)
    metrics.update({
        "schema_version": "blast-pit.improvement-score.v1",
        "checkpoint": str(checkpoint.resolve()),
        "checkpoint_sha256": v37.file_evidence(checkpoint)["sha256"],
        "policy_hash": policy.policy_hash,
        "training_fingerprint": metadata["fingerprint"],
        "trial_count": len(trials),
        "score_seed_hash": v37.sha256_json(seeds),
        "fitness_stddev": float(np.std([trial.fitness for trial in trials])),
    })
    return metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trusted v37 candidate checkpoint scorer")
    parser.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(score(args.checkpoint), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
