from __future__ import annotations

"""Score candidate checkpoints with an independent, hidden-fold evaluator."""

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

import numpy as np

import tmp_2d_simulator_v37 as v37


MIN_FOLD_TRIALS = 8
MAX_FOLD_TRIALS = 512
PROFILES = {"standard", "water_fire_challenge"}
FOLD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_fold(path: Path, requested_id: str | None = None) -> tuple[str, list[int], list[str], str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 128_000:
        raise ValueError("fold file is invalid")
    try:
        record = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")),
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("fold file is not strict JSON") from exc
    if not isinstance(record, dict) or not set(record).issubset({"fold_id", "seeds", "profiles"}):
        raise ValueError("fold file has unexpected fields")
    seeds = record.get("seeds")
    profiles = record.get("profiles")
    if not isinstance(seeds, list) or not isinstance(profiles, list) or len(seeds) != len(profiles):
        raise ValueError("fold seeds and profiles must be equal-length arrays")
    if not MIN_FOLD_TRIALS <= len(seeds) <= MAX_FOLD_TRIALS:
        raise ValueError("fold trial count is out of bounds")
    if any(isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**63 for seed in seeds):
        raise ValueError("fold seeds must be bounded non-negative integers")
    if len(set(seeds)) != len(seeds):
        raise ValueError("fold seeds must be unique")
    if any(not isinstance(profile, str) or profile not in PROFILES for profile in profiles):
        raise ValueError("fold contains an invalid profile")
    if len(seeds) % 2 or profiles.count("standard") != len(seeds) // 2:
        raise ValueError("fold must be balanced across standard and challenge profiles")
    embedded_id = record.get("fold_id")
    if embedded_id is not None and (not isinstance(embedded_id, str) or not FOLD_ID_RE.fullmatch(embedded_id)):
        raise ValueError("fold_id is invalid")
    if requested_id is not None and not FOLD_ID_RE.fullmatch(requested_id):
        raise ValueError("requested fold_id is invalid")
    if requested_id and embedded_id and requested_id != embedded_id:
        raise ValueError("requested fold_id does not match fold file")
    canonical = {"seeds": seeds, "profiles": profiles}
    fold_sha256 = v37.sha256_json(canonical)
    fold_id = requested_id or embedded_id or f"fold-{fold_sha256[:16]}"
    return fold_id, seeds, profiles, fold_sha256


def score(checkpoint: Path, fold_file: Path, fold_id: str | None = None) -> dict[str, object]:
    metadata, policy, simulation = v37.load_hof(checkpoint)
    resolved_fold_id, seeds, profiles, fold_sha256 = load_fold(fold_file, fold_id)
    trials = v37.evaluate_brain(policy.brain, simulation, seeds, profiles)
    if len(trials) != len(seeds):
        raise ValueError("evaluator returned an unexpected trial count")
    for expected_profile, trial in zip(profiles, trials):
        actual_profile = getattr(trial, "profile", expected_profile)
        if actual_profile != expected_profile:
            raise ValueError("evaluator returned trials out of profile order")
    fitness_values = [float(trial.fitness) for trial in trials]
    if not all(math.isfinite(value) for value in fitness_values):
        raise ValueError("evaluator returned non-finite fitness")
    metrics = v37.aggregate(trials, 0.25)
    if any(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and not math.isfinite(float(value))
        for value in metrics.values()
    ):
        raise ValueError("evaluator returned non-finite aggregate metrics")
    metrics.update({
        "schema_version": "blast-pit.improvement-score.v2",
        "evaluator_source_sha256": v37.file_evidence(Path(__file__))["sha256"],
        "simulator_source_sha256": v37.file_evidence(Path(v37.__file__))["sha256"],
        "python_executable": str(Path(sys.executable).resolve()),
        "checkpoint": str(checkpoint.resolve()),
        "checkpoint_sha256": v37.file_evidence(checkpoint)["sha256"],
        "policy_hash": policy.policy_hash,
        "training_fingerprint": metadata["fingerprint"],
        "trial_count": len(trials),
        "score_seed_hash": v37.sha256_json(seeds),
        "fold_id": resolved_fold_id,
        "fold_sha256": fold_sha256,
        "fitness_values": fitness_values,
        "fitness_stddev": float(np.std(fitness_values)),
    })
    if not math.isfinite(float(metrics["fitness_stddev"])):
        raise ValueError("evaluator returned non-finite fitness standard deviation")
    return metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trusted v37 candidate hidden-fold scorer v2")
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--fold-file", type=Path, required=True)
    parser.add_argument("--fold-id")
    args = parser.parse_args(argv)
    print(json.dumps(score(args.checkpoint, args.fold_file, args.fold_id), sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
