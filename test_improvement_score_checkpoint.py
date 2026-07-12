import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import improvement_score_checkpoint_v2 as scorer


def write_fold(path: Path, **updates) -> Path:
    record = {"fold_id": "hidden-b1", "seeds": list(range(8)),
              "profiles": ["standard", "water_fire_challenge"] * 4}
    record.update(updates)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_load_fold_is_canonical_and_order_sensitive(tmp_path):
    path = write_fold(tmp_path / "fold.json")
    fold_id, seeds, profiles, digest = scorer.load_fold(path)
    assert fold_id == "hidden-b1" and seeds == list(range(8))
    assert digest == scorer.v37.sha256_json({"seeds": seeds, "profiles": profiles})
    reversed_path = write_fold(tmp_path / "reversed.json", seeds=list(reversed(range(8))))
    assert scorer.load_fold(reversed_path)[3] != digest


def test_requested_fold_id_must_match(tmp_path):
    path = write_fold(tmp_path / "fold.json")
    assert scorer.load_fold(path, "hidden-b1")[0] == "hidden-b1"
    with pytest.raises(ValueError, match="does not match"):
        scorer.load_fold(path, "hidden-b2")


@pytest.mark.parametrize("updates", [
    {"seeds": [1] * 8}, {"seeds": list(range(7))},
    {"seeds": [True, *range(1, 8)]}, {"seeds": [-1, *range(1, 8)]},
    {"profiles": ["invalid"] * 8}, {"profiles": ["standard"] * 8}, {"unexpected": 1},
])
def test_malformed_folds_rejected(tmp_path, updates):
    path = write_fold(tmp_path / "fold.json", **updates)
    with pytest.raises(ValueError):
        scorer.load_fold(path)


def test_duplicate_json_keys_rejected(tmp_path):
    path = tmp_path / "fold.json"
    path.write_text('{"seeds":[0,1,2,3,4,5,6,7],"seeds":[8,9,10,11,12,13,14,15],"profiles":["standard","standard","standard","standard","standard","standard","standard","standard"]}')
    with pytest.raises(ValueError, match="duplicate"):
        scorer.load_fold(path)


def test_score_emits_ordered_fold_results(monkeypatch, tmp_path):
    checkpoint = tmp_path / "checkpoint.npz"; checkpoint.write_bytes(b"checkpoint")
    fold = write_fold(tmp_path / "fold.json")
    policy = SimpleNamespace(brain=object(), policy_hash="policy")
    monkeypatch.setattr(scorer.v37, "load_hof", lambda path: ({"fingerprint": "training"}, policy, object()))
    monkeypatch.setattr(scorer.v37, "evaluate_brain", lambda brain, simulation, seeds, profiles: [SimpleNamespace(fitness=float(seed), profile=profile, metrics={"early_extinction": False}) for seed, profile in zip(seeds, profiles)])
    monkeypatch.setattr(scorer.v37, "aggregate", lambda trials, alpha: {"mean": 3.5})
    result = scorer.score(checkpoint, fold)
    assert result["fold_id"] == "hidden-b1"
    assert result["trial_count"] == 8
    assert result["fitness_values"] == [float(value) for value in range(8)]
    assert result["score_seed_hash"] == scorer.v37.sha256_json(list(range(8)))
    assert len(result["evaluator_source_sha256"]) == 64
    assert len(result["simulator_source_sha256"]) == 64


def test_trial_profile_order_mismatch_is_rejected(monkeypatch, tmp_path):
    checkpoint = tmp_path / "checkpoint.npz"; checkpoint.write_bytes(b"checkpoint")
    fold = write_fold(tmp_path / "fold.json")
    policy = SimpleNamespace(brain=object(), policy_hash="policy")
    monkeypatch.setattr(scorer.v37, "load_hof", lambda path: ({"fingerprint": "training"}, policy, object()))
    monkeypatch.setattr(
        scorer.v37,
        "evaluate_brain",
        lambda brain, simulation, seeds, profiles: [SimpleNamespace(fitness=1.0, profile="standard") for _ in seeds],
    )
    with pytest.raises(ValueError, match="profile order"):
        scorer.score(checkpoint, fold)


def test_non_finite_fitness_rejected(monkeypatch, tmp_path):
    checkpoint = tmp_path / "checkpoint.npz"
    fold = write_fold(tmp_path / "fold.json")
    policy = SimpleNamespace(brain=object(), policy_hash="policy")
    monkeypatch.setattr(scorer.v37, "load_hof", lambda path: ({"fingerprint": "training"}, policy, object()))
    monkeypatch.setattr(scorer.v37, "evaluate_brain", lambda *args: [SimpleNamespace(fitness=float("nan"))] * 8)
    with pytest.raises(ValueError, match="non-finite fitness"):
        scorer.score(checkpoint, fold)


def test_fold_file_is_required_by_cli():
    with pytest.raises(SystemExit):
        scorer.main(["--checkpoint", "checkpoint.npz"])
