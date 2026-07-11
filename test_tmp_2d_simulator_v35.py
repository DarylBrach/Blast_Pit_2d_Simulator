from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest


ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("simulator_v35", ROOT / "tmp_2d_simulator_v35.py")
assert SPEC and SPEC.loader
sim = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sim
SPEC.loader.exec_module(sim)


def test_parser_requires_positional_train_and_supports_status():
    parser = sim.build_parser()
    args = parser.parse_args(["train", "--experiment-id", "test-run"])
    assert args.command == "train"
    status = parser.parse_args(["status", "--checkpoint", "state.npz"])
    assert status.command == "status"


def test_python_engine_does_not_eagerly_import_numba():
    assert "numba" not in sys.modules
    sim.ExecutionConfig(1, "python", "batch")
    assert "numba" not in sys.modules


def test_brain_scalar_and_batch_inference_match():
    config = sim.SimulationConfig()
    brain = sim.Brain.random(config, np.random.default_rng(7))
    inputs = np.random.default_rng(8).uniform(-1, 1, (5, len(sim.SENSOR_LABELS)))
    scalar = np.asarray([brain.forward(row) for row in inputs])
    assert np.allclose(brain.forward_many(inputs), scalar, rtol=0, atol=1e-14)


def test_same_seed_same_final_hash_across_inference_backends():
    config = sim.SimulationConfig(max_frames=30, initial_food=10, initial_water=10, initial_fire=2)
    brain = sim.Brain.random(config, np.random.default_rng(9))
    scalar = sim.Simulation(config, brain, 10, execution=sim.ExecutionConfig(1, "python", "scalar")).run()
    batch = sim.Simulation(config, brain, 10, execution=sim.ExecutionConfig(1, "python", "batch")).run()
    assert scalar.final_state_hash == batch.final_state_hash
    assert scalar.fitness == pytest.approx(batch.fitness, rel=0, abs=1e-15)


def test_status_reports_generation_zero_remaining_count(tmp_path):
    checkpoint = tmp_path / "evolution_state_v35.npz"
    metadata = {
        "generation": 0,
        "config": {"generations": 50},
        "experiment_id": "v35-production-001",
        "workflow_state": "TRAINING_COMMITTED",
        "master_seed": 20260711,
        "engine_fingerprint": "abc",
        "execution": {"workers": 8, "kernel_backend": "python", "inference_backend": "batch"},
    }
    status = sim._checkpoint_status(metadata, checkpoint)
    assert status["completed_generations"] == 1
    assert status["remaining_generations"] == 49
    assert status["last_committed_generation"] == 0


def test_status_prefers_persisted_plan_over_continue_segment(tmp_path):
    metadata = {
        "generation": 1,
        "planned_generation_count": 50,
        "config": {"generations": 49},
        "experiment_id": "v35-production-001",
        "workflow_state": "TRAINING_COMMITTED",
        "master_seed": 20260711,
        "engine_fingerprint": "abc",
        "execution": {"workers": 8, "kernel_backend": "python", "inference_backend": "batch"},
    }
    status = sim._checkpoint_status(metadata, tmp_path / "state.npz")
    assert status["planned_generations"] == 50
    assert status["remaining_generations"] == 48


def test_occupied_error_is_actionable_and_non_mutating(tmp_path, monkeypatch):
    state = tmp_path / "evolution_state_v35.npz"
    state.write_bytes(b"retained")
    before = state.read_bytes()
    metadata = {
        "generation": 0,
        "config": {"generations": 50},
        "experiment_id": "v35-production-001",
        "workflow_state": "TRAINING_COMMITTED",
        "master_seed": 20260711,
        "engine_fingerprint": "abc",
        "execution": {"workers": 8, "kernel_backend": "python", "inference_backend": "batch"},
    }
    monkeypatch.setattr(sim, "_raw_checkpoint_metadata", lambda _: metadata)
    message = str(sim._occupied_training_error(state, [state]))
    assert "fresh train is prohibited" in message
    assert "committed generation=0" in message
    assert "--additional-generations 49" in message
    assert state.read_bytes() == before


def test_unsafe_experiment_id_rejected(tmp_path):
    with pytest.raises(ValueError, match="experiment-id"):
        sim._artifact_paths(tmp_path, "../escape")


def test_production_checkpoint_status_if_present():
    checkpoint = ROOT / "artifacts" / "v35" / "v35-production-001" / "evolution_state_v35.npz"
    if not checkpoint.is_file():
        pytest.skip("retained production checkpoint is not present")
    metadata = sim._raw_checkpoint_metadata(checkpoint)
    status = sim._checkpoint_status(metadata, checkpoint)
    assert status["experiment_id"] == "v35-production-001"
    assert status["workflow_state"] in {"TRAINING_COMMITTED", "RELEASED"}
    assert status["last_committed_generation"] >= 0
