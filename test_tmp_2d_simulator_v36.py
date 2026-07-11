import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import numpy as np

import tmp_2d_simulator_v36 as v36


class ConfigTests(unittest.TestCase):
    def test_invalid_ppo_config_is_rejected(self):
        with self.assertRaises(ValueError):
            v36.PPOConfig(gamma=1.1)

    def test_invalid_qd_capacity_is_rejected(self):
        with self.assertRaises(ValueError):
            v36.QDConfig(bins=17)


class AdvantageTests(unittest.TestCase):
    def test_gae_matches_hand_calculation(self):
        rewards = np.array([1.0, 2.0])
        values = np.array([0.5, 0.25])
        dones = np.array([0.0, 1.0])
        advantages, returns = v36.generalized_advantage(rewards, values, dones, .9, .8)
        expected_last = 2.0 - .25
        expected_first = 1.0 + .9 * .25 - .5 + .9 * .8 * expected_last
        np.testing.assert_allclose(advantages, [expected_first, expected_last])
        np.testing.assert_allclose(returns, advantages + values)

    def test_truncation_bootstraps_value(self):
        advantages, _ = v36.generalized_advantage(np.array([0.0]), np.array([.2]),
                                                  np.array([0.0]), .9, .95, bootstrap=.5)
        np.testing.assert_allclose(advantages, [.25])

    def test_squashed_gaussian_log_probability_is_finite(self):
        action = np.array([[0.0, .999999]])
        location = np.zeros((1, 2))
        result = v36.squashed_gaussian_log_probability(action, location, np.zeros(2))
        self.assertTrue(np.isfinite(result).all())


class ArchiveTests(unittest.TestCase):
    def _candidate(self, candidate_id, quality, descriptor):
        simulation = v36.v35.SimulationConfig(max_frames=16)
        policy = v36.Policy.random(simulation, np.random.default_rng(candidate_id), .25)
        candidate = v36.Candidate(candidate_id, policy, v36.Adam.zeros(policy))
        candidate.trials = []
        candidate.__dict__["_test_quality"] = quality
        candidate.__dict__["_test_descriptor"] = descriptor
        return candidate

    def test_bin_edges_are_bounded(self):
        archive = v36.QDArchive(v36.QDConfig())
        self.assertEqual(archive.cell((0.0, 1.0)), (0, 4))
        self.assertEqual(archive.cell((.2, .999)), (1, 4))
        with self.assertRaises(ValueError):
            archive.cell((float("nan"), .5))


class PolicyAndCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.simulation = v36.v35.SimulationConfig(max_frames=16)
        self.policy = v36.Policy.random(self.simulation, np.random.default_rng(7), .25)

    def test_policy_is_finite_and_hash_changes(self):
        self.policy.validate(self.simulation)
        before = self.policy.policy_hash
        self.policy.brain.b3[0] += .01
        self.assertNotEqual(before, self.policy.policy_hash)

    def test_optimizer_changes_policy(self):
        optimizer = v36.Adam.zeros(self.policy)
        before = self.policy.policy_hash
        gradients = [np.ones_like(x) for x in self.policy.arrays()]
        optimizer.apply(self.policy.arrays(), gradients, 1e-3, .5)
        self.assertNotEqual(before, self.policy.policy_hash)
        self.policy.validate(self.simulation)

    def test_checkpoint_uses_non_object_arrays(self):
        candidate = v36.Candidate(1, self.policy, v36.Adam.zeros(self.policy))
        archive = v36.QDArchive(v36.QDConfig())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.npz"
            v36.save_checkpoint(path, {"fingerprint": "f", "generation": 0}, [candidate], archive)
            with np.load(path, allow_pickle=False) as data:
                self.assertIn("metadata", data.files)
                self.assertTrue(all(data[name].dtype != object for name in data.files))
                self.assertEqual(json.loads(bytes(data["metadata"]).decode())["fingerprint"], "f")

    def _governed_checkpoint(self, root: Path):
        candidate = v36.Candidate(1, self.policy.copy(), v36.Adam.zeros(self.policy))
        second_policy = self.policy.copy(); second_policy.brain.b3[0] += .001
        second = v36.Candidate(2, second_policy, v36.Adam.zeros(second_policy))
        archive = v36.QDArchive(v36.QDConfig())
        entry = v36.ArchiveEntry((0, 0), 1, candidate.policy.policy_hash, .5, (.1, .1), 0)
        archive.entries[(0, 0)] = entry; archive.policies[(0, 0)] = candidate.policy.copy()
        record = {"schema_version": v36.SCHEMA_VERSION, "generation": 0, "algorithm": v36.ALGORITHM,
                  "fingerprint": "lineage", "previous_record_hash": "0" * 64,
                  "validation_hof": {"candidate_id": 1, "policy_hash": candidate.policy.policy_hash,
                                      "fitness": .5, "source_generation": 0}}
        record["record_hash"] = v36.sha256_json(record)
        metadata = {"schema_version": v36.SCHEMA_VERSION, "app_version": v36.APP_VERSION,
                    "algorithm": v36.ALGORITHM, "workflow_state": "TRAINING_COMMITTED", "generation": 0,
                    "master_seed": 11, "fingerprint": "lineage", "record": record, "next_candidate_id": 3,
                    "simulation": v36.asdict(self.simulation), "ppo": v36.asdict(v36.PPOConfig()),
                    "qd": v36.asdict(v36.QDConfig()), "reward": v36.asdict(v36.RewardPolicy()),
                    "validation_hof": record["validation_hof"]}
        checkpoint = root / "evolution_state_v36.npz"
        v36.save_checkpoint(checkpoint, metadata, [candidate, second], archive, candidate)
        return checkpoint, record

    def test_hardened_checkpoint_round_trip_and_status(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint, record = self._governed_checkpoint(Path(directory))
            metadata, candidates, archive, hof = v36.load_checkpoint(checkpoint)
            self.assertEqual(metadata["generation"], 0)
            self.assertEqual(candidates[0].policy.policy_hash, self.policy.policy_hash)
            self.assertEqual(len(archive.entries), 1)
            self.assertEqual(hof.policy.policy_hash, self.policy.policy_hash)
            (checkpoint.with_name("generations_v36.jsonl")).write_text(v36.canonical_json(record) + "\n", encoding="utf-8")
            self.assertEqual(v36.checkpoint_status(checkpoint)["results_reconciliation"]["state"], "CONSISTENT")

    def test_checkpoint_ahead_repairs_jsonl_once(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint, record = self._governed_checkpoint(Path(directory)); results = checkpoint.with_name("generations_v36.jsonl")
            state = v36.reconcile_results(results, v36.load_checkpoint(checkpoint)[0], repair=False)
            self.assertEqual(state["state"], "CHECKPOINT_AHEAD_RECOVERABLE")
            v36.reconcile_results(results, v36.load_checkpoint(checkpoint)[0], repair=True)
            self.assertEqual(len(results.read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(v36.reconcile_results(results, v36.load_checkpoint(checkpoint)[0])["state"], "CONSISTENT")

    def test_checkpoint_repair_replaces_partial_terminal_json(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint, record = self._governed_checkpoint(Path(directory)); results = checkpoint.with_name("generations_v36.jsonl")
            results.write_text('{"partial":', encoding="utf-8")
            v36.reconcile_results(results, v36.load_checkpoint(checkpoint)[0], repair=True)
            self.assertEqual(json.loads(results.read_text(encoding="utf-8")), record)
            self.assertEqual(v36.reconcile_results(results, v36.load_checkpoint(checkpoint)[0])["state"], "CONSISTENT")

    def test_archive_svg_and_policy_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); checkpoint, record = self._governed_checkpoint(root)
            checkpoint.with_name("generations_v36.jsonl").write_text(v36.canonical_json(record) + "\n", encoding="utf-8")
            svg = root / "archive.svg"
            self.assertEqual(v36.visualize_archive(Namespace(checkpoint=checkpoint, output=svg)), 0)
            self.assertIn("Median exploration", svg.read_text(encoding="utf-8"))
            self.assertIn('role="img"', svg.read_text(encoding="utf-8"))
            hof = root / "hof.npz"
            self.assertEqual(v36.export_hof(Namespace(checkpoint=checkpoint, output=hof)), 0)
            with np.load(hof, allow_pickle=False) as data: self.assertIn("p0", data.files)


class CliTests(unittest.TestCase):
    def test_all_lifecycle_commands_parse(self):
        parser = v36.build_parser()
        self.assertEqual(parser.parse_args(["status", "--checkpoint", "x.npz"]).command, "status")
        self.assertEqual(parser.parse_args(["continue", "--experiment-id", "x", "--resume", "x.npz",
                                            "--additional-generations", "1"]).command, "continue")
        self.assertEqual(parser.parse_args(["export-archive", "--checkpoint", "x.npz", "--output", "out"]).command,
                         "export-archive")

    def test_retained_production_checkpoint_if_present(self):
        checkpoint = Path("artifacts/v36/qdppo-evaluation-001/evolution_state_v36.npz")
        if not checkpoint.is_file(): self.skipTest("retained checkpoint unavailable")
        status = v36.checkpoint_status(checkpoint)
        self.assertGreaterEqual(status["last_committed_generation"], 19)
        self.assertEqual(status["archive_occupied"], 11)
        self.assertEqual(status["validation_hof"]["candidate_id"], 201)


class ContinuationTests(unittest.TestCase):
    def test_legacy_emitter_reconstruction_is_deterministic(self):
        simulation = v36.v35.SimulationConfig(max_frames=16, population_size=4, elite_count=2, child_count=1, immigrant_count=1)
        qd = v36.QDArchive(v36.QDConfig())
        policies = [v36.Policy.random(simulation, np.random.default_rng(index), .25) for index in range(2)]
        candidates = [v36.Candidate(index + 1, policy, v36.Adam.zeros(policy)) for index, policy in enumerate(policies)]
        for index, candidate in enumerate(candidates):
            cell = (index, 0); entry = v36.ArchiveEntry(cell, candidate.candidate_id, candidate.policy.policy_hash, .5, (.1 + .2*index, .1), 3)
            qd.entries[cell] = entry; qd.policies[cell] = candidate.policy.copy()
        a, next_a = v36._emit_population(qd, candidates, 4, 9, 3, 20260711, simulation)
        b, next_b = v36._emit_population(qd, candidates, 4, 9, 3, 20260711, simulation)
        identity = lambda rows: [(c.candidate_id, c.parent_id, c.origin, c.policy.policy_hash) for c in rows]
        self.assertEqual(next_a, next_b)
        self.assertEqual(identity(a), identity(b))


class SmokeTests(unittest.TestCase):
    def test_tiny_rollout_and_update(self):
        simulation = v36.v35.SimulationConfig(max_frames=16)
        policy = v36.Policy.random(simulation, np.random.default_rng(7), .25)
        ppo = v36.PPOConfig(rollout_frames=16, update_epochs=1, minibatch_size=8)
        reward = v36.RewardPolicy()
        candidate = v36.Candidate(1, policy, v36.Adam.zeros(policy))
        v36.train_candidate(candidate, 0, 11, simulation, ppo, reward)
        self.assertIsNotNone(candidate.ppo_report)
        self.assertGreater(candidate.ppo_report.agent_transitions, 0)
        self.assertGreater(candidate.ppo_report.updates, 0)
        policy.validate(simulation)


if __name__ == "__main__":
    unittest.main()
