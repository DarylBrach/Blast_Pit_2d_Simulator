import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

import numpy as np

import tmp_2d_simulator_v37 as v37


class RobustnessTests(unittest.TestCase):
    def test_requires_multiple_challenge_rollouts(self):
        with self.assertRaises(ValueError): v37.RobustnessConfig(challenge_rollouts=1)

    def test_cvar_weights_emphasize_worst_episode(self):
        weights, cvar, tail = v37.cvar_weights([4.0, 1.0, 3.0, 2.0], .25, .6)
        self.assertEqual(tail, (1,)); self.assertEqual(cvar, 1.0)
        self.assertGreater(weights[1], weights[0])

    def test_cvar_small_sample_is_finite(self):
        weights, cvar, tail = v37.cvar_weights([-.5], .25, .6)
        self.assertTrue(np.isfinite(weights).all()); self.assertEqual(cvar, -.5)

    def test_committed_audit_seed_suite_is_unique_and_large(self):
        for path in (Path("audit_seeds_v37_committed.txt"),Path("audit_seeds_v37_002_committed.txt")):
            seeds=[int(x) for x in path.read_text().splitlines()]
            self.assertEqual(len(seeds),64); self.assertEqual(len(set(seeds)),64)


class CriticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=Path("artifacts/v36/qdppo-evaluation-001/evolution_state_v36.npz")
        cls.metadata,_,cls.archive,cls.hof=v37.v36.load_checkpoint(cls.source)
        source_simulation=v37.v35.SimulationConfig(**cls.metadata["simulation"])
        cls.simulation=v37.v35.SimulationConfig(**{**asdict(source_simulation),"max_frames":32})

    def test_migration_preserves_actor_hash(self):
        policy=v37.RobustPolicy.migrate(self.hof.policy,self.simulation)
        self.assertEqual(policy.brain.genome_hash,self.hof.policy.brain.genome_hash)

    def test_critic_has_explicit_context_columns(self):
        policy=v37.RobustPolicy.migrate(self.hof.policy,self.simulation)
        self.assertEqual(policy.critic_W1.shape[1],len(v37.v35.SENSOR_LABELS)+len(v37.CRITIC_CONTEXT_LABELS))
        self.assertTrue(np.all(policy.critic_W1[:,-len(v37.CRITIC_CONTEXT_LABELS):]==0))

    def test_lineage_context_is_bounded(self):
        policy=v37.RobustPolicy.migrate(self.hof.policy,self.simulation)
        world=v37.RobustRollout(self.simulation,policy,1,2,"water_fire_challenge",v37.v36.RewardPolicy(),v37.RobustnessConfig(),0)
        context=v37.lineage_context(world)
        self.assertEqual(context.shape,(5,)); self.assertTrue(np.all((0<=context)&(context<=1)))

    def test_profile_is_actually_challenge(self):
        policy=v37.RobustPolicy.migrate(self.hof.policy,self.simulation)
        world=v37.RobustRollout(self.simulation,policy,1,2,"water_fire_challenge",v37.v36.RewardPolicy(),v37.RobustnessConfig(),0)
        self.assertEqual(world.profile,"water_fire_challenge")

    def test_specialist_bootstrap_is_deterministic_and_provenanced(self):
        robust=v37.RobustnessConfig(); a=v37.bootstrap_candidates(self.source,self.simulation,robust,8,20260711)[1]
        b=v37.bootstrap_candidates(self.source,self.simulation,robust,8,20260711)[1]
        identity=lambda rows:[(c.source_kind,c.source_policy_hash,c.policy.brain.genome_hash) for c in rows]
        self.assertEqual(identity(a),identity(b)); self.assertEqual(a[0].source_kind,"protected_v36_hof")


class ArtifactTests(unittest.TestCase):
    def test_approval_is_scoped_and_unsigned(self):
        import json
        record=json.loads(Path("approval_v37.json").read_text())
        self.assertEqual(record["experiment_id"],"robustness-v37-001")
        self.assertFalse(record["release_authorized_conditionally"])

    def test_parser_has_train_status_audit(self):
        parser=v37.build_parser()
        self.assertEqual(parser.parse_args(["status","--checkpoint","x.npz"]).command,"status")

    def test_positive_delta_policy_is_preservable(self):
        import json
        audit=json.loads(Path("artifacts/v36/qdppo-evaluation-001/terminal_audit_v36.json").read_text())
        positives=[row for row in audit["pairs"] if row["delta"]>0]
        self.assertGreaterEqual(len(positives),1)
        self.assertEqual(audit["v36_policy_hash"],"ee521f0fb698762c6d2794d6ce0aff6114af2c3ee0bf5c31e213f54fff3de02f")

    def test_corrected_checkpoint_is_hardened_and_hash_valid(self):
        checkpoint=Path("artifacts/v37/robustness-v37-002/evolution_state_v37.npz")
        metadata,policy,simulation=v37.load_hof(checkpoint)
        self.assertEqual(metadata["generation"],0)
        self.assertEqual(metadata["record"]["record_hash"],metadata["record_hash"])
        self.assertEqual(policy.policy_hash,metadata["hof"]["policy_hash"])
        with np.load(checkpoint,allow_pickle=False) as data:
            self.assertTrue(any("_m" in name for name in data.files))
            self.assertTrue(any("_v" in name for name in data.files))


if __name__=="__main__": unittest.main()
