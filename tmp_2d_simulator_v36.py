from __future__ import annotations

"""Blast_Pit v36: governed quality-diversity plus NumPy PPO.

This module layers a bounded PPO optimizer and deterministic MAP-Elites archive
over the authoritative v35 simulator.  It deliberately uses only JSON and
non-object NumPy arrays for checkpoints; no pickle-capable loader is used.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import sys
import tempfile
import traceback
import zipfile
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from pathlib import Path
from statistics import median
from typing import TYPE_CHECKING, Iterable, Sequence

import numpy as np


APP_VERSION = "v36"
SCHEMA_VERSION = "v36.0"
ALGORITHM = "qd-ppo-numpy"
OBSERVATION_SCHEMA = "blast-pit-local-19-v1"
ACTION_SCHEMA = "bounded-turn-speed-2-v1"
REWARD_SCHEMA = "individual-delta-plus-terminal-v1"
QD_SCHEMA = "exploration-reproduction-uniform-bins-v1"
MAX_CHECKPOINT_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_TOTAL_ENVIRONMENT_FRAMES = 1_000_000_000
POLICY_ARRAY_COUNT = 11
AUDIT_SCHEMA = "v36.audit.v1"
APPROVAL_SCHEMA = "approval.v36.v1"


def _load_v35():
    path = Path(__file__).with_name("tmp_2d_simulator_v35.py")
    if not path.is_file():
        raise RuntimeError(f"required v35 simulator is missing: {path}")
    spec = importlib.util.spec_from_file_location("blast_pit_v35", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the v35 simulator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


v35 = _load_v35()

if TYPE_CHECKING:
    import tmp_2d_simulator_v35 as v35_types
else:
    # Keep runtime annotation resolution aligned with the governed dynamic load.
    v35_types = v35


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def stable_seed(master: int, *parts: object) -> int:
    return v35.stable_seed(master, APP_VERSION, *parts)


@dataclass(frozen=True)
class PPOConfig:
    rollout_frames: int = 512
    update_epochs: int = 4
    minibatch_size: int = 256
    learning_rate: float = 3e-4
    gamma: float = 0.99
    gae_lambda: float = 0.95
    clip_epsilon: float = 0.2
    value_coefficient: float = 0.5
    entropy_coefficient: float = 0.01
    max_grad_norm: float = 0.5
    initial_action_std: float = 0.25
    terminal_bonus: float = 0.25
    target_kl: float = 0.03

    def __post_init__(self) -> None:
        if not 16 <= self.rollout_frames <= 1_000_000:
            raise ValueError("rollout_frames must be in [16,1000000]")
        if not 1 <= self.update_epochs <= 64 or not 8 <= self.minibatch_size <= 65536:
            raise ValueError("invalid PPO epoch or minibatch limit")
        finite = (self.learning_rate, self.gamma, self.gae_lambda, self.clip_epsilon,
                  self.value_coefficient, self.entropy_coefficient, self.max_grad_norm,
                  self.initial_action_std, self.terminal_bonus, self.target_kl)
        if not all(math.isfinite(x) for x in finite):
            raise ValueError("PPO settings must be finite")
        if not 0 < self.learning_rate <= .1 or not 0 < self.gamma <= 1 or not 0 <= self.gae_lambda <= 1:
            raise ValueError("invalid PPO learning/discount setting")
        if not 0 < self.clip_epsilon <= 1 or not 0 < self.max_grad_norm <= 100:
            raise ValueError("invalid PPO clipping setting")
        if not 0.01 <= self.initial_action_std <= 2 or not 0 < self.target_kl <= 1:
            raise ValueError("invalid PPO distribution setting")


@dataclass(frozen=True)
class QDConfig:
    bins: int = 5
    nominees: int = 3
    minimum_quality: float = 0.05

    def __post_init__(self) -> None:
        if not 2 <= self.bins <= 16 or self.bins * self.bins > 256:
            raise ValueError("QD bins must produce at most 256 cells")
        if not 1 <= self.nominees <= 8 or not 0 <= self.minimum_quality <= 1:
            raise ValueError("invalid QD nominee or quality setting")

    @property
    def edges(self) -> tuple[float, ...]:
        return tuple(float(x) for x in np.linspace(0, 1, self.bins + 1))


@dataclass(frozen=True)
class RewardPolicy:
    survival: float = .001
    food: float = .08
    water: float = .10
    recovery: float = .12
    fire_contact: float = -.10
    energy: float = -.0005
    death: float = -.20
    terminal_bonus: float = .25
    clip: float = 1.0

    def __post_init__(self) -> None:
        values = tuple(asdict(self).values())
        if not all(math.isfinite(float(x)) for x in values) or not 0 < self.clip <= 100:
            raise ValueError("invalid reward policy")


@dataclass
class Policy:
    brain: v35_types.Brain
    critic_W1: np.ndarray
    critic_b1: np.ndarray
    critic_W2: np.ndarray
    critic_b2: np.ndarray
    log_std: np.ndarray

    @classmethod
    def random(cls, config: v35_types.SimulationConfig, rng: np.random.Generator, action_std: float) -> "Policy":
        brain = v35.Brain.random(config, rng)
        return cls(brain, rng.normal(0, .15, (config.hidden1, len(v35.SENSOR_LABELS))),
                   np.zeros(config.hidden1), rng.normal(0, .15, (1, config.hidden1)),
                   np.zeros(1), np.full(2, math.log(action_std)))

    def copy(self) -> "Policy":
        return Policy(self.brain.copy(), self.critic_W1.copy(), self.critic_b1.copy(),
                      self.critic_W2.copy(), self.critic_b2.copy(), self.log_std.copy())

    def arrays(self) -> tuple[np.ndarray, ...]:
        return (*self.brain.arrays(), self.critic_W1, self.critic_b1,
                self.critic_W2, self.critic_b2, self.log_std)

    def validate(self, config: v35_types.SimulationConfig) -> None:
        self.brain.validate(config)
        shapes = ((config.hidden1, len(v35.SENSOR_LABELS)), (config.hidden1,),
                  (1, config.hidden1), (1,), (2,))
        for array, shape in zip(self.arrays()[6:], shapes):
            if array.shape != shape or array.dtype != np.float64 or not np.isfinite(array).all():
                raise ValueError(f"invalid policy array, expected finite float64 {shape}")
        if np.any(self.log_std < -5) or np.any(self.log_std > 1):
            raise ValueError("policy log_std outside governed bounds")

    @property
    def actor_hash(self) -> str:
        return self.brain.genome_hash

    @property
    def policy_hash(self) -> str:
        digest = hashlib.sha256()
        digest.update(b"actor-critic-policy-v1")
        for array in self.arrays():
            value = np.ascontiguousarray(array, dtype="<f8")
            digest.update(canonical_json(list(value.shape)).encode())
            digest.update(value.tobytes())
        return digest.hexdigest()

    def actor(self, obs: np.ndarray) -> tuple[np.ndarray, tuple[np.ndarray, ...]]:
        h1 = np.tanh(obs @ self.brain.W1.T + self.brain.b1)
        h2 = np.tanh(h1 @ self.brain.W2.T + self.brain.b2)
        location = h2 @ self.brain.W3.T + self.brain.b3
        mean = np.tanh(location)
        return mean, (obs, h1, h2, location)

    def value(self, obs: np.ndarray) -> tuple[np.ndarray, tuple[np.ndarray, ...]]:
        h = np.tanh(obs @ self.critic_W1.T + self.critic_b1)
        value = (h @ self.critic_W2.T + self.critic_b2).reshape(-1)
        return value, (obs, h)


@dataclass
class Adam:
    m: list[np.ndarray]
    v: list[np.ndarray]
    step: int = 0

    @classmethod
    def zeros(cls, policy: Policy) -> "Adam":
        return cls([np.zeros_like(x) for x in policy.arrays()], [np.zeros_like(x) for x in policy.arrays()])

    def apply(self, arrays: Sequence[np.ndarray], gradients: Sequence[np.ndarray], lr: float, max_norm: float) -> float:
        if len(arrays) != len(gradients) or len(arrays) != len(self.m):
            raise ValueError("optimizer array mismatch")
        norm = math.sqrt(sum(float(np.sum(g * g)) for g in gradients))
        if not math.isfinite(norm):
            raise ValueError("non-finite PPO gradient")
        scale = min(1.0, max_norm / (norm + 1e-12))
        self.step += 1
        for p, g, m, v in zip(arrays, gradients, self.m, self.v):
            g = g * scale
            m *= .9; m += .1 * g
            v *= .999; v += .001 * g * g
            mh = m / (1 - .9 ** self.step)
            vh = v / (1 - .999 ** self.step)
            p -= lr * mh / (np.sqrt(vh) + 1e-8)
            if not np.isfinite(p).all():
                raise ValueError("non-finite policy after PPO update")
        arrays[-1][:] = np.clip(arrays[-1], -5, 1)
        return norm


@dataclass(frozen=True)
class Transition:
    observation: np.ndarray
    action: np.ndarray
    old_log_probability: float
    value: float
    reward: float
    done: bool
    creature_id: int


def squashed_gaussian_log_probability(action: np.ndarray, location: np.ndarray, log_std: np.ndarray) -> np.ndarray:
    bounded = np.clip(action, -1 + 1e-7, 1 - 1e-7)
    latent = np.arctanh(bounded)
    variance = np.exp(2 * log_std)
    normal = -0.5 * np.sum((latent - location) ** 2 / variance + 2 * log_std + math.log(2 * math.pi), axis=1)
    jacobian = np.sum(np.log(1 - bounded * bounded + 1e-6), axis=1)
    return normal - jacobian


def generalized_advantage(rewards: np.ndarray, values: np.ndarray, dones: np.ndarray,
                          gamma: float, lam: float, bootstrap: float = 0.0) -> tuple[np.ndarray, np.ndarray]:
    if not (rewards.ndim == values.ndim == dones.ndim == 1 and len(rewards) == len(values) == len(dones)):
        raise ValueError("GAE arrays must be equal one-dimensional arrays")
    advantages = np.zeros_like(rewards, dtype=np.float64)
    carry = 0.0
    next_value = float(bootstrap)
    for index in range(len(rewards) - 1, -1, -1):
        live = 1.0 - float(dones[index])
        delta = rewards[index] + gamma * next_value * live - values[index]
        carry = delta + gamma * lam * live * carry
        advantages[index] = carry
        next_value = values[index]
    return advantages, advantages + values


class SamplingBrain(v35.Brain):
    def __init__(self, policy: Policy, rng: np.random.Generator):
        super().__init__(*(array for array in policy.brain.arrays()))
        self.policy = policy
        self.rng = rng
        self.pending: list[tuple[np.ndarray, np.ndarray, float, float]] = []

    def forward(self, inputs: np.ndarray) -> np.ndarray:
        obs = np.asarray(inputs, dtype=np.float64)[None, :]
        _, cache = self.policy.actor(obs)
        location = cache[3]
        value, _ = self.policy.value(obs)
        latent = location[0] + np.exp(self.policy.log_std) * self.rng.normal(size=2)
        action = np.tanh(latent)
        logp = float(squashed_gaussian_log_probability(action[None, :], location, self.policy.log_std)[0])
        self.pending.append((obs[0].copy(), action.copy(), logp, float(value[0])))
        return action


class RolloutSimulation(v35.Simulation):
    def __init__(self, config: v35_types.SimulationConfig, policy: Policy, seed: int,
                 action_seed: int, reward_policy: RewardPolicy):
        self.sampling_brain = SamplingBrain(policy, np.random.default_rng(action_seed))
        self.reward_policy = reward_policy
        self.trajectories: dict[int, list[Transition]] = {}
        super().__init__(config, self.sampling_brain, seed, execution=v35.ExecutionConfig(1, "python", "scalar"))

    def _act(self, creature, inputs, outputs) -> None:
        before = (self.metrics.lineage_food, self.metrics.lineage_water,
                  self.metrics.water_recoveries, self.metrics.fire_contact_frames,
                  self.metrics.lineage_energy_spent)
        obs, action, logp, value = self.sampling_brain.pending.pop(0)
        super()._act(creature, inputs, outputs)
        after = (self.metrics.lineage_food, self.metrics.lineage_water,
                 self.metrics.water_recoveries, self.metrics.fire_contact_frames,
                 self.metrics.lineage_energy_spent)
        reward = (self.reward_policy.survival
                  + self.reward_policy.food * (after[0] - before[0])
                  + self.reward_policy.water * (after[1] - before[1])
                  + self.reward_policy.recovery * (after[2] - before[2])
                  + self.reward_policy.fire_contact * (after[3] - before[3])
                  + self.reward_policy.energy * (after[4] - before[4])
                  + (self.reward_policy.death if not creature.alive else 0.0))
        reward = float(np.clip(reward, -self.reward_policy.clip, self.reward_policy.clip))
        self.trajectories.setdefault(creature.creature_id, []).append(
            Transition(obs, action, logp, value, reward, not creature.alive, creature.creature_id))

    def finish(self) -> list[tuple[list[Transition], float]]:
        fitness, _ = self.fitness()
        living = {creature.creature_id: creature for creature in self.creatures if creature.alive}
        result: list[tuple[list[Transition], float]] = []
        for trajectory in self.trajectories.values():
            if trajectory:
                last = trajectory[-1]
                truncated = last.creature_id in living
                trajectory[-1] = Transition(last.observation, last.action, last.old_log_probability,
                                             last.value, last.reward + self.reward_policy.terminal_bonus * fitness,
                                             not truncated, last.creature_id)
                bootstrap = 0.0
                if truncated:
                    final_observation = np.asarray(self.sense(living[last.creature_id]), dtype=np.float64)[None, :]
                    bootstrap = float(self.sampling_brain.policy.value(final_observation)[0][0])
                result.append((trajectory, bootstrap))
        return result


@dataclass(frozen=True)
class PPOReport:
    environment_frames: int
    agent_transitions: int
    updates: int
    mean_reward: float
    policy_loss: float
    value_loss: float
    entropy: float
    approximate_kl: float
    clip_fraction: float
    gradient_norm: float
    pre_policy_hash: str
    post_policy_hash: str
    rollout_hash: str


def _actor_grad(policy: Policy, obs: np.ndarray, action: np.ndarray, coefficient: np.ndarray) -> list[np.ndarray]:
    _, (_, h1, h2, location) = policy.actor(obs)
    bounded = np.clip(action, -1 + 1e-7, 1 - 1e-7)
    latent = np.arctanh(bounded)
    inv_var = np.exp(-2 * policy.log_std)
    dz3 = coefficient[:, None] * (latent - location) * inv_var / len(obs)
    gW3 = dz3.T @ h2; gb3 = dz3.sum(axis=0)
    dz2 = (dz3 @ policy.brain.W3) * (1 - h2 * h2)
    gW2 = dz2.T @ h1; gb2 = dz2.sum(axis=0)
    dz1 = (dz2 @ policy.brain.W2) * (1 - h1 * h1)
    gW1 = dz1.T @ obs; gb1 = dz1.sum(axis=0)
    glog = np.sum(coefficient[:, None] * (((latent - location) ** 2) * inv_var - 1), axis=0) / len(obs)
    return [gW1, gb1, gW2, gb2, gW3, gb3, glog]


def ppo_update(policy: Policy, optimizer: Adam, trajectories: Sequence[tuple[Sequence[Transition], float]],
               config: PPOConfig, rng: np.random.Generator, environment_frames: int) -> PPOReport:
    pre_hash = policy.policy_hash
    rows: list[tuple[Transition, float, float]] = []
    for trajectory, bootstrap in trajectories:
        rewards = np.asarray([x.reward for x in trajectory], dtype=np.float64)
        values = np.asarray([x.value for x in trajectory], dtype=np.float64)
        dones = np.asarray([x.done for x in trajectory], dtype=np.float64)
        advantages, returns = generalized_advantage(rewards, values, dones, config.gamma, config.gae_lambda, bootstrap)
        rows.extend((item, float(adv), float(ret)) for item, adv, ret in zip(trajectory, advantages, returns))
    if not rows:
        raise ValueError("PPO rollout contained no transitions")
    observations = np.stack([x[0].observation for x in rows])
    actions = np.stack([x[0].action for x in rows])
    old_logp = np.asarray([x[0].old_log_probability for x in rows])
    advantages = np.asarray([x[1] for x in rows])
    returns = np.asarray([x[2] for x in rows])
    advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
    rollout_hash = hashlib.sha256(np.ascontiguousarray(np.column_stack((observations, actions, old_logp, returns)), dtype="<f8").tobytes()).hexdigest()
    metrics: list[tuple[float, float, float, float, float, float]] = []
    updates = 0
    for _ in range(config.update_epochs):
        permutation = rng.permutation(len(rows))
        for start in range(0, len(rows), config.minibatch_size):
            indices = permutation[start:start + config.minibatch_size]
            if not len(indices): continue
            obs, act, old, adv, target = observations[indices], actions[indices], old_logp[indices], advantages[indices], returns[indices]
            _, actor_cache = policy.actor(obs)
            location = actor_cache[3]
            logp = squashed_gaussian_log_probability(act, location, policy.log_std)
            ratio = np.exp(np.clip(logp - old, -20, 20))
            unclipped = ratio * adv
            clipped = np.clip(ratio, 1 - config.clip_epsilon, 1 + config.clip_epsilon) * adv
            use_unclipped = unclipped <= clipped
            actor_coefficient = -np.where(use_unclipped, ratio * adv, 0.0)
            actor_grads = _actor_grad(policy, obs, act, actor_coefficient)
            value, (_, vh) = policy.value(obs)
            value_error = value - target
            dv = config.value_coefficient * value_error / len(indices)
            gCW2 = dv[None, :] @ vh
            gCb2 = np.asarray([dv.sum()])
            dz = dv[:, None] * policy.critic_W2 * (1 - vh * vh)
            gCW1 = dz.T @ obs; gCb1 = dz.sum(axis=0)
            gradients = [*actor_grads[:6], gCW1, gCb1, gCW2, gCb2,
                         actor_grads[6] - config.entropy_coefficient]
            norm = optimizer.apply(policy.arrays(), gradients, config.learning_rate, config.max_grad_norm)
            entropy = float(np.sum(policy.log_std + .5 * math.log(2 * math.pi * math.e)))
            kl = float(np.mean(old - logp))
            metrics.append((float(-np.mean(np.minimum(unclipped, clipped))), float(.5 * np.mean(value_error ** 2)),
                            entropy, kl, float(np.mean(np.abs(ratio - 1) > config.clip_epsilon)), norm))
            updates += 1
        if metrics and metrics[-1][3] > config.target_kl:
            break
    means = np.mean(np.asarray(metrics), axis=0)
    return PPOReport(environment_frames, len(rows), updates,
                     float(np.mean([x[0].reward for x in rows])), *map(float, means),
                     pre_hash, policy.policy_hash, rollout_hash)


@dataclass
class Candidate:
    candidate_id: int
    policy: Policy
    optimizer: Adam
    parent_id: int | None = None
    origin: str = "random"
    trials: list[v35_types.TrialSummary] = field(default_factory=list)
    validation_trials: list[v35_types.TrialSummary] = field(default_factory=list)
    ppo_report: PPOReport | None = None

    @property
    def selection_fitness(self) -> float:
        proxy = v35.Candidate(self.candidate_id, self.policy.brain, trials=self.trials)
        return proxy.selection_fitness

    @property
    def descriptor(self) -> tuple[float, float]:
        if not self.trials: return 0.0, 0.0
        return (float(median(x.components["exploration"] for x in self.trials)),
                float(median(x.components["reproduction"] for x in self.trials)))

    @property
    def early_extinction_rate(self) -> float:
        return sum(bool(x.metrics["early_extinction"]) for x in self.trials) / len(self.trials) if self.trials else 1.0


@dataclass(frozen=True)
class ArchiveEntry:
    cell: tuple[int, int]
    candidate_id: int
    policy_hash: str
    quality: float
    descriptor: tuple[float, float]
    generation: int


class QDArchive:
    def __init__(self, config: QDConfig):
        self.config = config
        self.entries: dict[tuple[int, int], ArchiveEntry] = {}
        self.policies: dict[tuple[int, int], Policy] = {}

    def cell(self, descriptor: tuple[float, float]) -> tuple[int, int]:
        if not all(math.isfinite(x) and 0 <= x <= 1 for x in descriptor):
            raise ValueError("descriptor must be finite and in [0,1]")
        return tuple(min(self.config.bins - 1, int(x * self.config.bins)) for x in descriptor)  # type: ignore[return-value]

    def consider(self, candidate: Candidate, generation: int) -> str:
        quality = candidate.selection_fitness
        if quality < self.config.minimum_quality or candidate.early_extinction_rate >= 1:
            return "rejected"
        cell = self.cell(candidate.descriptor)
        proposed = ArchiveEntry(cell, candidate.candidate_id, candidate.policy.policy_hash, quality, candidate.descriptor, generation)
        incumbent = self.entries.get(cell)
        if incumbent is None:
            self.entries[cell] = proposed; self.policies[cell] = candidate.policy.copy(); return "inserted"
        if (proposed.quality, proposed.policy_hash) > (incumbent.quality, incumbent.policy_hash):
            self.entries[cell] = proposed; self.policies[cell] = candidate.policy.copy(); return "replaced"
        return "retained"

    @property
    def coverage(self) -> float:
        return len(self.entries) / (self.config.bins ** 2)

    @property
    def qd_score(self) -> float:
        return sum(entry.quality for entry in self.entries.values())


def evaluate(policy: Policy, config: v35_types.SimulationConfig, candidate_id: int,
             seeds: Sequence[int], profiles: Sequence[str]) -> list[v35_types.TrialSummary]:
    results = []
    for seed, profile in zip(seeds, profiles):
        summary = v35.Simulation(config, policy.brain, seed, candidate_id, profile,
                                 v35.ExecutionConfig(1, "python", "batch")).run()
        v35.validate_trial_summary(summary, config, candidate_id, seed, profile)
        results.append(summary)
    return results


def train_candidate(candidate: Candidate, generation: int, master_seed: int,
                    simulation_config: v35_types.SimulationConfig, ppo_config: PPOConfig,
                    reward_policy: RewardPolicy) -> None:
    trajectories: list[tuple[list[Transition], float]] = []
    collected = 0; rollout = 0
    while collected < ppo_config.rollout_frames:
        seed = stable_seed(master_seed, "ppo_train", generation, candidate.candidate_id, rollout)
        action_seed = stable_seed(master_seed, "ppo_actions", generation, candidate.candidate_id, rollout)
        sim = RolloutSimulation(simulation_config, candidate.policy, seed, action_seed, reward_policy)
        while sim.step() is None and sim.frame < min(simulation_config.max_frames, ppo_config.rollout_frames - collected):
            pass
        episode = sim.finish(); trajectories.extend(episode)
        collected += sim.frame; rollout += 1
    candidate.ppo_report = ppo_update(candidate.policy, candidate.optimizer, trajectories, ppo_config,
                                      np.random.default_rng(stable_seed(master_seed, "ppo_minibatches", generation, candidate.candidate_id)),
                                      collected)


def experiment_fingerprint(simulation: v35_types.SimulationConfig, ppo: PPOConfig, qd: QDConfig,
                           reward: RewardPolicy) -> str:
    v35_path = Path(__file__).with_name("tmp_2d_simulator_v35.py")
    source_path = Path(__file__)
    return sha256_json({"algorithm": ALGORITHM, "app": APP_VERSION, "observation": OBSERVATION_SCHEMA,
                        "action": ACTION_SCHEMA, "reward_schema": REWARD_SCHEMA, "qd_schema": QD_SCHEMA,
                        "simulation": asdict(simulation), "ppo": asdict(ppo), "qd": asdict(qd),
                        "reward": asdict(reward), "numpy": np.__version__, "dtype": "float64",
                        "python": sys.version, "platform": platform.platform(),
                        "v35_source_sha256": hashlib.sha256(v35_path.read_bytes()).hexdigest(),
                        "v36_source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                        "native_threads": {name: os.environ.get(name) for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}})


def save_checkpoint(path: Path, metadata: dict[str, object], candidates: Sequence[Candidate], archive: QDArchive,
                    validation_hof: Candidate | None = None) -> None:
    if path.is_symlink() or path.parent.is_symlink(): raise ValueError("checkpoint symlinks are prohibited")
    path.parent.mkdir(parents=True, exist_ok=True)
    arrays: dict[str, np.ndarray] = {}
    for candidate in candidates:
        for index, array in enumerate(candidate.policy.arrays()): arrays[f"c{candidate.candidate_id}_p{index}"] = array
        for index, array in enumerate(candidate.optimizer.m): arrays[f"c{candidate.candidate_id}_m{index}"] = array
        for index, array in enumerate(candidate.optimizer.v): arrays[f"c{candidate.candidate_id}_v{index}"] = array
    for archive_index, cell in enumerate(sorted(archive.entries)):
        for policy_index, array in enumerate(archive.policies[cell].arrays()):
            arrays[f"a{archive_index}_p{policy_index}"] = array
    if validation_hof is not None:
        for policy_index, array in enumerate(validation_hof.policy.arrays()): arrays[f"hof_p{policy_index}"] = array
    full = dict(metadata)
    full["candidates"] = [{"candidate_id": c.candidate_id, "parent_id": c.parent_id, "origin": c.origin,
                            "optimizer_step": c.optimizer.step, "policy_hash": c.policy.policy_hash} for c in candidates]
    full["archive"] = [asdict(archive.entries[cell]) for cell in sorted(archive.entries)]
    encoded = canonical_json(full).encode()
    if len(encoded) > MAX_METADATA_BYTES: raise ValueError("checkpoint metadata exceeds limit")
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
            temp = Path(handle.name)
            np.savez_compressed(handle, metadata=np.frombuffer(encoded, dtype=np.uint8), **arrays)
            handle.flush(); os.fsync(handle.fileno())
        if temp.stat().st_size > MAX_CHECKPOINT_BYTES: raise ValueError("checkpoint exceeds size limit")
        with np.load(temp, allow_pickle=False) as data:
            decoded = json.loads(bytes(data["metadata"]).decode())
            if decoded["fingerprint"] != metadata["fingerprint"]: raise ValueError("checkpoint round-trip mismatch")
        os.replace(temp, path)
    finally:
        if temp and temp.exists(): temp.unlink()


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", mode="w", encoding="utf-8", delete=False) as handle:
            temp = Path(handle.name); handle.write(canonical_json(value) + "\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if temp and temp.exists(): temp.unlink()


def validate_artifact_paths(root: Path, *paths: Path) -> None:
    resolved_root = root.resolve()
    for path in paths:
        resolved = path.resolve(strict=False)
        if os.path.commonpath((str(resolved_root), str(resolved))) != str(resolved_root):
            raise ValueError("artifact path escapes artifact root")
        current = path
        while current != root.parent and current != current.parent:
            if current.exists() and current.is_symlink():
                raise ValueError(f"artifact symlinks are prohibited: {current}")
            current = current.parent


def file_evidence(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def _policy_from_arrays(arrays: Sequence[np.ndarray], config: v35_types.SimulationConfig) -> Policy:
    if len(arrays) != POLICY_ARRAY_COUNT:
        raise ValueError("policy array count mismatch")
    values = [np.array(value, dtype=np.float64, copy=True) for value in arrays]
    policy = Policy(v35.Brain(*values[:6]), *values[6:])
    policy.validate(config)
    return policy


def _preflight_checkpoint(path: Path) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CHECKPOINT_BYTES:
        raise ValueError("checkpoint is missing, linked, or oversized")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not 2 <= len(members) <= 4096:
            raise ValueError("checkpoint member count is invalid")
        total = 0
        for member in members:
            if member.is_dir() or not re.fullmatch(r"[A-Za-z0-9_]+\.npy", member.filename):
                raise ValueError("checkpoint member name is invalid")
            if member.file_size > MAX_CHECKPOINT_BYTES or (member.compress_size and member.file_size / member.compress_size > 1000):
                raise ValueError("checkpoint member exceeds decompression limits")
            total += member.file_size
        if total > MAX_CHECKPOINT_BYTES * 4:
            raise ValueError("checkpoint decompressed size exceeds limit")


def load_checkpoint(path: Path) -> tuple[dict[str, object], list[Candidate], QDArchive, Candidate | None]:
    _preflight_checkpoint(path)
    with np.load(path, allow_pickle=False) as data:
        if "metadata" not in data.files:
            raise ValueError("checkpoint metadata is missing")
        raw = np.asarray(data["metadata"])
        if raw.dtype != np.uint8 or raw.ndim != 1 or raw.nbytes > MAX_METADATA_BYTES:
            raise ValueError("checkpoint metadata encoding is invalid")
        metadata = json.loads(bytes(raw).decode("utf-8"))
        if metadata.get("schema_version") != SCHEMA_VERSION or metadata.get("algorithm") != ALGORITHM:
            raise ValueError("checkpoint schema or algorithm mismatch")
        simulation = v35.SimulationConfig(**dict(metadata["simulation"]))
        qd_config = QDConfig(**dict(metadata["qd"]))
        descriptors = metadata.get("candidates")
        archive_descriptors = metadata.get("archive")
        if not isinstance(descriptors, list) or not 2 <= len(descriptors) <= 32 or not isinstance(archive_descriptors, list):
            raise ValueError("checkpoint candidate/archive metadata is invalid")
        expected = {"metadata"}
        candidates: list[Candidate] = []
        seen_ids: set[int] = set()
        for descriptor in descriptors:
            candidate_id = int(descriptor["candidate_id"])
            if candidate_id in seen_ids:
                raise ValueError("duplicate checkpoint candidate ID")
            seen_ids.add(candidate_id)
            policy_names = [f"c{candidate_id}_p{i}" for i in range(POLICY_ARRAY_COUNT)]
            m_names = [f"c{candidate_id}_m{i}" for i in range(POLICY_ARRAY_COUNT)]
            v_names = [f"c{candidate_id}_v{i}" for i in range(POLICY_ARRAY_COUNT)]
            expected.update(policy_names + m_names + v_names)
            if any(name not in data.files for name in policy_names + m_names + v_names):
                raise ValueError("checkpoint candidate arrays are incomplete")
            policy = _policy_from_arrays([data[name] for name in policy_names], simulation)
            m = [np.array(data[name], dtype=np.float64, copy=True) for name in m_names]
            vv = [np.array(data[name], dtype=np.float64, copy=True) for name in v_names]
            if any(value.shape != target.shape or not np.isfinite(value).all() for value, target in zip(m + vv, list(policy.arrays()) * 2)):
                raise ValueError("checkpoint optimizer arrays are invalid")
            if policy.policy_hash != descriptor["policy_hash"]:
                raise ValueError("checkpoint candidate policy hash mismatch")
            candidates.append(Candidate(candidate_id, policy, Adam(m, vv, int(descriptor["optimizer_step"])),
                                        descriptor.get("parent_id"), str(descriptor.get("origin", "restored"))))
        qd = QDArchive(qd_config)
        cells: set[tuple[int, int]] = set()
        for archive_index, descriptor in enumerate(archive_descriptors):
            entry = ArchiveEntry(tuple(int(x) for x in descriptor["cell"]), int(descriptor["candidate_id"]),
                                 str(descriptor["policy_hash"]), float(descriptor["quality"]),
                                 tuple(float(x) for x in descriptor["descriptor"]), int(descriptor["generation"]))
            if entry.cell in cells or qd.cell(entry.descriptor) != entry.cell or not math.isfinite(entry.quality):
                raise ValueError("checkpoint archive entry is invalid")
            cells.add(entry.cell)
            names = [f"a{archive_index}_p{i}" for i in range(POLICY_ARRAY_COUNT)]
            expected.update(names)
            if any(name not in data.files for name in names):
                raise ValueError("checkpoint archive arrays are incomplete")
            policy = _policy_from_arrays([data[name] for name in names], simulation)
            if policy.policy_hash != entry.policy_hash:
                raise ValueError("checkpoint archive policy hash mismatch")
            qd.entries[entry.cell] = entry; qd.policies[entry.cell] = policy
        hof = None
        hof_summary = metadata.get("validation_hof") or dict(metadata.get("record", {})).get("validation_hof")
        hof_names = [f"hof_p{i}" for i in range(POLICY_ARRAY_COUNT)]
        if hof_summary is not None:
            expected.update(hof_names)
            if any(name not in data.files for name in hof_names):
                raise ValueError("checkpoint Hall-of-Fame arrays are incomplete")
            policy = _policy_from_arrays([data[name] for name in hof_names], simulation)
            if policy.policy_hash != hof_summary["policy_hash"]:
                raise ValueError("checkpoint Hall-of-Fame policy hash mismatch")
            hof = Candidate(int(hof_summary["candidate_id"]), policy, Adam.zeros(policy), origin="validation_hof")
        if set(data.files) != expected:
            raise ValueError("checkpoint contains unexpected members")
    record = dict(metadata["record"])
    supplied_hash = str(record.pop("record_hash"))
    if sha256_json(record) != supplied_hash or int(record["generation"]) != int(metadata["generation"]):
        raise ValueError("checkpoint embedded generation record is invalid")
    record["record_hash"] = supplied_hash
    if max(seen_ids) >= int(metadata["next_candidate_id"]):
        raise ValueError("checkpoint next candidate ID is invalid")
    return metadata, sorted(candidates, key=lambda item: item.candidate_id), qd, hof


def reconcile_results(path: Path, metadata: dict[str, object], repair: bool = True) -> dict[str, object]:
    checkpoint_record = dict(metadata["record"])
    records: list[dict[str, object]] = []
    if path.exists():
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(raw_lines):
            if not line.strip():
                if index != len(raw_lines) - 1: raise ValueError("results contain an interior blank line")
                continue
            try: record = json.loads(line)
            except json.JSONDecodeError:
                if index == len(raw_lines) - 1: break
                raise ValueError("results contain interior malformed JSON")
            records.append(record)
    previous = "0" * 64
    for generation, record in enumerate(records):
        supplied = str(record.get("record_hash", "")); unsigned = dict(record); unsigned.pop("record_hash", None)
        if int(record.get("generation", -1)) != generation or record.get("previous_record_hash") != previous or sha256_json(unsigned) != supplied:
            raise ValueError("results generation chain is invalid")
        previous = supplied
    checkpoint_generation = int(metadata["generation"])
    if len(records) == checkpoint_generation:
        if checkpoint_record["previous_record_hash"] != previous:
            raise ValueError("checkpoint does not extend results chain")
        if not repair:
            return {"state": "CHECKPOINT_AHEAD_RECOVERABLE", "records": len(records), "head": previous}
        path.parent.mkdir(parents=True, exist_ok=True); temp = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", mode="w", encoding="utf-8", delete=False, newline="\n") as handle:
                temp = Path(handle.name)
                for record in [*records, checkpoint_record]: handle.write(canonical_json(record) + "\n")
                handle.flush(); os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            if temp and temp.exists(): temp.unlink()
        records.append(checkpoint_record)
        return {"state": "REPAIRED_FROM_CHECKPOINT", "records": len(records), "head": checkpoint_record["record_hash"]}
    if len(records) != checkpoint_generation + 1 or records[-1] != checkpoint_record:
        raise ValueError("results are ahead of or divergent from checkpoint")
    return {"state": "CONSISTENT", "records": len(records), "head": checkpoint_record["record_hash"]}


def _emit_population(archive: QDArchive, ranked: Sequence[Candidate], population: int, next_id: int,
                     generation: int, master_seed: int, simulation: v35_types.SimulationConfig) -> tuple[list[Candidate], int]:
    archive_parents = [(archive.entries[cell].candidate_id, archive.policies[cell]) for cell in sorted(archive.entries)]
    parent_pool = archive_parents or [(candidate.candidate_id, candidate.policy) for candidate in ranked]
    result = []
    for index in range(population):
        parent_id, parent_policy = parent_pool[index % len(parent_pool)]
        policy = parent_policy.copy()
        if index >= max(1, population // 2):
            mutated, _ = v35.MutationPolicy().mutate(policy.brain, simulation,
                np.random.default_rng(stable_seed(master_seed, "emitter", generation, index)))
            policy.brain = mutated
        result.append(Candidate(next_id, policy, Adam.zeros(policy), parent_id,
                                "qd_elite" if index < max(1, population // 2) else "qd_mutation"))
        next_id += 1
    return result, next_id


def load_approval(path: Path, experiment_id: str, lineage_fingerprint: str, action: str) -> tuple[dict[str, object], str]:
    if not path.is_file() or path.stat().st_size > 64_000:
        raise ValueError("v36 approval record is missing or oversized")
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("schema_version") != APPROVAL_SCHEMA or record.get("project") != "Blast_Pit" or record.get("version") != APP_VERSION:
        raise ValueError("v36 approval identity mismatch")
    if record.get("status") != "approved" or record.get("experiment_id") != experiment_id or record.get("lineage_fingerprint") != lineage_fingerprint:
        raise ValueError("v36 approval scope mismatch")
    if action not in record.get("authorized_actions", []):
        raise ValueError(f"v36 approval does not authorize {action}")
    return record, sha256_json(record)


def _acquire_lock(path: Path) -> tuple[str, dict[str, object]]:
    token = hashlib.sha256(f"{os.getpid()}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()
    record = {"pid": os.getpid(), "token": token, "created_utc": datetime.now(timezone.utc).isoformat()}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8")); os.kill(int(existing["pid"]), 0)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            stale = path.with_name(path.name + ".stale." + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
            os.replace(path, stale)
        else:
            raise ValueError(f"training is already in progress pid={existing['pid']} lock={path}")
    with path.open("x", encoding="utf-8") as handle:
        handle.write(canonical_json(record)); handle.flush(); os.fsync(handle.fileno())
    return token, record


def _release_lock(path: Path, token: str) -> None:
    if path.exists():
        try: existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): return
        if existing.get("token") == token: path.unlink()


def _hof_source_generation(results_path: Path, policy_hash: str) -> int | None:
    if not results_path.is_file(): return None
    for line in results_path.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        record = json.loads(line)
        if dict(record.get("validation_hof", {})).get("policy_hash") == policy_hash:
            return int(record["generation"])
    return None


def _execute_generations(*, base: Path, checkpoint: Path, results_path: Path, status_path: Path,
                         candidates: list[Candidate], archive: QDArchive, validation_hof: Candidate | None,
                         hof_fitness: float, hof_source_generation: int | None, start_generation: int,
                         count: int, next_id: int, previous_hash: str, master_seed: int,
                         simulation: v35_types.SimulationConfig, ppo: PPOConfig, qd: QDConfig,
                         reward: RewardPolicy, lineage_fingerprint: str, approval_digest: str) -> int:
    population = len(candidates); implementation_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    transition_checkpoint_sha = file_evidence(checkpoint)["sha256"] if checkpoint.exists() else None
    if start_generation > 0:
        candidates, next_id = _emit_population(archive, candidates, population, next_id,
                                               start_generation - 1, master_seed, simulation)
    for generation in range(start_generation, start_generation + count):
        for index, candidate in enumerate(candidates, 1):
            print(f"progress generation={generation} phase=ppo candidate={index}/{population}", flush=True)
            train_candidate(candidate, generation, master_seed, simulation, ppo, reward)
            standard = [stable_seed(master_seed, "selection", generation, trial) for trial in range(simulation.trials)]
            challenge = [stable_seed(master_seed, "challenge", generation, trial) for trial in range(simulation.challenge_trials)]
            candidate.trials = evaluate(candidate.policy, simulation, candidate.candidate_id, standard + challenge,
                                        ["standard"] * len(standard) + ["water_fire_challenge"] * len(challenge))
        actions = {"inserted": 0, "replaced": 0, "retained": 0, "rejected": 0}
        for candidate in sorted(candidates, key=lambda c: c.candidate_id): actions[archive.consider(candidate, generation)] += 1
        ranked = sorted(candidates, key=lambda c: (-c.selection_fitness, c.policy.policy_hash))
        nominees = ranked[:qd.nominees]
        validation_seeds = [stable_seed(master_seed, "fixed_validation", trial) for trial in range(simulation.validation_trials)]
        for candidate in nominees:
            candidate.validation_trials = evaluate(candidate.policy, simulation, candidate.candidate_id,
                                                   validation_seeds, ["validation"] * len(validation_seeds))
        best = max(nominees, key=lambda c: (v35.Candidate(c.candidate_id, c.policy.brain, validation_trials=c.validation_trials).validation_fitness, c.policy.policy_hash))
        best_validation = v35.Candidate(best.candidate_id, best.policy.brain, validation_trials=best.validation_trials).validation_fitness
        if validation_hof is None or (best_validation, best.policy.policy_hash) > (hof_fitness, validation_hof.policy.policy_hash):
            validation_hof = Candidate(best.candidate_id, best.policy.copy(), Adam.zeros(best.policy), best.parent_id,
                                       "validation_hof", list(best.trials), list(best.validation_trials), best.ppo_report)
            hof_fitness = best_validation; hof_source_generation = generation
        hof_summary = {"candidate_id": validation_hof.candidate_id, "policy_hash": validation_hof.policy.policy_hash,
                       "fitness": hof_fitness, "source_generation": hof_source_generation}
        record = {"schema_version": SCHEMA_VERSION, "generation": generation, "algorithm": ALGORITHM,
                  "fingerprint": lineage_fingerprint, "previous_record_hash": previous_hash,
                  "implementation_sha256": implementation_sha, "approval_digest": approval_digest,
                  "implementation_transition_checkpoint_sha256": transition_checkpoint_sha,
                  "training_environment_frames": sum(c.ppo_report.environment_frames for c in candidates if c.ppo_report),
                  "training_agent_transitions": sum(c.ppo_report.agent_transitions for c in candidates if c.ppo_report),
                  "optimizer_updates": sum(c.ppo_report.updates for c in candidates if c.ppo_report),
                  "archive": {"coverage": archive.coverage, "qd_score": archive.qd_score, "occupied": len(archive.entries), **actions},
                  "champion": {"candidate_id": ranked[0].candidate_id, "selection_fitness": ranked[0].selection_fitness,
                               "policy_hash": ranked[0].policy.policy_hash},
                  "validation_nominee": {"candidate_id": best.candidate_id, "policy_hash": best.policy.policy_hash,
                                          "fitness": best_validation, "trials": [asdict(trial) for trial in best.validation_trials]},
                  "validation_hof": hof_summary,
                  "candidates": [{"candidate_id": c.candidate_id, "parent_id": c.parent_id, "origin": c.origin,
                                  "policy_hash": c.policy.policy_hash, "selection_fitness": c.selection_fitness,
                                  "descriptor": c.descriptor, "ppo": asdict(c.ppo_report) if c.ppo_report else None,
                                  "trials": [asdict(trial) for trial in c.trials]} for c in candidates]}
        record["record_hash"] = sha256_json(record); previous_hash = record["record_hash"]
        metadata = {"schema_version": SCHEMA_VERSION, "app_version": APP_VERSION, "algorithm": ALGORITHM,
                    "workflow_state": "TRAINING_COMMITTED", "generation": generation, "master_seed": master_seed,
                    "fingerprint": lineage_fingerprint, "record": record, "next_candidate_id": next_id,
                    "simulation": asdict(simulation), "ppo": asdict(ppo), "qd": asdict(qd), "reward": asdict(reward),
                    "validation_hof": hof_summary, "approval_digest": approval_digest,
                    "implementation_sha256": implementation_sha}
        save_checkpoint(checkpoint, metadata, candidates, archive, validation_hof)
        with results_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(record) + "\n"); handle.flush(); os.fsync(handle.fileno())
        write_json_atomic(status_path, {"workflow_state": "TRAINING_COMMITTED", "last_generation": generation,
                          "completed_generations": generation + 1, "fingerprint": lineage_fingerprint,
                          "archive_occupied": len(archive.entries), "archive_capacity": qd.bins ** 2,
                          "archive_coverage": archive.coverage, "qd_score": archive.qd_score,
                          "validation_hof": hof_summary, "checkpoint": str(checkpoint), "results": str(results_path)})
        print(f"commit generation={generation} selection={ranked[0].selection_fitness:.6f} validation={best_validation:.6f} "
              f"coverage={archive.coverage:.3f} qd_score={archive.qd_score:.6f} record_hash={previous_hash}", flush=True)
        candidates, next_id = _emit_population(archive, ranked, population, next_id, generation, master_seed, simulation)
    return 0


def run_experiment(args: argparse.Namespace) -> int:
    elite_count = min(2, args.population - 1)
    simulation = v35.SimulationConfig(generations=args.generations, population_size=args.population,
                                      elite_count=elite_count, child_count=args.population - elite_count - 1,
                                      immigrant_count=1, trials=args.trials, challenge_trials=args.challenge_trials,
                                      validation_trials=args.validation_trials,
                                      max_frames=args.max_frames)
    ppo = PPOConfig(args.rollout_frames, args.ppo_epochs, args.minibatch_size, args.learning_rate,
                    args.gamma, args.gae_lambda, args.clip_epsilon, .5, args.entropy_coefficient,
                    args.max_grad_norm)
    qd = QDConfig(args.qd_bins, min(3, args.population), args.minimum_quality)
    reward = RewardPolicy()
    fingerprint = experiment_fingerprint(simulation, ppo, qd, reward)
    estimated_training = args.generations * args.population * ppo.rollout_frames
    estimated_evaluation = args.generations * (args.population * (args.trials + args.challenge_trials)
                                                + min(qd.nominees, args.population) * args.validation_trials) * args.max_frames
    if estimated_training + estimated_evaluation > MAX_TOTAL_ENVIRONMENT_FRAMES:
        raise ValueError("experiment exceeds the governed one-billion-frame budget")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.experiment_id):
        raise ValueError("invalid experiment ID")
    base = args.artifact_root / args.experiment_id
    checkpoint = base / "evolution_state_v36.npz"; results_path = base / "generations_v36.jsonl"
    lock = base / "training_v36.lock"
    status_path = base / "status_v36.json"
    validate_artifact_paths(args.artifact_root, base, checkpoint, results_path, lock, status_path)
    base.mkdir(parents=True, exist_ok=True)
    approval, approval_digest = load_approval(args.approval_record, args.experiment_id, fingerprint, "train")
    token, _ = _acquire_lock(lock)
    print(f"preflight algorithm={ALGORITHM} experiment={args.experiment_id} generations={args.generations} "
          f"population={args.population} rollout_frames={ppo.rollout_frames} estimated_training_frames={estimated_training} estimated_evaluation_frames={estimated_evaluation} "
          f"qd_cells={qd.bins ** 2} fingerprint={fingerprint}", flush=True)
    try:
        if any(path != lock for path in base.iterdir()):
            raise ValueError("v36 experiment directory is not empty; choose a new experiment ID")
        archive = QDArchive(qd); candidates: list[Candidate] = []
        next_id = 1; previous_hash = "0" * 64
        for index in range(args.population):
            policy = Policy.random(simulation, np.random.default_rng(stable_seed(args.seed, "founder", index)), ppo.initial_action_std)
            candidates.append(Candidate(next_id, policy, Adam.zeros(policy))); next_id += 1
        return _execute_generations(base=base, checkpoint=checkpoint, results_path=results_path, status_path=status_path,
            candidates=candidates, archive=archive, validation_hof=None, hof_fitness=-1.0, hof_source_generation=None,
            start_generation=0, count=args.generations, next_id=next_id, previous_hash=previous_hash,
            master_seed=args.seed, simulation=simulation, ppo=ppo, qd=qd, reward=reward,
            lineage_fingerprint=fingerprint, approval_digest=approval_digest)
    finally:
        _release_lock(lock, token)


def checkpoint_status(checkpoint: Path, results: Path | None = None) -> dict[str, object]:
    metadata, candidates, archive, hof = load_checkpoint(checkpoint)
    results_path = results or checkpoint.with_name("generations_v36.jsonl")
    reconciliation = reconcile_results(results_path, metadata, repair=False)
    hof_summary = dict(metadata.get("validation_hof") or metadata["record"]["validation_hof"])
    if hof_summary.get("source_generation") is None and hof is not None:
        hof_summary["source_generation"] = _hof_source_generation(results_path, hof.policy.policy_hash)
    audit_path = checkpoint.with_name("terminal_audit_v36.json"); audit_state = "NOT_RUN"; release_gate = "NOT_EVALUATED"
    if audit_path.is_file():
        audit = json.loads(audit_path.read_text(encoding="utf-8")); unsigned = dict(audit); supplied = unsigned.pop("record_hash", "")
        pairs = list(audit.get("pairs", []))
        bound_source = dict(audit.get("source_checkpoint", {})).get("sha256") == file_evidence(checkpoint)["sha256"]
        audit_state = "AUDIT_COMMITTED" if (sha256_json(unsigned) == supplied and audit.get("schema_version") == AUDIT_SCHEMA and
            bool(audit.get("approval_digest")) and bound_source and pairs and
            all(f"{label}_early_extinction" in pair for pair in pairs for label in ("v36", "v35"))) else "INVALID"
        if audit_state == "AUDIT_COMMITTED":
            release_gate = "PASS" if (audit["v36"]["median"] >= audit["v35"]["median"] and audit["v36"]["minimum"] >= audit["v35"]["minimum"] and audit["v36"]["early_extinction_rate"] <= audit["v35"]["early_extinction_rate"]) else "FAIL"
    return {"checkpoint": str(checkpoint.resolve()), "workflow_state": metadata["workflow_state"],
            "last_committed_generation": int(metadata["generation"]), "completed_generations": int(metadata["generation"]) + 1,
            "population": len(candidates), "next_candidate_id": int(metadata["next_candidate_id"]),
            "archive_occupied": len(archive.entries), "archive_capacity": archive.config.bins ** 2,
            "archive_coverage": archive.coverage, "qd_score": archive.qd_score,
            "validation_hof": hof_summary, "lineage_fingerprint": metadata["fingerprint"],
            "master_seed": int(metadata["master_seed"]), "results_reconciliation": reconciliation,
            "audit_state": audit_state, "release_gate": release_gate,
            "release_manifest": checkpoint.with_name("manifest_v36.json").is_file()}


def continue_experiment(args: argparse.Namespace) -> int:
    metadata, candidates, archive, hof = load_checkpoint(args.resume)
    base = args.artifact_root / args.experiment_id; expected = base / "evolution_state_v36.npz"
    if args.resume.resolve() != expected.resolve(): raise ValueError(f"resume must be governed checkpoint {expected}")
    if metadata.get("workflow_state") == "RELEASED" or (base / "manifest_v36.json").exists(): raise ValueError("released experiment cannot continue")
    if int(metadata["master_seed"]) != args.seed: raise ValueError("resume master seed mismatch")
    approval, approval_digest = load_approval(args.approval_record, args.experiment_id, str(metadata["fingerprint"]), "continue")
    results = base / "generations_v36.jsonl"; lock = base / "training_v36.lock"; token, _ = _acquire_lock(lock)
    try:
        locked_metadata, candidates, archive, hof = load_checkpoint(args.resume)
        if locked_metadata.get("workflow_state") == "RELEASED" or (base / "manifest_v36.json").exists(): raise ValueError("released experiment cannot continue")
        if int(locked_metadata["generation"]) != int(metadata["generation"]): raise ValueError("checkpoint changed before continuation lock")
        metadata = locked_metadata
        reconciliation = reconcile_results(results, metadata, repair=True)
        simulation = v35.SimulationConfig(**dict(metadata["simulation"])); ppo = PPOConfig(**dict(metadata["ppo"]))
        qd = QDConfig(**dict(metadata["qd"])); reward = RewardPolicy(**dict(metadata["reward"]))
        estimated = args.additional_generations * (len(candidates) * ppo.rollout_frames +
                    (len(candidates) * (simulation.trials + simulation.challenge_trials) + qd.nominees * simulation.validation_trials) * simulation.max_frames)
        committed = 0
        for line in results.read_text(encoding="utf-8").splitlines():
            record = json.loads(line); committed += int(record.get("training_environment_frames", 0))
            committed += sum(int(trial["frames"]) for candidate in record.get("candidates", []) for trial in candidate.get("trials", []))
            committed += sum(int(trial["frames"]) for trial in dict(record.get("validation_nominee", {})).get("trials", []))
        if committed + estimated > MAX_TOTAL_ENVIRONMENT_FRAMES: raise ValueError("continuation exceeds governed cumulative one-billion-frame budget")
        prior_audit = base / "terminal_audit_v36.json"
        if prior_audit.exists():
            retained = base / f"terminal_audit_v36.g{metadata['generation']}.json"
            if retained.exists(): raise ValueError("prior terminal audit retention target already exists")
            os.replace(prior_audit, retained)
        hof_summary = metadata.get("validation_hof") or metadata["record"]["validation_hof"]
        hof_fitness = float(hof_summary["fitness"]); source = hof_summary.get("source_generation")
        if source is None and hof is not None: source = _hof_source_generation(results, hof.policy.policy_hash)
        print(f"preflight continue experiment={args.experiment_id} from_generation={int(metadata['generation']) + 1} "
              f"additional={args.additional_generations} archive_occupied={len(archive.entries)} recovery={reconciliation['state']}", flush=True)
        return _execute_generations(base=base, checkpoint=expected, results_path=results,
            status_path=base / "status_v36.json", candidates=candidates, archive=archive, validation_hof=hof,
            hof_fitness=hof_fitness, hof_source_generation=None if source is None else int(source),
            start_generation=int(metadata["generation"]) + 1, count=args.additional_generations,
            next_id=int(metadata["next_candidate_id"]), previous_hash=str(metadata["record"]["record_hash"]),
            master_seed=args.seed, simulation=simulation, ppo=ppo, qd=qd, reward=reward,
            lineage_fingerprint=str(metadata["fingerprint"]), approval_digest=approval_digest)
    finally: _release_lock(lock, token)


def export_policy(path: Path, policy: Policy, metadata: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists(): raise ValueError(f"export already exists: {path}")
    write = {f"p{i}": array for i, array in enumerate(policy.arrays())}
    with path.open("xb") as handle:
        np.savez_compressed(handle, metadata=np.frombuffer(canonical_json(metadata).encode(), dtype=np.uint8), **write)


def set_checkpoint_workflow(path: Path, workflow_state: str, audit_record_hash: str) -> None:
    load_checkpoint(path); temp = None
    with np.load(path, allow_pickle=False) as data:
        arrays = {name: np.array(data[name], copy=True) for name in data.files if name != "metadata"}
        metadata = json.loads(bytes(np.asarray(data["metadata"], dtype=np.uint8)).decode("utf-8"))
    metadata["workflow_state"] = workflow_state; metadata["audit_record_hash"] = audit_record_hash
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
            temp = Path(handle.name); np.savez_compressed(handle, metadata=np.frombuffer(canonical_json(metadata).encode(), dtype=np.uint8), **arrays)
            handle.flush(); os.fsync(handle.fileno())
        load_checkpoint(temp); os.replace(temp, path)
    finally:
        if temp and temp.exists(): temp.unlink()


def export_hof(args: argparse.Namespace) -> int:
    metadata, _, _, hof = load_checkpoint(args.checkpoint)
    if hof is None: raise ValueError("checkpoint has no Hall of Fame")
    summary = metadata.get("validation_hof") or metadata["record"]["validation_hof"]
    export_policy(args.output, hof.policy, {"schema_version": "v36.policy.v1", "kind": "validation_hof",
        "source_checkpoint": file_evidence(args.checkpoint), "source_generation": summary.get("source_generation"),
        "candidate_id": hof.candidate_id, "policy_hash": hof.policy.policy_hash, "fitness": summary["fitness"],
        "simulation": metadata["simulation"], "lineage_fingerprint": metadata["fingerprint"]})
    print(canonical_json(file_evidence(args.output))); return 0


def export_archive(args: argparse.Namespace) -> int:
    metadata, _, archive, _ = load_checkpoint(args.checkpoint)
    args.output.mkdir(parents=True, exist_ok=False); entries = []
    for cell in sorted(archive.entries):
        entry = archive.entries[cell]; target = args.output / f"elite_{cell[0]}_{cell[1]}.npz"
        export_policy(target, archive.policies[cell], {"schema_version": "v36.policy.v1", "kind": "archive_elite", **asdict(entry)})
        entries.append({**asdict(entry), "file": target.name, "file_sha256": file_evidence(target)["sha256"]})
    manifest = {"schema_version": "v36.archive-export.v1", "source_checkpoint": file_evidence(args.checkpoint),
                "generation": metadata["generation"], "lineage_fingerprint": metadata["fingerprint"],
                "descriptor_labels": ["median_exploration", "median_reproduction"], "bins": archive.config.bins,
                "edges": archive.config.edges, "entries": entries}
    write_json_atomic(args.output / "archive_manifest_v36.json", manifest); print(canonical_json(manifest)); return 0


def visualize_archive(args: argparse.Namespace) -> int:
    metadata, _, archive, _ = load_checkpoint(args.checkpoint); size = 110; margin = 90; bins = archive.config.bins
    width = margin * 2 + bins * size; height = margin * 2 + bins * size
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
             f'<title id="title">Blast Pit v36 quality diversity archive generation {metadata["generation"]}</title>',
             '<desc id="desc">Grid of median exploration by median reproduction. Each occupied cell includes candidate ID and quality; empty cells are labeled.</desc>',
             '<style>text{font-family:Segoe UI,Arial;font-size:13px}.empty{fill:#eee;stroke:#777}.elite{stroke:#222}</style>',
             f'<text x="{width/2}" y="25" text-anchor="middle">v36 archive generation {metadata["generation"]}</text>',
             f'<text x="{width/2}" y="{height-15}" text-anchor="middle">Median exploration</text>',
             f'<text transform="translate(20 {height/2}) rotate(-90)" text-anchor="middle">Median reproduction</text>']
    for index, edge in enumerate(archive.config.edges):
        x = margin + index * size; y = margin + (bins-index) * size
        parts.append(f'<text x="{x}" y="{height-margin+20}" text-anchor="middle">{edge:.1f}</text>')
        parts.append(f'<text x="{margin-12}" y="{y+4}" text-anchor="end">{edge:.1f}</text>')
    for x in range(bins):
        for y in range(bins):
            px = margin + x * size; py = margin + (bins - 1 - y) * size; entry = archive.entries.get((x, y))
            if entry is None:
                parts.append(f'<rect class="empty" x="{px}" y="{py}" width="{size}" height="{size}"/><text x="{px+size/2}" y="{py+size/2}" text-anchor="middle">empty</text>')
            else:
                shade = max(0, min(255, int(255 * entry.quality)))
                parts.append(f'<rect class="elite" x="{px}" y="{py}" width="{size}" height="{size}" fill="rgb({255-shade},{120+shade//2},210)"/><text x="{px+5}" y="{py+22}">cell {x},{y}</text><text x="{px+5}" y="{py+42}">id {entry.candidate_id}</text><text x="{px+5}" y="{py+62}">q {entry.quality:.4f}</text>')
    parts.append('</svg>'); args.output.write_text("".join(parts), encoding="utf-8"); print(str(args.output.resolve())); return 0


def _audit_policy(policy: Policy, config: v35_types.SimulationConfig, seeds: Sequence[int], profiles: Sequence[str]) -> list[v35_types.TrialSummary]:
    return evaluate(policy, config, 0, seeds, profiles)


def _environment_contract(config: v35_types.SimulationConfig) -> dict[str, object]:
    value = asdict(config)
    for name in ("generations", "population_size", "elite_count", "child_count", "immigrant_count",
                 "trials", "challenge_trials", "validation_trials", "audit_trials", "stagnation_window",
                 "mutation_probability", "mutation_strength", "mutation_strength_min", "mutation_strength_max"):
        value.pop(name, None)
    return value


def audit_compare(args: argparse.Namespace) -> int:
    metadata, _, _, hof = load_checkpoint(args.checkpoint)
    if hof is None: raise ValueError("v36 Hall of Fame is missing")
    _, approval_digest = load_approval(args.approval_record, args.experiment_id, str(metadata["fingerprint"]), "audit")
    output = args.checkpoint.with_name("terminal_audit_v36.json"); source_evidence = file_evidence(args.checkpoint)
    if output.exists():
        existing = json.loads(output.read_text(encoding="utf-8")); unsigned = dict(existing); supplied = unsigned.pop("record_hash", "")
        expected_seeds = [stable_seed(args.audit_seed, "unseen_terminal_comparison", index) for index in range(args.audit_trials)]
        existing_pairs = list(existing.get("pairs", []))
        if (sha256_json(unsigned) != supplied or existing.get("schema_version") != AUDIT_SCHEMA or
            existing.get("experiment_id") != args.experiment_id or
            dict(existing.get("source_checkpoint", {})).get("sha256") != source_evidence["sha256"] or
            existing.get("v36_policy_hash") != hof.policy.policy_hash or existing.get("approval_digest") != approval_digest or
            existing.get("audit_seed") != args.audit_seed or len(existing_pairs) != args.audit_trials or
            [int(pair["seed"]) for pair in existing_pairs] != expected_seeds or
            dict(existing.get("v35_checkpoint", {})).get("sha256") != file_evidence(args.v35_checkpoint)["sha256"]):
            raise ValueError("existing terminal audit identity or hash is invalid")
        print(canonical_json(existing)); return 0
    v35_metadata = v35._raw_checkpoint_metadata(args.v35_checkpoint)
    v35_config = v35.SimulationConfig(**v35_metadata["config"]); v36_config = v35.SimulationConfig(**dict(metadata["simulation"]))
    if _environment_contract(v35_config) != _environment_contract(v36_config): raise ValueError("v35/v36 environment behavior contracts differ")
    v35_brain = v35.CheckpointRepository.load(args.v35_checkpoint, v35_config)[0]
    v35_policy = Policy(v35_brain, np.zeros((v35_config.hidden1, len(v35.SENSOR_LABELS))), np.zeros(v35_config.hidden1),
                        np.zeros((1, v35_config.hidden1)), np.zeros(1), np.zeros(2))
    seeds = [stable_seed(args.audit_seed, "unseen_terminal_comparison", index) for index in range(args.audit_trials)]
    profiles = ["standard" if index % 3 else "water_fire_challenge" for index in range(args.audit_trials)]
    v36_trials = _audit_policy(hof.policy, v36_config, seeds, profiles); v35_trials = _audit_policy(v35_policy, v35_config, seeds, profiles)
    def summary(trials):
        scores = [trial.fitness for trial in trials]
        return {"median": median(scores), "minimum": min(scores), "mean": sum(scores)/len(scores),
                "early_extinction_rate": sum(bool(t.metrics["early_extinction"]) for t in trials)/len(trials)}
    pairs = [{"seed": seed, "profile": profile, "v36_fitness": a.fitness, "v35_fitness": b.fitness,
              "v36_early_extinction": bool(a.metrics["early_extinction"]),
              "v35_early_extinction": bool(b.metrics["early_extinction"]),
              "delta": a.fitness-b.fitness} for seed, profile, a, b in zip(seeds, profiles, v36_trials, v35_trials)]
    record = {"schema_version": AUDIT_SCHEMA, "experiment_id": args.experiment_id, "audit_seed": args.audit_seed,
              "seed_suite_hash": sha256_json(seeds), "source_checkpoint": source_evidence,
              "v35_checkpoint": file_evidence(args.v35_checkpoint), "v36_policy_hash": hof.policy.policy_hash,
              "v35_actor_hash": v35_brain.genome_hash, "v36": summary(v36_trials), "v35": summary(v35_trials), "pairs": pairs,
              "approval_digest": approval_digest, "created_utc": datetime.now(timezone.utc).isoformat(), "workflow_state": "AUDIT_COMMITTED"}
    record["record_hash"] = sha256_json(record); write_json_atomic(output, record)
    print(canonical_json(record)); return 0


def _release_experiment_locked(args: argparse.Namespace) -> int:
    metadata, _, _, hof = load_checkpoint(args.checkpoint)
    _, approval_digest = load_approval(args.approval_record, args.experiment_id, str(metadata["fingerprint"]), "release")
    intent_path = args.checkpoint.with_name("release_intent_v36.json"); released = metadata.get("workflow_state") == "RELEASED"
    intent = None
    if intent_path.exists():
        intent = json.loads(intent_path.read_text(encoding="utf-8")); unsigned_intent = dict(intent); intent_hash = unsigned_intent.pop("record_hash", "")
        if sha256_json(unsigned_intent) != intent_hash: raise ValueError("release intent hash is invalid")
    audit = args.checkpoint.with_name("terminal_audit_v36.json")
    if not audit.is_file(): raise ValueError("release requires terminal audit evidence")
    audit_record = json.loads(audit.read_text(encoding="utf-8"))
    unsigned = dict(audit_record); supplied_hash = unsigned.pop("record_hash", "")
    if (audit_record.get("workflow_state") != "AUDIT_COMMITTED" or audit_record.get("schema_version") != AUDIT_SCHEMA or
        sha256_json(unsigned) != supplied_hash or audit_record.get("experiment_id") != args.experiment_id or
        audit_record.get("approval_digest") != approval_digest or
        dict(audit_record.get("source_checkpoint", {})).get("sha256") != (intent.get("pre_release_checkpoint_sha256") if released and intent else file_evidence(args.checkpoint)["sha256"]) or
        hof is None or audit_record.get("v36_policy_hash") != hof.policy.policy_hash):
        raise ValueError("terminal audit hash or identity binding is invalid")
    pairs = list(audit_record.get("pairs", [])); seeds = [int(pair["seed"]) for pair in pairs]
    if not pairs or sha256_json(seeds) != audit_record.get("seed_suite_hash"): raise ValueError("terminal audit seed suite is invalid")
    for label in ("v36", "v35"):
        scores = [float(pair[f"{label}_fitness"]) for pair in pairs]
        computed = {"median": median(scores), "minimum": min(scores), "mean": sum(scores)/len(scores),
                    "early_extinction_rate": sum(bool(pair[f"{label}_early_extinction"]) for pair in pairs)/len(pairs)}
        if any(not math.isclose(float(audit_record[label][name]), value, rel_tol=0, abs_tol=1e-15) for name, value in computed.items()):
            raise ValueError("terminal audit aggregates are invalid")
    v35_evidence = dict(audit_record["v35_checkpoint"]); v35_path = Path(str(v35_evidence["path"]))
    if not v35_path.is_file() or file_evidence(v35_path)["sha256"] != v35_evidence["sha256"]: raise ValueError("v35 audit evidence is unavailable or changed")
    passed = (float(audit_record["v36"]["median"]) >= float(audit_record["v35"]["median"]) and
              float(audit_record["v36"]["minimum"]) >= float(audit_record["v35"]["minimum"]) and
              float(audit_record["v36"]["early_extinction_rate"]) <= float(audit_record["v35"]["early_extinction_rate"]))
    if not passed:
        raise ValueError("release gate failed: v36 did not meet v35 median, minimum, and early-extinction baselines")
    if not released:
        intent = {"schema_version": "v36.release-intent.v1", "experiment_id": args.experiment_id,
                  "pre_release_checkpoint_sha256": file_evidence(args.checkpoint)["sha256"],
                  "audit_record_hash": audit_record["record_hash"], "approval_digest": approval_digest}
        intent["record_hash"] = sha256_json(intent); write_json_atomic(intent_path, intent)
        set_checkpoint_workflow(args.checkpoint, "RELEASED", str(audit_record["record_hash"])); metadata = load_checkpoint(args.checkpoint)[0]
    elif not intent or intent.get("audit_record_hash") != audit_record["record_hash"] or intent.get("approval_digest") != approval_digest:
        raise ValueError("released checkpoint is missing valid release intent")
    root = Path(__file__).parent; files = [args.checkpoint, args.checkpoint.with_name("generations_v36.jsonl"), audit, intent_path,
        root/"tmp_2d_simulator_v36.py", root/"test_tmp_2d_simulator_v36.py", root/"README_v36.md", root/"IMPLEMENTATION_REVIEW_v36.md"]
    manifest = {"schema_version": "v36.release.v1", "experiment_id": args.experiment_id, "workflow_state": "RELEASED",
                "generation": metadata["generation"], "lineage_fingerprint": metadata["fingerprint"],
                "approval_digest": approval_digest, "audit_record_hash": audit_record["record_hash"],
                "files": [file_evidence(path) for path in files], "created_utc": datetime.now(timezone.utc).isoformat()}
    manifest["manifest_hash"] = sha256_json(manifest); write_json_atomic(args.checkpoint.with_name("manifest_v36.json"), manifest)
    status = checkpoint_status(args.checkpoint); status["workflow_state"] = "RELEASED"; status["manifest_hash"] = manifest["manifest_hash"]
    write_json_atomic(args.checkpoint.with_name("status_v36.json"), status); print(canonical_json(manifest)); return 0


def release_experiment(args: argparse.Namespace) -> int:
    lock = args.checkpoint.with_name("training_v36.lock"); token, _ = _acquire_lock(lock)
    try: return _release_experiment_locked(args)
    finally: _release_lock(lock, token)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Blast_Pit v36 governed quality-diversity PPO")
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train"); train.add_argument("--experiment-id", required=True)
    train.add_argument("--artifact-root", type=Path, default=Path("artifacts/v36"))
    train.add_argument("--approval-record", type=Path, default=Path("approval_v36.json"))
    for target in (train,):
        target.add_argument("--generations", type=int, default=3); target.add_argument("--population", type=int, default=8)
        target.add_argument("--trials", type=int, default=3); target.add_argument("--challenge-trials", type=int, default=1)
        target.add_argument("--validation-trials", type=int, default=3); target.add_argument("--max-frames", type=int, default=1000)
        target.add_argument("--rollout-frames", type=int, default=512); target.add_argument("--ppo-epochs", type=int, default=4)
        target.add_argument("--minibatch-size", type=int, default=256); target.add_argument("--learning-rate", type=float, default=3e-4)
        target.add_argument("--gamma", type=float, default=.99); target.add_argument("--gae-lambda", type=float, default=.95)
        target.add_argument("--clip-epsilon", type=float, default=.2); target.add_argument("--entropy-coefficient", type=float, default=.01)
        target.add_argument("--max-grad-norm", type=float, default=.5); target.add_argument("--qd-bins", type=int, default=5)
        target.add_argument("--minimum-quality", type=float, default=.05); target.add_argument("--seed", type=int, default=20260711)
    cont = sub.add_parser("continue"); cont.add_argument("--experiment-id", required=True); cont.add_argument("--resume", type=Path, required=True)
    cont.add_argument("--additional-generations", type=int, required=True); cont.add_argument("--seed", type=int, default=20260711)
    cont.add_argument("--artifact-root", type=Path, default=Path("artifacts/v36")); cont.add_argument("--approval-record", type=Path, default=Path("approval_v36.json"))
    for name in ("status", "inspect"):
        command = sub.add_parser(name); command.add_argument("--checkpoint", type=Path, required=True)
    hof = sub.add_parser("export-hof"); hof.add_argument("--checkpoint", type=Path, required=True); hof.add_argument("--output", type=Path, required=True)
    archive = sub.add_parser("export-archive"); archive.add_argument("--checkpoint", type=Path, required=True); archive.add_argument("--output", type=Path, required=True)
    visual = sub.add_parser("visualize-archive"); visual.add_argument("--checkpoint", type=Path, required=True); visual.add_argument("--output", type=Path, required=True)
    audit = sub.add_parser("audit"); audit.add_argument("--experiment-id", required=True); audit.add_argument("--checkpoint", type=Path, required=True)
    audit.add_argument("--v35-checkpoint", type=Path, required=True); audit.add_argument("--audit-seed", type=int, default=20260711)
    audit.add_argument("--audit-trials", type=int, default=11); audit.add_argument("--approval-record", type=Path, default=Path("approval_v36.json"))
    release = sub.add_parser("release"); release.add_argument("--experiment-id", required=True); release.add_argument("--checkpoint", type=Path, required=True)
    release.add_argument("--approval-record", type=Path, default=Path("approval_v36.json"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "train":
            if not 2 <= args.population <= 32 or not 1 <= args.generations <= 10000 or not 16 <= args.max_frames <= 1_000_000: raise ValueError("training limits invalid")
            return run_experiment(args)
        if args.command == "continue":
            if not 1 <= args.additional_generations <= 10000: raise ValueError("additional-generations outside governed limits")
            return continue_experiment(args)
        if args.command == "status": print(canonical_json(checkpoint_status(args.checkpoint))); return 0
        if args.command == "inspect": print(canonical_json(load_checkpoint(args.checkpoint)[0])); return 0
        if args.command == "export-hof": return export_hof(args)
        if args.command == "export-archive": return export_archive(args)
        if args.command == "visualize-archive": return visualize_archive(args)
        if args.command == "audit": return audit_compare(args)
        if args.command == "release": return release_experiment(args)
        raise ValueError("unsupported command")
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr, flush=True); return 3


if __name__ == "__main__":
    raise SystemExit(main())
