from __future__ import annotations

"""Blast_Pit v37 robustness-focused QD-PPO experiment."""

import argparse
import hashlib
import json
import math
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Sequence

import numpy as np

import tmp_2d_simulator_v36 as v36

v35 = v36.v35
APP_VERSION = "v37"
SCHEMA_VERSION = "v37.0"
ALGORITHM = "robust-qd-cvar-ppo-numpy"
CRITIC_CONTEXT_LABELS = ("hydration_mean", "low_water_fraction", "near_fire_fraction", "population_ratio", "recovery_opportunity_rate")
CRITIC_SCHEMA = "local-19-plus-lineage-5-v1"
MAX_FRAMES_BUDGET = 1_000_000_000


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def file_evidence(path: Path) -> dict[str, object]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest}


def canonical_source_sha256(path: Path) -> str:
    """Hash text source independent of Git/Windows line-ending conversion."""
    data=path.read_bytes().replace(b"\r\n",b"\n").replace(b"\r",b"\n")
    return hashlib.sha256(data).hexdigest()


def stable_seed(master: int, *parts: object) -> int:
    return v35.stable_seed(master, APP_VERSION, *parts)


@dataclass(frozen=True)
class RobustnessConfig:
    standard_rollouts: int = 1
    challenge_rollouts: int = 3
    challenge_reward_multiplier: float = 2.0
    challenge_selection_weight: float = 0.60
    early_extinction_penalty: float = 0.75
    cvar_alpha: float = 0.25
    cvar_weight: float = 0.60
    specialist_parent_fraction: float = 0.50
    audit_trials: int = 64

    def __post_init__(self) -> None:
        if not 1 <= self.standard_rollouts <= 16 or not 2 <= self.challenge_rollouts <= 32:
            raise ValueError("v37 requires at least two challenge rollouts")
        if not 1 <= self.challenge_reward_multiplier <= 10 or not 0.5 <= self.challenge_selection_weight <= .9:
            raise ValueError("invalid challenge weighting")
        if not 0 < self.early_extinction_penalty <= 5 or not 0 < self.cvar_alpha <= .5 or not 0 <= self.cvar_weight <= 1:
            raise ValueError("invalid extinction/CVaR policy")
        if not .25 <= self.specialist_parent_fraction <= .75 or not 32 <= self.audit_trials <= 512:
            raise ValueError("invalid specialist fraction or audit size")


@dataclass
class RobustPolicy:
    brain: object
    critic_W1: np.ndarray
    critic_b1: np.ndarray
    critic_W2: np.ndarray
    critic_b2: np.ndarray
    log_std: np.ndarray

    @classmethod
    def migrate(cls, source: v36.Policy, simulation) -> "RobustPolicy":
        width = len(v35.SENSOR_LABELS) + len(CRITIC_CONTEXT_LABELS)
        critic = np.zeros((simulation.hidden1, width), dtype=np.float64)
        critic[:, :len(v35.SENSOR_LABELS)] = source.critic_W1
        return cls(source.brain.copy(), critic, source.critic_b1.copy(), source.critic_W2.copy(),
                   source.critic_b2.copy(), source.log_std.copy())

    def copy(self) -> "RobustPolicy":
        return RobustPolicy(self.brain.copy(), self.critic_W1.copy(), self.critic_b1.copy(),
                            self.critic_W2.copy(), self.critic_b2.copy(), self.log_std.copy())

    def arrays(self) -> tuple[np.ndarray, ...]:
        return (*self.brain.arrays(), self.critic_W1, self.critic_b1, self.critic_W2, self.critic_b2, self.log_std)

    @property
    def policy_hash(self) -> str:
        digest = hashlib.sha256(b"robust-policy-v37")
        for array in self.arrays(): digest.update(np.ascontiguousarray(array, dtype="<f8").tobytes())
        return digest.hexdigest()

    def actor(self, obs: np.ndarray):
        h1 = np.tanh(obs @ self.brain.W1.T + self.brain.b1); h2 = np.tanh(h1 @ self.brain.W2.T + self.brain.b2)
        location = h2 @ self.brain.W3.T + self.brain.b3
        return np.tanh(location), (obs, h1, h2, location)

    def value(self, critic_obs: np.ndarray):
        h = np.tanh(critic_obs @ self.critic_W1.T + self.critic_b1)
        return (h @ self.critic_W2.T + self.critic_b2).reshape(-1), (critic_obs, h)


@dataclass
class RobustAdam(v36.Adam):
    @classmethod
    def zeros(cls, policy: RobustPolicy):
        return cls([np.zeros_like(x) for x in policy.arrays()], [np.zeros_like(x) for x in policy.arrays()])


@dataclass(frozen=True)
class RobustTransition:
    observation: np.ndarray
    critic_observation: np.ndarray
    action: np.ndarray
    old_log_probability: float
    value: float
    reward: float
    done: bool
    episode_id: int
    profile: str
    creature_id: int


def lineage_context(simulation) -> np.ndarray:
    living = [creature for creature in simulation.creatures if creature.alive]
    if not living: return np.zeros(len(CRITIC_CONTEXT_LABELS), dtype=np.float64)
    hydration = float(np.mean([1.0 - min(creature.thirst, 1.0) for creature in living]))
    low_water = float(np.mean([creature.thirst >= .75 for creature in living]))
    near_fire = float(np.mean([any(True for _ in simulation.resource_indexes["fire"].query(creature.x, creature.y, simulation.config.fire_sense_range)) for creature in living]))
    population = min(len(living) / simulation.config.lineage_cap, 1.0)
    opportunities = min(simulation.metrics.water_recovery_opportunities / max(1, simulation.frame + 1), 1.0)
    return np.asarray([hydration, low_water, near_fire, population, opportunities], dtype=np.float64)


class RobustSamplingBrain(v35.Brain):
    def __init__(self, policy: RobustPolicy, rng: np.random.Generator):
        super().__init__(*(array for array in policy.brain.arrays())); self.policy = policy; self.rng = rng
        self.context_provider = lambda: np.zeros(5); self.pending = []

    def forward(self, inputs: np.ndarray) -> np.ndarray:
        obs = np.asarray(inputs, dtype=np.float64)[None, :]; critic_obs = np.concatenate((obs[0], self.context_provider()))[None, :]
        _, cache = self.policy.actor(obs); location = cache[3]; value, _ = self.policy.value(critic_obs)
        action = np.tanh(location[0] + np.exp(self.policy.log_std) * self.rng.normal(size=2))
        logp = float(v36.squashed_gaussian_log_probability(action[None, :], location, self.policy.log_std)[0])
        self.pending.append((obs[0].copy(), critic_obs[0].copy(), action.copy(), logp, float(value[0]))); return action


class RobustRollout(v35.Simulation):
    def __init__(self, config, policy: RobustPolicy, seed: int, action_seed: int, profile: str,
                 reward: v36.RewardPolicy, robustness: RobustnessConfig, episode_id: int):
        self.sampling_brain = RobustSamplingBrain(policy, np.random.default_rng(action_seed)); self.reward_policy = reward
        self.robustness = robustness; self.episode_id = episode_id; self.trajectories: dict[int,list[RobustTransition]] = {}
        super().__init__(config, self.sampling_brain, seed, profile=profile, execution=v35.ExecutionConfig(1, "python", "scalar"))
        self.sampling_brain.context_provider = lambda: lineage_context(self)

    def _act(self, creature, inputs, outputs) -> None:
        before = (self.metrics.lineage_food, self.metrics.lineage_water, self.metrics.water_recoveries,
                  self.metrics.fire_contact_frames, self.metrics.lineage_energy_spent)
        obs, critic_obs, action, logp, value = self.sampling_brain.pending.pop(0); super()._act(creature, inputs, outputs)
        after = (self.metrics.lineage_food, self.metrics.lineage_water, self.metrics.water_recoveries,
                 self.metrics.fire_contact_frames, self.metrics.lineage_energy_spent)
        multiplier = self.robustness.challenge_reward_multiplier if self.profile == "water_fire_challenge" else 1.0
        reward = (self.reward_policy.survival + self.reward_policy.food*(after[0]-before[0]) +
                  multiplier*self.reward_policy.water*(after[1]-before[1]) +
                  multiplier*self.reward_policy.recovery*(after[2]-before[2]) +
                  multiplier*self.reward_policy.fire_contact*(after[3]-before[3]) +
                  self.reward_policy.energy*(after[4]-before[4]) + (self.reward_policy.death if not creature.alive else 0.0))
        self.trajectories.setdefault(creature.creature_id,[]).append(RobustTransition(obs, critic_obs, action, logp, value,
            float(np.clip(reward, -self.reward_policy.clip, self.reward_policy.clip)), not creature.alive, self.episode_id, self.profile, creature.creature_id))

    def finish(self) -> list[list[RobustTransition]]:
        result=[]
        for creature_id in sorted(self.trajectories):
            trajectory=self.trajectories[creature_id]
            if trajectory:
                last=trajectory[-1]; penalty=self.robustness.early_extinction_penalty if self.metrics.early_extinction else 0.0
                trajectory[-1]=RobustTransition(last.observation,last.critic_observation,last.action,last.old_log_probability,
                    last.value,last.reward-penalty,True,last.episode_id,last.profile,last.creature_id)
                result.append(trajectory)
        return result


def cvar_weights(episode_returns: Sequence[float], alpha: float, tail_weight: float) -> tuple[np.ndarray, float, tuple[int, ...]]:
    values = np.asarray(episode_returns, dtype=np.float64)
    if not len(values) or not np.isfinite(values).all(): raise ValueError("invalid episode returns")
    count = max(1, math.ceil(alpha * len(values))); order = np.argsort(values, kind="stable"); tail = tuple(int(x) for x in order[:count])
    weights = np.full(len(values), 1.0 - tail_weight); weights[list(tail)] += tail_weight / alpha
    return weights, float(np.mean(values[list(tail)])), tail


def robust_update(policy: RobustPolicy, optimizer: RobustAdam, trajectories: Sequence[Sequence[RobustTransition]],
                  config: v36.PPOConfig, robustness: RobustnessConfig, rng: np.random.Generator) -> dict[str, object]:
    episode_ids=sorted(set(item.episode_id for trajectory in trajectories for item in trajectory))
    returns_by_episode=[sum(item.reward for trajectory in trajectories for item in trajectory if item.episode_id==episode_id) for episode_id in episode_ids]
    episode_weights, cvar_return, tail = cvar_weights(returns_by_episode, robustness.cvar_alpha, robustness.cvar_weight)
    weight_by_episode={episode_id:episode_weights[index] for index,episode_id in enumerate(episode_ids)}; rows=[]
    for trajectory in trajectories:
        rewards=np.asarray([x.reward for x in trajectory]); values=np.asarray([x.value for x in trajectory]); dones=np.asarray([x.done for x in trajectory])
        advantages, targets = v36.generalized_advantage(rewards, values, dones, config.gamma, config.gae_lambda)
        rows.extend((item,float(adv)*weight_by_episode[item.episode_id],float(target)) for item,adv,target in zip(trajectory,advantages,targets))
    obs = np.stack([r[0].observation for r in rows]); critic_obs = np.stack([r[0].critic_observation for r in rows])
    actions = np.stack([r[0].action for r in rows]); old = np.asarray([r[0].old_log_probability for r in rows])
    advantages = np.asarray([r[1] for r in rows]); targets = np.asarray([r[2] for r in rows])
    advantages = (advantages-advantages.mean())/(advantages.std()+1e-8); updates = 0
    for _ in range(config.update_epochs):
        permutation=rng.permutation(len(rows))
        for start in range(0, len(rows), config.minibatch_size):
            idx = permutation[start:start+config.minibatch_size]
            if not len(idx): continue
            _, actor_cache = policy.actor(obs[idx]); location = actor_cache[3]
            logp = v36.squashed_gaussian_log_probability(actions[idx], location, policy.log_std); ratio = np.exp(np.clip(logp-old[idx], -20, 20))
            unclipped = ratio*advantages[idx]; clipped = np.clip(ratio, 1-config.clip_epsilon, 1+config.clip_epsilon)*advantages[idx]
            actor_grads = v36._actor_grad(policy, obs[idx], actions[idx], -np.where(unclipped <= clipped, ratio*advantages[idx], 0.0))
            value, (_, hidden) = policy.value(critic_obs[idx]); error = value-targets[idx]; dv=.5*error/len(idx)
            gCW2=dv[None,:]@hidden; gCb2=np.asarray([dv.sum()]); dz=dv[:,None]*policy.critic_W2*(1-hidden*hidden)
            gradients=[*actor_grads[:6],dz.T@critic_obs[idx],dz.sum(axis=0),gCW2,gCb2,actor_grads[6]-config.entropy_coefficient]
            optimizer.apply(policy.arrays(), gradients, config.learning_rate, config.max_grad_norm); updates += 1
    return {"mean_episode_return": float(np.mean(returns_by_episode)), "cvar_episode_return": cvar_return,
            "tail_episode_indices": tail, "episode_returns": returns_by_episode, "updates": updates}


@dataclass
class RobustCandidate:
    candidate_id: int
    policy: RobustPolicy
    optimizer: RobustAdam
    source_policy_hash: str
    source_kind: str
    trials: list[object] = field(default_factory=list)
    report: dict[str, object] = field(default_factory=dict)

    def robust_score(self, robustness: RobustnessConfig) -> float:
        standard=[t.fitness for t in self.trials if t.profile=="standard"]; challenge=[t.fitness for t in self.trials if t.profile=="water_fire_challenge"]
        def tail(values):
            count=max(1,math.ceil(robustness.cvar_alpha*len(values))); return float(np.mean(sorted(values)[:count]))
        early=sum(bool(t.metrics["early_extinction"]) for t in self.trials)/len(self.trials)
        mean=(1-robustness.challenge_selection_weight)*np.mean(standard)+robustness.challenge_selection_weight*np.mean(challenge)
        return float((1-robustness.cvar_weight)*mean+robustness.cvar_weight*tail(standard+challenge)-robustness.early_extinction_penalty*early)


def evaluate_brain(brain, config, seeds, profiles):
    return [v35.Simulation(config, brain, seed, 0, profile, v35.ExecutionConfig(1,"python","batch")).run() for seed,profile in zip(seeds,profiles)]


def bootstrap_candidates(source_checkpoint: Path, simulation, robustness: RobustnessConfig, population: int, seed: int):
    metadata, _, archive, hof = v36.load_checkpoint(source_checkpoint)
    if hof is None: raise ValueError("v36 source Hall of Fame missing")
    challenge_seeds=[stable_seed(seed,"specialist_selection",i) for i in range(6)]
    bank=[]
    for cell in sorted(archive.entries):
        policy=archive.policies[cell]; trials=evaluate_brain(policy.brain,simulation,challenge_seeds,["water_fire_challenge"]*len(challenge_seeds))
        scores=[t.fitness for t in trials]; bank.append((float(np.mean(sorted(scores)[:2])), -sum(bool(t.metrics["early_extinction"]) for t in trials), cell, policy))
    bank.sort(key=lambda row:(row[0],row[1],row[3].policy_hash), reverse=True)
    sources=[("protected_v36_hof",hof.policy)] + [(f"challenge_cell_{cell[0]}_{cell[1]}",p) for _,_,cell,p in bank]
    candidates=[]
    for index in range(population):
        kind,source=sources[index%max(1,math.ceil(len(sources)*robustness.specialist_parent_fraction))]
        policy=RobustPolicy.migrate(source,simulation); candidates.append(RobustCandidate(index+1,policy,RobustAdam.zeros(policy),source.policy_hash,kind))
    return metadata, candidates, bank, hof


def save_checkpoint(path: Path, metadata: dict[str, object], candidates: Sequence[RobustCandidate], hof: RobustCandidate) -> None:
    arrays={}
    for c in candidates:
        for i,a in enumerate(c.policy.arrays()): arrays[f"c{c.candidate_id}_p{i}"]=a
        for i,a in enumerate(c.optimizer.m): arrays[f"c{c.candidate_id}_m{i}"]=a
        for i,a in enumerate(c.optimizer.v): arrays[f"c{c.candidate_id}_v{i}"]=a
    for i,a in enumerate(hof.policy.arrays()): arrays[f"hof_p{i}"]=a
    full=dict(metadata); full["checkpoint_candidates"]=[{"candidate_id":c.candidate_id,"policy_hash":c.policy.policy_hash,"source_policy_hash":c.source_policy_hash,"source_kind":c.source_kind,"robust_score":c.report.get("robust_score"),"optimizer_step":c.optimizer.step} for c in candidates]
    temp=None; path.parent.mkdir(parents=True,exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix=path.name+".",suffix=".tmp",delete=False) as handle:
            temp=Path(handle.name); np.savez_compressed(handle,metadata=np.frombuffer(canonical_json(full).encode(),dtype=np.uint8),**arrays); handle.flush(); os.fsync(handle.fileno())
        with np.load(temp,allow_pickle=False) as data:
            if json.loads(bytes(data["metadata"]).decode())["record"]["record_hash"]!=metadata["record"]["record_hash"]: raise ValueError("checkpoint verification failed")
        os.replace(temp,path)
    finally:
        if temp and temp.exists(): temp.unlink()


def load_hof(path: Path):
    v36._preflight_checkpoint(path)
    with np.load(path,allow_pickle=False) as data:
        raw=np.asarray(data["metadata"])
        if raw.dtype!=np.uint8 or raw.ndim!=1 or raw.nbytes>4*1024*1024: raise ValueError("v37 checkpoint metadata invalid")
        metadata=json.loads(bytes(raw).decode()); simulation=v35.SimulationConfig(**metadata["simulation"])
        if metadata.get("schema_version")!=SCHEMA_VERSION or metadata.get("algorithm")!=ALGORITHM: raise ValueError("v37 checkpoint identity mismatch")
        record=dict(metadata["record"]); supplied=record.pop("record_hash")
        if sha256_json(record)!=supplied or int(metadata["generation"])!=int(record["generation"]): raise ValueError("v37 checkpoint record hash mismatch")
        expected={"metadata",*[f"hof_p{i}" for i in range(11)]}
        for descriptor in metadata["checkpoint_candidates"]:
            cid=int(descriptor["candidate_id"]); expected.update(f"c{cid}_{kind}{i}" for kind in ("p","m","v") for i in range(11))
        if set(data.files)!=expected: raise ValueError("v37 checkpoint members invalid")
        arrays=[np.array(data[f"hof_p{i}"],dtype=np.float64,copy=True) for i in range(11)]
        if any(a.dtype!=np.float64 or not np.isfinite(a).all() for a in arrays): raise ValueError("v37 HoF arrays invalid")
        policy=RobustPolicy(v35.Brain(*arrays[:6]),*arrays[6:])
        if policy.policy_hash!=metadata["hof"]["policy_hash"]: raise ValueError("v37 HoF policy hash mismatch")
        if policy.critic_W1.shape!=(simulation.hidden1,len(v35.SENSOR_LABELS)+len(CRITIC_CONTEXT_LABELS)): raise ValueError("v37 critic shape invalid")
    return metadata,policy,simulation


def load_training_checkpoint(path: Path):
    """Load the complete governed training state, including Adam moments."""
    metadata, hof_policy, simulation = load_hof(path)
    candidates=[]
    with np.load(path,allow_pickle=False) as data:
        for descriptor in metadata["checkpoint_candidates"]:
            cid=int(descriptor["candidate_id"])
            arrays=[np.array(data[f"c{cid}_p{i}"],dtype=np.float64,copy=True) for i in range(11)]
            moments=[np.array(data[f"c{cid}_m{i}"],dtype=np.float64,copy=True) for i in range(11)]
            variances=[np.array(data[f"c{cid}_v{i}"],dtype=np.float64,copy=True) for i in range(11)]
            if any(not np.isfinite(a).all() for a in (*arrays,*moments,*variances)):
                raise ValueError("v37 candidate or optimizer contains non-finite values")
            policy=RobustPolicy(v35.Brain(*arrays[:6]),*arrays[6:])
            if policy.policy_hash!=descriptor["policy_hash"]:
                raise ValueError("v37 candidate policy hash mismatch")
            optimizer=RobustAdam(moments,variances,int(descriptor.get("optimizer_step",0)))
            candidates.append(RobustCandidate(cid,policy,optimizer,descriptor["source_policy_hash"],descriptor["source_kind"]))
    hof=RobustCandidate(int(metadata["hof"]["candidate_id"]),hof_policy,RobustAdam.zeros(hof_policy),"resume","committed_hof")
    return metadata,candidates,hof,simulation


def write_json(path: Path,value: object):
    path.parent.mkdir(parents=True,exist_ok=True); temp=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix=path.name+".",suffix=".tmp",mode="w",encoding="utf-8",delete=False) as handle:
            temp=Path(handle.name); handle.write(canonical_json(value)+"\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp,path)
    finally:
        if temp and temp.exists(): temp.unlink()


def read_generation_journal(path: Path) -> list[dict[str,object]]:
    if not path.exists(): return []
    records=[]; previous="0"*64
    for number,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
        try: record=json.loads(line)
        except json.JSONDecodeError as error: raise ValueError(f"invalid v37 generation journal line {number}") from error
        supplied=record.get("record_hash"); unsigned=dict(record); unsigned.pop("record_hash",None)
        if supplied!=sha256_json(unsigned) or record.get("previous_record_hash")!=previous:
            raise ValueError(f"v37 generation journal hash-chain mismatch at line {number}")
        if int(record.get("generation",-1))!=number-1: raise ValueError("v37 generation journal sequence mismatch")
        previous=str(supplied); records.append(record)
    return records


def runtime_allows_generation(started: float,max_runtime_seconds: int,runtime_grace_seconds: int,last_generation_seconds: float|None) -> bool:
    if max_runtime_seconds<=0: return True
    remaining=max_runtime_seconds-(time.monotonic()-started)
    reserve=max(float(runtime_grace_seconds),(last_generation_seconds or 0.0)*1.20)
    return remaining>reserve


def experiment_fingerprint(source: Path, simulation, ppo, robustness, audit_seed_file: Path):
    return sha256_json({"app":APP_VERSION,"algorithm":ALGORITHM,"critic_schema":CRITIC_SCHEMA,"simulation":asdict(simulation),"ppo":asdict(ppo),"robustness":asdict(robustness),"v36_checkpoint":file_evidence(source)["sha256"],"audit_seed_commitment":file_evidence(audit_seed_file)["sha256"],"v37_source":canonical_source_sha256(Path(__file__))})


def load_approval(path: Path,experiment_id: str,fingerprint: str,action: str,*,source: Path|None=None,audit_seed_file: Path|None=None,
                  planned_generations: int|None=None,max_runtime_seconds: int|None=None):
    if not path.is_file() or path.is_symlink() or path.stat().st_size>64_000: raise ValueError("v37 approval file invalid")
    record=json.loads(path.read_text(encoding="utf-8"))
    actions=record.get("authorized_actions")
    if (record.get("schema_version")!="approval.v37.v1" or record.get("project")!="Blast_Pit" or record.get("version")!=APP_VERSION or record.get("status")!="approved" or
        record.get("authority")!="human-owner" or record.get("experiment_id")!=experiment_id or record.get("lineage_fingerprint")!=fingerprint or
        not isinstance(actions,list) or not all(isinstance(value,str) for value in actions) or action not in actions):
        raise ValueError("v37 approval scope mismatch")
    expected={
        "source_v36_checkpoint_sha256": file_evidence(source)["sha256"] if source else None,
        "audit_seed_commitment_sha256": file_evidence(audit_seed_file)["sha256"] if audit_seed_file else None,
        "v37_source_sha256": canonical_source_sha256(Path(__file__)),
        "approved_total_generations": planned_generations,
        "approved_max_runtime_seconds": max_runtime_seconds,
    }
    for key,value in expected.items():
        if value is not None and record.get(key)!=value: raise ValueError(f"v37 approval {key} mismatch")
    return sha256_json(record)


def train(args) -> int:
    if args.max_runtime_seconds<0 or args.runtime_grace_seconds<0: raise ValueError("v37 runtime budget values must be non-negative")
    simulation=v35.SimulationConfig(generations=args.generations,population_size=args.population,elite_count=2,child_count=args.population-3,immigrant_count=1,trials=2,challenge_trials=3,validation_trials=5,max_frames=args.max_frames)
    ppo=v36.PPOConfig(rollout_frames=args.rollout_frames,update_epochs=2,minibatch_size=64); robust=RobustnessConfig(audit_trials=args.audit_trials)
    estimated=args.generations*args.population*(args.rollout_frames+5*args.max_frames)+args.generations*15*args.max_frames
    if estimated>MAX_FRAMES_BUDGET: raise ValueError("v37 training exceeds frame budget")
    fingerprint=experiment_fingerprint(args.source_v36,simulation,ppo,robust,args.audit_seed_file)
    approval_action="resume" if args.resume else "train"
    approval_digest=load_approval(args.approval_record,args.experiment_id,fingerprint,approval_action,source=args.source_v36,audit_seed_file=args.audit_seed_file,
                                  planned_generations=args.generations,max_runtime_seconds=args.max_runtime_seconds)
    if not args.experiment_id.replace("-","").replace("_","").isalnum(): raise ValueError("invalid v37 experiment ID")
    base=args.artifact_root/args.experiment_id
    checkpoint=base/"evolution_state_v37.npz"; journal=base/"generations_v37.jsonl"; status_path=base/"status_v37.json"
    v36.validate_artifact_paths(args.artifact_root,base,checkpoint,journal)
    started=time.monotonic(); last_generation_seconds=None
    if args.resume:
        if Path(args.resume).resolve()!=checkpoint.resolve(): raise ValueError("v37 resume checkpoint must match the experiment artifact path")
        metadata,candidates,hof,resumed_simulation=load_training_checkpoint(checkpoint)
        if asdict(resumed_simulation)!=asdict(simulation) or metadata.get("ppo")!=asdict(ppo) or metadata.get("robustness")!=asdict(robust):
            raise ValueError("v37 resume configuration drift")
        if metadata.get("fingerprint")!=fingerprint or metadata.get("master_seed")!=args.seed or int(metadata.get("planned_generations",-1))!=args.generations:
            raise ValueError("v37 resume lineage, seed, or generation plan mismatch")
        if metadata["record"].get("approval_digest")!=approval_digest: raise ValueError("v37 resume approval record drift")
        records=read_generation_journal(journal); expected=int(metadata["generation"])+1
        if len(records)==expected-1 and metadata["record"].get("previous_record_hash")==((records[-1]["record_hash"] if records else "0"*64)):
            with journal.open("a",encoding="utf-8") as handle:
                handle.write(canonical_json(metadata["record"])+"\n"); handle.flush(); os.fsync(handle.fileno())
            records.append(metadata["record"])
            write_json(base/"recovery_v37.json",{"workflow_state":"RECOVERED","generation":metadata["generation"],"record_hash":metadata["record_hash"],"reason":"checkpoint commit recovered into journal"})
        if len(records)!=expected or records[-1]["record_hash"]!=metadata["record_hash"]: raise ValueError("v37 checkpoint and generation journal disagree")
        start_generation=expected; record_hash=metadata["record_hash"]; hof_score=float(metadata["hof"]["challenge_cvar"])
    else:
        if base.exists() and any(base.iterdir()): raise ValueError("v37 experiment directory is occupied; use --resume with its checkpoint")
        base.mkdir(parents=True,exist_ok=True); _,candidates,bank,source_hof=bootstrap_candidates(args.source_v36,simulation,robust,args.population,args.seed)
        positive=json.loads(args.source_v36.with_name("terminal_audit_v36.json").read_text(encoding="utf-8"))
        preserved={"schema_version":"v37.specialists.v1","source_checkpoint":file_evidence(args.source_v36),"protected_hof_hash":source_hof.policy.policy_hash,"positive_audit_pairs":[p for p in positive["pairs"] if p["delta"]>0],"challenge_specialists":[{"cell":cell,"source_policy_hash":policy.policy_hash,"challenge_cvar":score,"extinction_tiebreak":ext} for score,ext,cell,policy in bank[:4]]}
        write_json(base/"robustness_specialists_v37.json",preserved)
        hof=None; hof_score=-1e9; record_hash="0"*64; start_generation=0
    write_json(status_path,{"workflow_state":"TRAINING","audit_eligible":False,"generation":start_generation-1,"fingerprint":fingerprint,"planned_generations":args.generations})
    completed=start_generation
    for generation in range(start_generation,args.generations):
        if not runtime_allows_generation(started,args.max_runtime_seconds,args.runtime_grace_seconds,last_generation_seconds): break
        generation_started=time.monotonic()
        for candidate in candidates:
            episodes=[]; episode_id=0
            for profile,count in (("standard",robust.standard_rollouts),("water_fire_challenge",robust.challenge_rollouts)):
                for rollout in range(count):
                    env_seed=stable_seed(args.seed,"ppo",profile,generation,candidate.candidate_id,rollout); action_seed=stable_seed(args.seed,"actions",profile,generation,candidate.candidate_id,rollout)
                    world=RobustRollout(simulation,candidate.policy,env_seed,action_seed,profile,v36.RewardPolicy(),robust,episode_id)
                    while world.step() is None and world.frame<args.rollout_frames//(robust.standard_rollouts+robust.challenge_rollouts): pass
                    episodes.extend(world.finish()); episode_id+=1
            candidate.report=robust_update(candidate.policy,candidate.optimizer,episodes,ppo,robust,np.random.default_rng(stable_seed(args.seed,"minibatches",generation,candidate.candidate_id)))
            seeds=[stable_seed(args.seed,"selection",generation,i) for i in range(5)]; profiles=["standard","standard","water_fire_challenge","water_fire_challenge","water_fire_challenge"]
            candidate.trials=evaluate_brain(candidate.policy.brain,simulation,seeds,profiles); candidate.report["robust_score"]=candidate.robust_score(robust)
        ranked=sorted(candidates,key=lambda c:(c.report["robust_score"],c.policy.policy_hash),reverse=True)
        val_seeds=[stable_seed(args.seed,"validation",i) for i in range(5)]
        for nominee in ranked[:3]:
            trials=evaluate_brain(nominee.policy.brain,simulation,val_seeds,["water_fire_challenge"]*5); score=float(np.mean(sorted([t.fitness for t in trials])[:2]))
            if score>hof_score: hof=RobustCandidate(nominee.candidate_id,nominee.policy.copy(),RobustAdam.zeros(nominee.policy),nominee.source_policy_hash,nominee.source_kind); hof_score=score
        record={"schema_version":SCHEMA_VERSION,"generation":generation,"previous_record_hash":record_hash,"fingerprint":fingerprint,"approval_digest":approval_digest,"robustness":asdict(robust),"candidates":[{"candidate_id":c.candidate_id,"policy_hash":c.policy.policy_hash,"source_policy_hash":c.source_policy_hash,"source_kind":c.source_kind,**c.report} for c in ranked],"hof":{"candidate_id":hof.candidate_id,"policy_hash":hof.policy.policy_hash,"challenge_cvar":hof_score},"source_v36":file_evidence(args.source_v36)}
        record["record_hash"]=sha256_json(record); record_hash=record["record_hash"]
        metadata={"schema_version":SCHEMA_VERSION,"algorithm":ALGORITHM,"record":record,"record_hash":record_hash,"generation":generation,"hof":record["hof"],"fingerprint":fingerprint,"robustness":asdict(robust),"workflow_state":"GENERATION_COMMITTED","master_seed":args.seed,"simulation":asdict(simulation),"ppo":asdict(ppo),"planned_generations":args.generations,"critic_schema":CRITIC_SCHEMA,"source_v36":file_evidence(args.source_v36),"audit_seed_commitment":file_evidence(args.audit_seed_file)}
        save_checkpoint(checkpoint,metadata,candidates,hof)
        with journal.open("a",encoding="utf-8") as handle: handle.write(canonical_json(record)+"\n"); handle.flush(); os.fsync(handle.fileno())
        completed=generation+1; last_generation_seconds=time.monotonic()-generation_started
        write_json(status_path,{"workflow_state":"GENERATION_COMMITTED","audit_eligible":False,"generation":generation,"record_hash":record_hash,"hof_policy_hash":hof.policy.policy_hash,"challenge_cvar":hof_score,"fingerprint":fingerprint,"planned_generations":args.generations})
        print(f"commit generation={generation} robust_score={ranked[0].report['robust_score']:.6f} hof_challenge_cvar={hof_score:.6f}",flush=True)
    state="TRAINING_COMPLETE" if completed==args.generations else "BUDGET_EXHAUSTED"
    write_json(status_path,{"workflow_state":state,"audit_eligible":state=="TRAINING_COMPLETE","generation":completed-1,"record_hash":record_hash,"hof_policy_hash":hof.policy.policy_hash if hof else None,"challenge_cvar":hof_score,"fingerprint":fingerprint,"planned_generations":args.generations,"max_runtime_seconds":args.max_runtime_seconds})
    print(canonical_json({"workflow_state":state,"completed_generations":completed,"planned_generations":args.generations}),flush=True)
    return 0


def aggregate(trials,alpha):
    scores=[t.fitness for t in trials]; count=max(1,math.ceil(alpha*len(scores)))
    return {"mean":float(np.mean(scores)),"median":median(scores),"minimum":min(scores),"cvar":float(np.mean(sorted(scores)[:count])),"early_extinction_rate":float(np.mean([bool(t.metrics["early_extinction"]) for t in trials])),"challenge_mean":float(np.mean([t.fitness for t in trials if t.profile=="water_fire_challenge"])),"standard_mean":float(np.mean([t.fitness for t in trials if t.profile=="standard"]))}


def report_status(checkpoint: Path) -> dict[str,object]:
    metadata,policy,_=load_hof(checkpoint)
    generation=int(metadata["generation"]); planned=int(metadata.get("planned_generations",generation+1))
    status_path=checkpoint.with_name("status_v37.json")
    if metadata.get("workflow_state")=="GENERATION_COMMITTED" and not status_path.is_file(): raise ValueError("v37 committed checkpoint requires status evidence")
    status=json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
    if metadata.get("workflow_state")=="GENERATION_COMMITTED" and not {"generation","fingerprint","record_hash"}.issubset(status): raise ValueError("v37 status binding fields missing")
    for key,expected in (("generation",generation),("fingerprint",metadata["fingerprint"]),("record_hash",metadata["record_hash"])):
        if key in status and status[key]!=expected: raise ValueError(f"v37 status {key} mismatch")
    completed=generation+1; remaining=max(0,planned-completed)
    workflow=str(status.get("workflow_state",metadata["workflow_state"]))
    audit_eligible=bool(status.get("audit_eligible",completed==planned))
    if audit_eligible and (completed!=planned or workflow not in {"TRAINING_COMPLETE","TRAINING_COMMITTED"}): raise ValueError("v37 status audit eligibility mismatch")
    next_action="audit" if audit_eligible else ("resume" if workflow=="BUDGET_EXHAUSTED" else "inspect")
    return {"workflow_state":workflow,"audit_eligible":audit_eligible,"generation":generation,"completed_generations":completed,
            "planned_generations":planned,"remaining_generations":remaining,"next_action":next_action,"hof_policy_hash":policy.policy_hash,
            "critic_schema":metadata["critic_schema"],"robustness":metadata["robustness"],"fingerprint":metadata["fingerprint"],"record_hash":metadata["record_hash"]}


def bootstrap_ci(deltas,seed):
    rng=np.random.default_rng(seed); values=np.asarray(deltas); means=np.asarray([np.mean(rng.choice(values,len(values),replace=True)) for _ in range(2000)])
    return [float(np.quantile(means,.025)),float(np.quantile(means,.975))]


def audit(args):
    metadata,v37_policy,simulation=load_hof(args.checkpoint); fingerprint=metadata["fingerprint"]; approval_digest=load_approval(args.approval_record,args.experiment_id,fingerprint,"audit")
    lifecycle=report_status(args.checkpoint)
    if lifecycle["workflow_state"]!="TRAINING_COMPLETE" or not lifecycle["audit_eligible"] or lifecycle["remaining_generations"]!=0: raise ValueError("v37 workflow is not terminal-audit eligible")
    v36_meta,_,_,v36_hof=v36.load_checkpoint(args.v36_checkpoint); v35_meta=v35._raw_checkpoint_metadata(args.v35_checkpoint); v35_config=v35.SimulationConfig(**v35_meta["config"]); v35_brain=v35.CheckpointRepository.load(args.v35_checkpoint,v35_config)[0]
    count=args.audit_trials
    if count<32: raise ValueError("v37 audit requires at least 32 trials")
    if count*3*simulation.max_frames>MAX_FRAMES_BUDGET: raise ValueError("v37 audit exceeds frame budget")
    if int(metadata["generation"])+1!=int(metadata["planned_generations"]): raise ValueError("v37 training plan is incomplete")
    if metadata["source_v36"]["sha256"]!=file_evidence(args.v36_checkpoint)["sha256"] or metadata["audit_seed_commitment"]["sha256"]!=file_evidence(args.audit_seed_file)["sha256"]: raise ValueError("v37 source or audit commitment mismatch")
    current_fingerprint=experiment_fingerprint(args.v36_checkpoint,simulation,v36.PPOConfig(**metadata["ppo"]),RobustnessConfig(**metadata["robustness"]),args.audit_seed_file)
    if current_fingerprint!=fingerprint: raise ValueError("v37 implementation fingerprint drift")
    if any(getattr(v35_config,name)!=getattr(simulation,name) for name in ("width","height","cell_size","hidden1","hidden2","lineage_cap")): raise ValueError("baseline environment/actor contract mismatch")
    seeds=[int(line.strip()) for line in args.audit_seed_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(seeds)!=count or len(set(seeds))!=count: raise ValueError("audit seed commitment count/uniqueness mismatch")
    profiles=["standard" if i%2==0 else "water_fire_challenge" for i in range(count)]
    models={"v37":v37_policy.brain,"v36":v36_hof.policy.brain,"v35":v35_brain}; results={name:evaluate_brain(brain,simulation,seeds,profiles) for name,brain in models.items()}
    summaries={name:aggregate(trials,.25) for name,trials in results.items()}; pairs=[]
    for i,(seed,profile) in enumerate(zip(seeds,profiles)):
        row={"seed":seed,"profile":profile}
        for name in models:
            t=results[name][i]; row[name]={"fitness":t.fitness,"early_extinction":bool(t.metrics["early_extinction"]),"components":t.components,"metrics":{k:t.metrics[k] for k in ("hydrated_alive_frames","severe_thirst_frames","fire_contact_frames","water_recoveries","water_recovery_opportunities","final_population") if k in t.metrics}}
        pairs.append(row)
    deltas={baseline:[pairs[i]["v37"]["fitness"]-pairs[i][baseline]["fitness"] for i in range(count)] for baseline in ("v35","v36")}
    record={"schema_version":"v37.audit.v1","experiment_id":args.experiment_id,"workflow_state":"AUDIT_COMMITTED","approval_digest":approval_digest,"audit_trials":count,"profile_balance":{"standard":count//2,"challenge":count//2},"seed_suite_hash":sha256_json(seeds),"seed_commitment_file":file_evidence(args.audit_seed_file),"checkpoints":{"v37":file_evidence(args.checkpoint),"v36":file_evidence(args.v36_checkpoint),"v35":file_evidence(args.v35_checkpoint)},"policy_hashes":{"v37":v37_policy.policy_hash,"v36":v36_hof.policy.policy_hash,"v35":v35_brain.genome_hash},"summaries":summaries,"paired_mean_delta_ci95":{name:bootstrap_ci(values,stable_seed(37,"bootstrap",name)) for name,values in deltas.items()},"pairs":pairs,"created_utc":datetime.now(timezone.utc).isoformat()}
    record["release_gate"]="PASS" if all(summaries["v37"]["cvar"]>=summaries[b]["cvar"] and summaries["v37"]["early_extinction_rate"]<=summaries[b]["early_extinction_rate"] and summaries["v37"]["standard_mean"]>=summaries[b]["standard_mean"]*.95 for b in ("v35","v36")) else "FAIL"
    record["record_hash"]=sha256_json(record); output=args.checkpoint.with_name("terminal_audit_v37.json")
    if output.exists(): raise ValueError("v37 terminal audit already exists")
    write_json(output,record); write_json(args.checkpoint.with_name("failure_analysis_v37.json"),{"schema_version":"v37.failure-analysis.v1","pairs":pairs,"summaries":summaries,"delta_ci95":record["paired_mean_delta_ci95"]})
    print(canonical_json({"summaries":summaries,"release_gate":record["release_gate"],"record_hash":record["record_hash"]})); return 0


def build_parser():
    parser=argparse.ArgumentParser(description="Blast_Pit v37 robustness experiment"); sub=parser.add_subparsers(dest="command",required=True)
    train_p=sub.add_parser("train"); train_p.add_argument("--experiment-id",required=True); train_p.add_argument("--source-v36",type=Path,required=True); train_p.add_argument("--audit-seed-file",type=Path,required=True); train_p.add_argument("--artifact-root",type=Path,default=Path("artifacts/v37")); train_p.add_argument("--approval-record",type=Path,default=Path("approval_v37.json")); train_p.add_argument("--generations",type=int,default=1); train_p.add_argument("--population",type=int,default=8); train_p.add_argument("--rollout-frames",type=int,default=256); train_p.add_argument("--max-frames",type=int,default=1000); train_p.add_argument("--audit-trials",type=int,default=64); train_p.add_argument("--seed",type=int,default=20260711); train_p.add_argument("--resume",type=Path); train_p.add_argument("--max-runtime-seconds",type=int,default=0); train_p.add_argument("--runtime-grace-seconds",type=int,default=300)
    status=sub.add_parser("status"); status.add_argument("--checkpoint",type=Path,required=True)
    audit_p=sub.add_parser("audit"); audit_p.add_argument("--experiment-id",required=True); audit_p.add_argument("--checkpoint",type=Path,required=True); audit_p.add_argument("--v36-checkpoint",type=Path,required=True); audit_p.add_argument("--v35-checkpoint",type=Path,required=True); audit_p.add_argument("--audit-seed-file",type=Path,required=True); audit_p.add_argument("--audit-trials",type=int,default=64); audit_p.add_argument("--approval-record",type=Path,default=Path("approval_v37.json"))
    return parser


def main(argv=None):
    args=build_parser().parse_args(argv)
    try:
        if args.command=="train": return train(args)
        if args.command=="status": print(canonical_json(report_status(args.checkpoint))); return 0
        if args.command=="audit": return audit(args)
    except (ValueError,OSError,KeyError,json.JSONDecodeError) as error:
        print(f"error: {error}",file=sys.stderr); return 3
    return 3


if __name__=="__main__": raise SystemExit(main())
