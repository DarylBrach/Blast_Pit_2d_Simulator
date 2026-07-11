from __future__ import annotations

"""Blast_Pit v35 accelerated governed evolutionary simulator. See README.md."""

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import tempfile
import time
import traceback
import zipfile
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from statistics import median, pstdev
from typing import Iterable, Sequence
from importlib import metadata as importlib_metadata

# Spawned workers inherit these limits before importing NumPy/native BLAS.
# Runtime threadpool mutation inside Windows workers proved process-unsafe.
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

import numpy as np

# See README.md for governed v35 train/continue/visualize/audit commands.

APP_VERSION = "v35"
SCHEMA_VERSION = "v35.1"
ENGINE_CONTRACT_VERSION = 1

try:
    NUMBA_VERSION = importlib_metadata.version("numba")
    NUMBA_AVAILABLE = True
except importlib_metadata.PackageNotFoundError:
    NUMBA_VERSION = None
    NUMBA_AVAILABLE = False
SENSOR_LABELS = (
    "hunger", "thirst", "food_visible_dir", "food_visible_near",
    "water_visible_dir", "water_visible_near", "fire_visible_dir",
    "fire_visible_near", "food_smell_forward", "food_smell_right",
    "water_smell_forward", "water_smell_right", "touch_food",
    "touch_water", "crowd_density", "boundary_left", "boundary_right",
    "boundary_top", "boundary_bottom",
)

def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def installed_version(name: str) -> str | None:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None


def stable_seed(master: int, *parts: object) -> int:
    text = ":".join((str(master), *(str(part) for part in parts)))
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "little")


def _squared_distance_python(x0: float, y0: float, x1: float, y1: float) -> float:
    return (x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0)


def _squared_distance_numba_source(x0: float, y0: float, x1: float, y1: float) -> float:
    return (x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0)


_NUMBA_DISTANCE = None


def _squared_distance_numba(x0: float, y0: float, x1: float, y1: float) -> float:
    """Load and compile Numba only for an explicitly selected Numba engine."""
    global _NUMBA_DISTANCE
    if _NUMBA_DISTANCE is None:
        try:
            from numba import njit
        except ImportError as error:
            raise RuntimeError("Numba was requested but is not installed") from error
        _NUMBA_DISTANCE = njit(cache=False, fastmath=False)(_squared_distance_numba_source)
    return float(_NUMBA_DISTANCE(x0, y0, x1, y1))


def load_approval_record(path: Path, required_action: str) -> tuple[dict[str, object], str]:
    if not path.is_file() or path.stat().st_size > 64_000:
        raise ValueError("approval record is missing or oversized")
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("schema_version") != "approval.v1" or record.get("project") != "Blast_Pit" or record.get("version") != APP_VERSION or record.get("status") != "approved":
        raise ValueError("approval record identity/status mismatch")
    scopes = record.get("authorized_actions")
    if not isinstance(scopes, list) or required_action not in scopes:
        raise ValueError(f"approval record does not authorize {required_action}")
    digest = hashlib.sha256(canonical_json(record).encode()).hexdigest()
    return record, digest


@dataclass(frozen=True)
class SimulationConfig:
    width: int = 800
    height: int = 1000
    cell_size: int = 50
    population_size: int = 16
    lineage_cap: int = 16
    trials: int = 5
    challenge_trials: int = 2
    validation_trials: int = 7
    audit_trials: int = 11
    early_extinction_fraction: float = 0.25
    generations: int = 10
    max_frames: int = 6000
    fps: int = 60
    initial_food: int = 200
    initial_water: int = 200
    initial_fire: int = 25
    food_capacity: int = 250
    water_capacity: int = 250
    food_spawn_rate: float = 0.05
    water_spawn_rate: float = 0.05
    hunger_increment: float = 0.005
    thirst_increment: float = 0.005
    movement_energy_rate: float = 0.05
    basal_energy_cost: float = 0.025
    starvation_penalty: float = 0.2
    vision_range: float = 180.0
    smell_radius: float = 90.0
    fire_sense_range: float = 100.0
    touch_distance: float = 5.0
    fov_degrees: float = 120.0
    max_speed: float = 3.0
    fire_damage: float = 20.0
    reproduction_interval: int = 600
    reproduction_threshold: float = 70.0
    reproduction_parent_cost: float = 35.0
    child_start_energy: float = 25.0
    hidden1: int = 24
    hidden2: int = 16
    elite_count: int = 2
    child_count: int = 11
    immigrant_count: int = 3
    tournament_size: int = 4
    mutation_probability: float = 0.05
    mutation_strength: float = 0.15
    standard_suite_weight: float = 0.70
    challenge_suite_weight: float = 0.30
    stagnation_window: int = 8
    mutation_strength_min: float = 0.03
    mutation_strength_max: float = 0.75

    def __post_init__(self) -> None:
        positive = ("width", "height", "cell_size", "population_size", "lineage_cap", "trials", "challenge_trials", "validation_trials", "audit_trials", "generations", "max_frames", "fps")
        for name in positive:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.elite_count + self.child_count + self.immigrant_count != self.population_size:
            raise ValueError("elite_count + child_count + immigrant_count must equal population_size")
        if self.lineage_cap < 1 or self.food_capacity < self.initial_food or self.water_capacity < self.initial_water:
            raise ValueError("capacities must cover initial populations")
        for name in ("food_spawn_rate", "water_spawn_rate", "mutation_probability"):
            if not 0 <= getattr(self, name) <= 1:
                raise ValueError(f"{name} must be in [0,1]")
        if self.fov_degrees <= 0 or self.fov_degrees > 360:
            raise ValueError("fov_degrees must be in (0,360]")
        if not 0 < self.early_extinction_fraction < 1:
            raise ValueError("early_extinction_fraction must be in (0,1)")
        if not math.isclose(self.standard_suite_weight + self.challenge_suite_weight, 1.0, abs_tol=1e-12):
            raise ValueError("suite weights must sum to 1")
        if self.stagnation_window < 2 or not 0 < self.mutation_strength_min <= self.mutation_strength <= self.mutation_strength_max:
            raise ValueError("adaptive mutation bounds are invalid")

    @property
    def fingerprint(self) -> str:
        behavior = asdict(self)
        behavior.pop("generations")
        behavior.pop("fps")
        return hashlib.sha256(canonical_json(behavior).encode()).hexdigest()


@dataclass(frozen=True)
class ExecutionConfig:
    workers: int = 1
    kernel_backend: str = "python"
    inference_backend: str = "scalar"
    start_method: str = "spawn"
    native_threads_per_worker: int = 1

    def __post_init__(self) -> None:
        maximum = min(64, os.cpu_count() or 1)
        if not 1 <= self.workers <= maximum: raise ValueError(f"workers must be in [1,{maximum}]")
        if self.kernel_backend not in {"python", "numba"}: raise ValueError("kernel backend must be python or numba")
        if self.inference_backend not in {"scalar", "batch"}: raise ValueError("inference backend must be scalar or batch")
        if self.start_method != "spawn": raise ValueError("v35 requires spawn multiprocessing")
        if self.native_threads_per_worker != 1: raise ValueError("v35 requires one native BLAS thread per worker")
        if self.kernel_backend == "numba" and not NUMBA_AVAILABLE: raise ValueError("Numba was requested but is not installed")

    @property
    def engine_fingerprint(self) -> str:
        contract = {"engine_contract_version": ENGINE_CONTRACT_VERSION, "kernel_backend": self.kernel_backend, "inference_backend": self.inference_backend}
        return hashlib.sha256(canonical_json(contract).encode()).hexdigest()

    @property
    def evidence_contract(self) -> dict[str, object]:
        """Scientific semantics; worker count is operational and intentionally excluded."""
        return {"kernel_backend": self.kernel_backend, "inference_backend": self.inference_backend,
                "start_method": self.start_method, "ordering": "canonical_ordinal",
                "native_threads_per_worker": self.native_threads_per_worker,
                "numba_available": NUMBA_AVAILABLE, "numba_version": NUMBA_VERSION}


class TerminationReason(str, Enum):
    EXTINCTION = "extinction"
    MAX_FRAMES = "max_frames"
    USER_QUIT = "user_quit"


@dataclass(frozen=True)
class ExperimentOutcome:
    selection_champion_id: int
    validation_hof_id: int
    validation_hof_generation: int
    workflow_state: str
    state_checkpoint: str
    validation_checkpoint: str
    results: str
    audit_status: str


@dataclass
class Brain:
    W1: np.ndarray
    b1: np.ndarray
    W2: np.ndarray
    b2: np.ndarray
    W3: np.ndarray
    b3: np.ndarray

    @classmethod
    def random(cls, config: SimulationConfig, rng: np.random.Generator) -> Brain:
        return cls(
            rng.uniform(-1, 1, (config.hidden1, len(SENSOR_LABELS))),
            rng.uniform(-1, 1, config.hidden1),
            rng.uniform(-1, 1, (config.hidden2, config.hidden1)),
            rng.uniform(-1, 1, config.hidden2),
            rng.uniform(-1, 1, (2, config.hidden2)),
            rng.uniform(-1, 1, 2),
        )

    def copy(self) -> Brain:
        return Brain(*(array.copy() for array in self.arrays()))

    def arrays(self) -> tuple[np.ndarray, ...]:
        return self.W1, self.b1, self.W2, self.b2, self.W3, self.b3

    def forward(self, inputs: np.ndarray) -> np.ndarray:
        if inputs.shape != (len(SENSOR_LABELS),):
            raise ValueError(f"expected {len(SENSOR_LABELS)} inputs, got {inputs.shape}")
        hidden1 = np.tanh(self.W1 @ inputs + self.b1)
        hidden2 = np.tanh(self.W2 @ hidden1 + self.b2)
        return np.tanh(self.W3 @ hidden2 + self.b3)

    def forward_many(self, inputs: np.ndarray) -> np.ndarray:
        inputs = np.asarray(inputs, dtype=np.float64)
        if inputs.ndim != 2 or inputs.shape[1] != len(SENSOR_LABELS) or not np.isfinite(inputs).all():
            raise ValueError(f"expected finite batch shape (N,{len(SENSOR_LABELS)})")
        hidden1 = np.tanh(inputs @ self.W1.T + self.b1)
        hidden2 = np.tanh(hidden1 @ self.W2.T + self.b2)
        outputs = np.tanh(hidden2 @ self.W3.T + self.b3)
        if outputs.shape != (inputs.shape[0], 2) or not np.isfinite(outputs).all(): raise ValueError("invalid batched inference output")
        return outputs

    @property
    def genome_hash(self) -> str:
        digest = hashlib.sha256()
        for name, array in zip(("W1", "b1", "W2", "b2", "W3", "b3"), self.arrays()):
            normalized = np.ascontiguousarray(array, dtype="<f8")
            digest.update(name.encode())
            digest.update(canonical_json(list(normalized.shape)).encode())
            digest.update(normalized.tobytes())
        return digest.hexdigest()

    def validate(self, config: SimulationConfig) -> None:
        expected = ((config.hidden1, len(SENSOR_LABELS)), (config.hidden1,), (config.hidden2, config.hidden1), (config.hidden2,), (2, config.hidden2), (2,))
        for array, shape in zip(self.arrays(), expected):
            if array.shape != shape or array.dtype != np.float64 or not np.isfinite(array).all():
                raise ValueError(f"invalid brain array; expected finite float64 shape {shape}")


@dataclass(frozen=True)
class MutationRecord:
    changed: int
    l2_delta: float


class MutationPolicy:
    def mutate(self, brain: Brain, config: SimulationConfig, rng: np.random.Generator) -> tuple[Brain, MutationRecord]:
        child = brain.copy()
        masks = [rng.random(array.shape) < config.mutation_probability for array in child.arrays()]
        if not any(mask.any() for mask in masks):
            flat_index = int(rng.integers(sum(array.size for array in child.arrays())))
            for mask in masks:
                if flat_index < mask.size:
                    mask.flat[flat_index] = True
                    break
                flat_index -= mask.size
        squared = 0.0
        changed = 0
        for array, mask in zip(child.arrays(), masks):
            count = int(mask.sum())
            if count:
                delta = rng.normal(0, config.mutation_strength, count)
                before = array[mask].copy()
                array[mask] = np.clip(before + delta, -5, 5)
                actual_delta = array[mask] - before
                squared += float(actual_delta @ actual_delta)
                changed += count
        if squared == 0.0:
            array = child.W1
            before = float(array.flat[0])
            array.flat[0] = before - config.mutation_strength if before > 0 else before + config.mutation_strength
            array.flat[0] = float(np.clip(array.flat[0], -5, 5))
            squared = (float(array.flat[0]) - before) ** 2
            changed = max(changed, 1)
        return child, MutationRecord(changed, math.sqrt(squared))


@dataclass
class Resource:
    resource_id: int
    kind: str
    x: float
    y: float


@dataclass
class LineageMetrics:
    founder_survival_frames: int = 0
    lineage_food: int = 0
    lineage_water: int = 0
    lineage_fire_damage: float = 0.0
    lineage_alive_frames: int = 0
    fire_contact_frames: int = 0
    fire_deaths: int = 0
    water_recovery_opportunities: int = 0
    water_recoveries: int = 0
    early_extinction: bool = False
    lineage_distance: float = 0.0
    lineage_energy_spent: float = 0.0
    offspring_born: int = 0
    deaths: int = 0
    offspring_survival_frames: int = 0
    offspring_possible_frames: int = 0
    hydrated_alive_frames: int = 0
    severe_thirst_frames: int = 0
    unique_grid_cells: set[tuple[int, int]] = field(default_factory=set)
    extinct_frame: int | None = None

    def raw(self) -> dict[str, object]:
        result = asdict(self)
        result["unique_grid_cells"] = len(self.unique_grid_cells)
        return result


FITNESS_WEIGHTS = {
    "survival": .30, "food": .10, "water": .12, "damage_avoidance": .14,
    "efficiency": .08, "reproduction": .08, "offspring_survival": .08,
    "exploration": .02, "recovery": .08,
}


def _saturating(value: float, scale: float) -> float:
    return 0.0 if value <= 0 else float(value / (value + scale))


def compute_fitness_components(
    metrics: dict[str, object], config: SimulationConfig, frames: int, final_population: int,
) -> dict[str, float]:
    """Single authoritative v35 fitness policy used by execution and validation."""
    alive = max(1, int(metrics["lineage_alive_frames"]))
    founder = float(metrics["founder_survival_frames"]) / config.max_frames
    lineage = frames / config.max_frames
    population_integral = min(alive / (config.max_frames * config.lineage_cap), 1.0)
    terminal = min(final_population / config.lineage_cap, 1.0)
    hydration = float(metrics["hydrated_alive_frames"]) / alive
    severe_thirst = float(metrics["severe_thirst_frames"]) / alive
    useful = (
        float(metrics["lineage_food"]) + 1.25 * float(metrics["lineage_water"])
        + 2.0 * float(metrics["water_recoveries"]) + .5 * float(metrics["offspring_born"])
    )
    energy = float(metrics["lineage_energy_spent"])
    return {
        "survival": .30 * founder + .35 * lineage + .25 * population_integral + .10 * terminal,
        "food": _saturating(float(metrics["lineage_food"]), 8.0),
        "water": _saturating(float(metrics["lineage_water"]), 8.0),
        "damage_avoidance": math.exp(-50 * float(metrics["fire_contact_frames"]) / alive),
        "efficiency": useful / (useful + energy / 20.0) if useful or energy else 0.0,
        "reproduction": _saturating(float(metrics["offspring_born"]), 5.0),
        "offspring_survival": (float(metrics["offspring_survival_frames"]) / float(metrics["offspring_possible_frames"])) if metrics["offspring_possible_frames"] else 0.0,
        "exploration": _saturating(float(metrics["unique_grid_cells"]), 60.0),
        "recovery": max(0.0, min(1.0, .75 * hydration + .25 * (1.0 - severe_thirst))),
    }


@dataclass
class Creature:
    creature_id: int
    parent_id: int | None
    founder_id: int
    generation: int
    birth_frame: int
    x: float
    y: float
    orientation: float
    energy: float
    hunger: float
    thirst: float
    brain: Brain
    age: int = 0
    alive: bool = True
    last_inputs: tuple[float, ...] = ()
    last_outputs: tuple[float, ...] = ()
    speed: float = 0.0
    low_water_state: bool = False


@dataclass(frozen=True)
class TrialSummary:
    candidate_id: int
    seed: int
    termination: str
    frames: int
    final_population: int
    peak_population: int
    fitness: float
    components: dict[str, float]
    metrics: dict[str, object]
    final_state_hash: str
    profile: str = "standard"


def trial_summary_from_dict(data: dict[str, object]) -> TrialSummary:
    return TrialSummary(
        int(data["candidate_id"]), int(data["seed"]), str(data["termination"]),
        int(data["frames"]), int(data["final_population"]), int(data["peak_population"]),
        float(data["fitness"]), dict(data["components"]), dict(data["metrics"]),
        str(data["final_state_hash"]), str(data.get("profile", "standard")),
    )


@dataclass(frozen=True)
class TrialTask:
    ordinal: int
    generation: int
    candidate_id: int
    profile: str
    seed: int
    config: SimulationConfig
    brain_arrays: tuple[np.ndarray, ...]
    engine_fingerprint: str
    kernel_backend: str
    inference_backend: str


@dataclass(frozen=True)
class TrialResult:
    ordinal: int
    generation: int
    candidate_id: int
    profile: str
    seed: int
    genome_hash: str
    engine_fingerprint: str
    summary: TrialSummary


def validate_trial_summary(summary: TrialSummary, config: SimulationConfig, candidate_id: int, seed: int, profile: str) -> None:
    component_keys = {"survival", "food", "water", "damage_avoidance", "efficiency", "reproduction", "offspring_survival", "exploration", "recovery"}
    metric_keys = {"founder_survival_frames", "lineage_food", "lineage_water", "lineage_fire_damage", "lineage_alive_frames", "fire_contact_frames", "fire_deaths", "water_recovery_opportunities", "water_recoveries", "early_extinction", "lineage_distance", "lineage_energy_spent", "offspring_born", "deaths", "offspring_survival_frames", "offspring_possible_frames", "hydrated_alive_frames", "severe_thirst_frames", "unique_grid_cells", "extinct_frame"}
    if (summary.candidate_id, summary.seed, summary.profile) != (candidate_id, seed, profile): raise ValueError("trial identity mismatch")
    if summary.termination not in {TerminationReason.EXTINCTION.value, TerminationReason.MAX_FRAMES.value}: raise ValueError("trial termination is invalid")
    if not isinstance(summary.frames, int) or not 0 <= summary.frames <= config.max_frames: raise ValueError("trial frame count is invalid")
    if not isinstance(summary.final_population, int) or not isinstance(summary.peak_population, int) or not 0 <= summary.final_population <= summary.peak_population <= config.lineage_cap: raise ValueError("trial population count is invalid")
    if len(summary.final_state_hash) != 64 or any(character not in "0123456789abcdef" for character in summary.final_state_hash): raise ValueError("trial state hash is invalid")
    if set(summary.components) != component_keys or set(summary.metrics) != metric_keys: raise ValueError("trial metric/component schema is invalid")
    m = summary.metrics
    integer_metrics = ("founder_survival_frames", "lineage_food", "lineage_water", "lineage_alive_frames", "fire_contact_frames", "fire_deaths", "water_recovery_opportunities", "water_recoveries", "offspring_born", "deaths", "offspring_survival_frames", "offspring_possible_frames", "hydrated_alive_frames", "severe_thirst_frames", "unique_grid_cells")
    if any(isinstance(m[key], bool) or not isinstance(m[key], int) or m[key] < 0 for key in integer_metrics): raise ValueError("trial metric bounds are invalid")
    if not isinstance(m["early_extinction"], bool): raise ValueError("trial early-extinction metric is invalid")
    if any(isinstance(m[key], bool) or not isinstance(m[key], (int, float)) or m[key] < 0 for key in ("lineage_fire_damage", "lineage_distance", "lineage_energy_spent")): raise ValueError("trial continuous metric bounds are invalid")
    if m["founder_survival_frames"] > summary.frames or m["fire_contact_frames"] > m["lineage_alive_frames"] or m["water_recoveries"] > m["water_recovery_opportunities"]: raise ValueError("trial metric relationships are invalid")
    if m["lineage_alive_frames"] > summary.frames * config.lineage_cap or m["offspring_survival_frames"] > summary.frames * config.lineage_cap: raise ValueError("trial lineage-frame metric is invalid")
    if m["extinct_frame"] is not None and (isinstance(m["extinct_frame"], bool) or not isinstance(m["extinct_frame"], int) or not 0 <= m["extinct_frame"] <= summary.frames): raise ValueError("trial extinction frame is invalid")
    numeric = [summary.fitness, *summary.components.values(), *(value for value in m.values() if isinstance(value, (int, float)))]
    if not all(math.isfinite(float(value)) for value in numeric): raise ValueError("trial contains non-finite values")
    if not 0 <= summary.fitness <= 1 or any(not 0 <= float(value) <= 1 for value in summary.components.values()): raise ValueError("trial fitness/component range is invalid")
    expected = compute_fitness_components(m, config, summary.frames, summary.final_population)
    weights = FITNESS_WEIGHTS
    if any(not math.isclose(float(summary.components[key]), float(value), rel_tol=0, abs_tol=1e-15) for key, value in expected.items()): raise ValueError("trial components do not match raw metrics")
    expected_fitness = sum(expected[key] * weights[key] for key in weights)
    if not math.isclose(summary.fitness, expected_fitness, rel_tol=0, abs_tol=1e-15): raise ValueError("trial fitness does not match raw metrics")


def run_trial_task(task: TrialTask) -> TrialResult:
    execution = ExecutionConfig(1, task.kernel_backend, task.inference_backend)
    if execution.engine_fingerprint != task.engine_fingerprint: raise ValueError("worker engine fingerprint mismatch")
    brain = Brain(*(np.array(array, dtype=np.float64, copy=True) for array in task.brain_arrays)); brain.validate(task.config)
    summary = Simulation(task.config, brain, task.seed, task.candidate_id, task.profile, execution).run()
    validate_trial_summary(summary, task.config, task.candidate_id, task.seed, task.profile)
    return TrialResult(task.ordinal, task.generation, task.candidate_id, task.profile, task.seed, brain.genome_hash, task.engine_fingerprint, summary)


def initialize_trial_worker() -> None:
    """Verify inherited native thread limits without mutating loaded runtimes."""
    for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        if os.environ.get(name) != "1":
            raise RuntimeError(f"worker native thread limit is invalid: {name}")


@dataclass
class Candidate:
    candidate_id: int
    brain: Brain
    origin: str = "random"
    parent_candidate_id: int | None = None
    mutation: MutationRecord | None = None
    trials: list[TrialSummary] = field(default_factory=list)
    validation_trials: list[TrialSummary] = field(default_factory=list)

    @property
    def median_fitness(self) -> float:
        return median([trial.fitness for trial in self.trials]) if self.trials else 0.0

    @property
    def fitness_stddev(self) -> float:
        return pstdev([trial.fitness for trial in self.trials]) if len(self.trials) > 1 else 0.0

    @property
    def selection_fitness(self) -> float:
        if not self.trials:
            return 0.0
        standard = [trial for trial in self.trials if trial.profile == "standard"]
        challenge = [trial for trial in self.trials if trial.profile == "water_fire_challenge"]
        def robust(items: list[TrialSummary]) -> float:
            if not items:
                return 0.0
            scores = [item.fitness for item in items]
            survival = min(float(item.components["survival"]) for item in items)
            return 0.60 * median(scores) + 0.25 * min(scores) + 0.15 * survival
        # Counts no longer silently alter the intended suite importance.
        return .70 * robust(standard) + .30 * robust(challenge)

    @property
    def early_extinction_rate(self) -> float:
        return sum(bool(trial.metrics.get("early_extinction")) for trial in self.trials) / len(self.trials) if self.trials else 1.0

    @property
    def validation_median(self) -> float:
        return median([trial.fitness for trial in self.validation_trials]) if self.validation_trials else 0.0

    @property
    def validation_stddev(self) -> float:
        return pstdev([trial.fitness for trial in self.validation_trials]) if len(self.validation_trials) > 1 else 0.0

    @property
    def validation_fitness(self) -> float:
        if not self.validation_trials:
            return 0.0
        scores = [trial.fitness for trial in self.validation_trials]
        survival_rate = 1.0 - sum(bool(trial.metrics.get("early_extinction")) for trial in self.validation_trials) / len(self.validation_trials)
        return 0.60 * median(scores) + 0.25 * min(scores) + 0.15 * survival_rate


class SpatialIndex:
    def __init__(self, cell_size: int, kernel_backend: str = "python"):
        self.cell_size = cell_size
        self.kernel_backend = kernel_backend
        self.cells: dict[tuple[int, int], list[object]] = defaultdict(list)

    def key(self, x: float, y: float) -> tuple[int, int]:
        return int(x // self.cell_size), int(y // self.cell_size)

    def build(self, objects: Iterable[object]) -> None:
        self.cells.clear()
        for obj in objects:
            self.cells[self.key(obj.x, obj.y)].append(obj)

    def remove(self, obj: object) -> None:
        bucket = self.cells.get(self.key(obj.x, obj.y), [])
        for index, candidate in enumerate(bucket):
            if candidate is obj:
                del bucket[index]
                return

    def query(self, x: float, y: float, radius: float) -> Iterable[object]:
        cx, cy = self.key(x, y)
        span = math.ceil(radius / self.cell_size)
        radius_sq = radius * radius
        for dx in range(-span, span + 1):
            for dy in range(-span, span + 1):
                for obj in self.cells.get((cx + dx, cy + dy), ()):
                    distance_sq = _squared_distance_numba(x, y, obj.x, obj.y) if self.kernel_backend == "numba" else _squared_distance_python(x, y, obj.x, obj.y)
                    if distance_sq <= radius_sq:
                        yield obj


class Simulation:
    def __init__(self, config: SimulationConfig, brain: Brain, seed: int, candidate_id: int = 0, profile: str = "standard", execution: ExecutionConfig | None = None):
        self.config = config
        self.brain = brain
        self.seed = seed
        self.candidate_id = candidate_id
        if profile not in {"standard", "water_fire_challenge", "validation", "audit"}:
            raise ValueError(f"unknown trial profile: {profile}")
        self.profile = profile
        self.execution = execution or ExecutionConfig()
        self.environment_rng = np.random.default_rng(stable_seed(seed, "environment"))
        self.lineage_rng = np.random.default_rng(stable_seed(seed, "lineage"))
        self.frame = 0
        self.next_creature_id = 1
        self.next_resource_id = 1
        self.creatures: list[Creature] = []
        self.resources: dict[str, list[Resource]] = {"food": [], "water": [], "fire": []}
        self.resource_indexes = {kind: SpatialIndex(config.cell_size, self.execution.kernel_backend) for kind in self.resources}
        self.creature_index = SpatialIndex(config.cell_size, self.execution.kernel_backend)
        self._indexes_ready = False
        self.metrics = LineageMetrics()
        self.food_accumulator = 0.0
        self.water_accumulator = 0.0
        self.peak_population = 1
        self.events: list[dict[str, object]] = []
        self._spawn_founder()
        challenge = profile == "water_fire_challenge"
        for kind, count in (("food", config.initial_food if not challenge else max(1, config.initial_food * 3 // 4)), ("water", config.initial_water if not challenge else max(1, config.initial_water // 4)), ("fire", config.initial_fire if not challenge else config.initial_fire + 10)):
            self._spawn_resources(kind, count)
        if challenge and self.resources["fire"]:
            founder = self.creatures[0]
            angle = math.radians(float(self.environment_rng.uniform(0, 360)))
            radius = max(2 * config.touch_distance, 20.0)
            self.resources["fire"][0].x = min(max(0.0, founder.x + math.cos(angle) * radius), config.width)
            self.resources["fire"][0].y = min(max(0.0, founder.y + math.sin(angle) * radius), config.height)
        for kind, index in self.resource_indexes.items():
            index.build(self.resources[kind])
        self._indexes_ready = True

    def _spawn_founder(self) -> None:
        self.creatures.append(self._new_creature(None, 1, 0, self.environment_rng.uniform(0, self.config.width), self.environment_rng.uniform(0, self.config.height), 100.0, 0.0, 0.0))

    def _new_creature(self, parent_id: int | None, founder_id: int, generation: int, x: float, y: float, energy: float, hunger: float, thirst: float) -> Creature:
        creature = Creature(self.next_creature_id, parent_id, founder_id, generation, self.frame, x, y, float(self.lineage_rng.uniform(0, 360)), energy, hunger, thirst, self.brain)
        self.next_creature_id += 1
        return creature

    def _spawn_resources(self, kind: str, count: int) -> None:
        for _ in range(count):
            x = float(self.environment_rng.uniform(0, self.config.width))
            y = float(self.environment_rng.uniform(0, self.config.height))
            if kind == "fire" and self.creatures:
                safe_distance = max(2 * self.config.touch_distance, 15.0)
                founder = self.creatures[0]
                for _attempt in range(64):
                    if math.hypot(x - founder.x, y - founder.y) >= safe_distance:
                        break
                    x = float(self.environment_rng.uniform(0, self.config.width))
                    y = float(self.environment_rng.uniform(0, self.config.height))
                if math.hypot(x - founder.x, y - founder.y) < safe_distance:
                    x, y = max(
                        ((0.0, 0.0), (float(self.config.width), 0.0), (0.0, float(self.config.height)), (float(self.config.width), float(self.config.height))),
                        key=lambda point: math.hypot(point[0] - founder.x, point[1] - founder.y),
                    )
            resource = Resource(self.next_resource_id, kind, x, y)
            self.resources[kind].append(resource)
            if self._indexes_ready:
                self.resource_indexes[kind].cells[self.resource_indexes[kind].key(x, y)].append(resource)
            self.next_resource_id += 1

    def _rebuild_indexes(self) -> None:
        """Resources are maintained incrementally; only moving creatures rebuild."""
        self.creature_index.build(creature for creature in self.creatures if creature.alive)

    @staticmethod
    def _relative_angle(creature: Creature, x: float, y: float) -> float:
        absolute = math.degrees(math.atan2(y - creature.y, x - creature.x))
        relative = (absolute - creature.orientation + 180) % 360 - 180
        return relative

    def _visible(self, creature: Creature, kind: str, radius: float) -> tuple[float, float]:
        best: tuple[float, float] | None = None
        for obj in self.resource_indexes[kind].query(creature.x, creature.y, radius):
            distance = math.hypot(obj.x - creature.x, obj.y - creature.y)
            relative = self._relative_angle(creature, obj.x, obj.y)
            if abs(relative) <= self.config.fov_degrees / 2 and (best is None or distance < best[0]):
                best = distance, relative
        if best is None:
            return 0.0, 0.0
        return best[1] / (self.config.fov_degrees / 2), 1.0 - min(best[0] / radius, 1.0)

    def _smell(self, creature: Creature, kind: str) -> tuple[float, float]:
        world_x = world_y = weight_sum = 0.0
        for obj in self.resource_indexes[kind].query(creature.x, creature.y, self.config.smell_radius):
            dx, dy = obj.x - creature.x, obj.y - creature.y
            distance = math.hypot(dx, dy)
            if distance == 0:
                return 1.0, 0.0
            weight = 1.0 - distance / self.config.smell_radius
            world_x += weight * dx / distance
            world_y += weight * dy / distance
            weight_sum += weight
        if weight_sum == 0:
            return 0.0, 0.0
        world_x /= weight_sum
        world_y /= weight_sum
        angle = math.radians(creature.orientation)
        forward = world_x * math.cos(angle) + world_y * math.sin(angle)
        right = -world_x * math.sin(angle) + world_y * math.cos(angle)
        magnitude = max(1.0, math.hypot(forward, right))
        return forward / magnitude, right / magnitude

    def sense(self, creature: Creature) -> tuple[float, ...]:
        values: list[float] = [min(creature.hunger, 1.0), min(creature.thirst, 1.0)]
        values.extend(self._visible(creature, "food", self.config.vision_range))
        values.extend(self._visible(creature, "water", self.config.vision_range))
        values.extend(self._visible(creature, "fire", self.config.fire_sense_range))
        values.extend(self._smell(creature, "food"))
        values.extend(self._smell(creature, "water"))
        values.append(float(any(True for _ in self.resource_indexes["food"].query(creature.x, creature.y, self.config.touch_distance))))
        values.append(float(any(True for _ in self.resource_indexes["water"].query(creature.x, creature.y, self.config.touch_distance))))
        crowd = sum(1 for other in self.creature_index.query(creature.x, creature.y, self.config.vision_range) if other is not creature and other.alive)
        values.append(min(crowd / max(1, self.config.lineage_cap - 1), 1.0))
        values.extend((
            1 - min(creature.x / self.config.vision_range, 1),
            1 - min((self.config.width - creature.x) / self.config.vision_range, 1),
            1 - min(creature.y / self.config.vision_range, 1),
            1 - min((self.config.height - creature.y) / self.config.vision_range, 1),
        ))
        if len(values) != len(SENSOR_LABELS) or not all(-1 <= value <= 1 for value in values):
            raise RuntimeError("sensor invariant failed")
        return tuple(float(value) for value in values)

    def _consume(self, creature: Creature, kind: str) -> bool:
        for obj in sorted(self.resource_indexes[kind].query(creature.x, creature.y, self.config.touch_distance), key=lambda item: item.resource_id):
            for index, candidate in enumerate(self.resources[kind]):
                if candidate is obj:
                    del self.resources[kind][index]
                    self.resource_indexes[kind].remove(obj)
                    if kind == "food":
                        creature.hunger = 0.0
                        creature.energy = min(100.0, creature.energy + 50.0)
                        self.metrics.lineage_food += 1
                    else:
                        if creature.low_water_state:
                            self.metrics.water_recoveries += 1
                            creature.low_water_state = False
                        creature.thirst = 0.0
                        self.metrics.lineage_water += 1
                    self.events.append({"frame": self.frame, "kind": f"consume_{kind}", "creature_id": creature.creature_id, "resource_id": obj.resource_id})
                    return True
        return False

    def _act(self, creature: Creature, inputs: tuple[float, ...], outputs: np.ndarray) -> None:
        creature.last_inputs = inputs
        creature.last_outputs = tuple(float(value) for value in outputs)
        creature.orientation = (creature.orientation + float(outputs[0]) * 30) % 360
        creature.speed = ((float(np.clip(outputs[1], -1, 1)) + 1) / 2) * self.config.max_speed
        angle = math.radians(creature.orientation)
        old_x, old_y = creature.x, creature.y
        creature.x = min(max(0.0, creature.x + math.cos(angle) * creature.speed), self.config.width)
        creature.y = min(max(0.0, creature.y + math.sin(angle) * creature.speed), self.config.height)
        distance = math.hypot(creature.x - old_x, creature.y - old_y)
        movement_cost = distance * self.config.movement_energy_rate
        creature.energy -= movement_cost + self.config.basal_energy_cost
        self.metrics.lineage_distance += distance
        self.metrics.lineage_energy_spent += movement_cost + self.config.basal_energy_cost
        self.metrics.lineage_alive_frames += 1
        if creature.thirst < 0.75:
            self.metrics.hydrated_alive_frames += 1
        if creature.thirst > 1.0:
            self.metrics.severe_thirst_frames += 1
        self.metrics.unique_grid_cells.add((int(creature.x // self.config.cell_size), int(creature.y // self.config.cell_size)))
        fire_contact = False
        for fire in self.resource_indexes["fire"].query(creature.x, creature.y, self.config.touch_distance):
            fire_contact = True
            creature.energy -= self.config.fire_damage
            self.metrics.lineage_fire_damage += self.config.fire_damage
            self.metrics.fire_contact_frames += 1
            break
        self._consume(creature, "food")
        self._consume(creature, "water")
        creature.hunger += self.config.hunger_increment
        creature.thirst += self.config.thirst_increment
        if creature.thirst >= 0.75 and not creature.low_water_state:
            creature.low_water_state = True
            self.metrics.water_recovery_opportunities += 1
        if creature.hunger > 1 or creature.thirst > 1:
            creature.energy -= self.config.starvation_penalty
        creature.age += 1
        if creature.creature_id == 1:
            self.metrics.founder_survival_frames = creature.age
        else:
            self.metrics.offspring_survival_frames += 1
        creature.alive = creature.energy > 0
        if not creature.alive and fire_contact:
            self.metrics.fire_deaths += 1

    def _reproduce(self) -> None:
        for parent in sorted(list(self.creatures), key=lambda item: item.creature_id):
            eligible = parent.alive and parent.age > 0 and parent.age % self.config.reproduction_interval == 0 and parent.energy >= self.config.reproduction_threshold
            if eligible and len(self.creatures) >= self.config.lineage_cap:
                self.events.append({"frame": self.frame, "kind": "reproduction_blocked_cap", "creature_id": parent.creature_id})
                continue
            if eligible:
                parent.energy -= self.config.reproduction_parent_cost
                self.metrics.lineage_energy_spent += self.config.reproduction_parent_cost
                child = self._new_creature(parent.creature_id, parent.founder_id, parent.generation + 1, parent.x, parent.y, self.config.child_start_energy, parent.hunger, parent.thirst)
                self.creatures.append(child)
                self.metrics.offspring_born += 1
                self.events.append({"frame": self.frame, "kind": "birth", "creature_id": child.creature_id, "parent_id": parent.creature_id})

    def _regenerate(self) -> None:
        water_rate = self.config.water_spawn_rate * (0.5 if self.profile == "water_fire_challenge" else 1.0)
        for kind, rate, capacity, attr in (("food", self.config.food_spawn_rate, self.config.food_capacity, "food_accumulator"), ("water", water_rate, self.config.water_capacity, "water_accumulator")):
            accumulator = getattr(self, attr) + rate
            count = min(int(accumulator), capacity - len(self.resources[kind]))
            if count:
                self._spawn_resources(kind, count)
                accumulator -= count
            if len(self.resources[kind]) >= capacity:
                accumulator %= 1.0
            setattr(self, attr, accumulator)

    def step(self) -> TerminationReason | None:
        if self.frame >= self.config.max_frames:
            return TerminationReason.MAX_FRAMES
        self.events = []
        self._rebuild_indexes()
        living = sorted((creature for creature in self.creatures if creature.alive), key=lambda item: item.creature_id)
        # Every previously born offspring has one more frame of possible survival,
        # including offspring that already died. This avoids late-birth bias.
        self.metrics.offspring_possible_frames += self.metrics.offspring_born
        decisions = [(creature, self.sense(creature)) for creature in living]
        if self.execution.inference_backend == "batch" and decisions:
            outputs_many = self.brain.forward_many(np.asarray([inputs for _, inputs in decisions], dtype=np.float64))
            for (creature, inputs), outputs in zip(decisions, outputs_many): self._act(creature, inputs, outputs)
        else:
            for creature, inputs in decisions: self._act(creature, inputs, self.brain.forward(np.asarray(inputs)))
        self.metrics.deaths += sum(1 for creature in self.creatures if not creature.alive)
        self.creatures = [creature for creature in self.creatures if creature.alive]
        self._reproduce()
        self._regenerate()
        self.frame += 1
        self.peak_population = max(self.peak_population, len(self.creatures))
        if not self.creatures:
            self.metrics.extinct_frame = self.frame
            self.metrics.early_extinction = self.frame < self.config.max_frames * self.config.early_extinction_fraction
            return TerminationReason.EXTINCTION
        if self.frame >= self.config.max_frames:
            return TerminationReason.MAX_FRAMES
        return None

    def state_hash(self) -> str:
        state = {
            "frame": self.frame, "next_creature_id": self.next_creature_id,
            "next_resource_id": self.next_resource_id, "food_accumulator": self.food_accumulator,
            "water_accumulator": self.water_accumulator,
            "environment_rng": self.environment_rng.bit_generator.state,
            "lineage_rng": self.lineage_rng.bit_generator.state,
            "creatures": [{key: value for key, value in asdict(creature).items() if key != "brain"} for creature in sorted(self.creatures, key=lambda item: item.creature_id)],
            "resources": [asdict(resource) for kind in sorted(self.resources) for resource in sorted(self.resources[kind], key=lambda item: item.resource_id)],
            "metrics": self.metrics.raw(), "genome_hash": self.brain.genome_hash,
        }
        return hashlib.sha256(canonical_json(state).encode()).hexdigest()

    def fitness(self) -> tuple[float, dict[str, float]]:
        raw = self.metrics.raw()
        components = compute_fitness_components(raw, self.config, self.frame, len(self.creatures))
        return sum(components[key] * FITNESS_WEIGHTS[key] for key in FITNESS_WEIGHTS), components

    def run(self) -> TrialSummary:
        reason = None
        while reason is None:
            reason = self.step()
        fitness, components = self.fitness()
        return TrialSummary(self.candidate_id, self.seed, reason.value, self.frame, len(self.creatures), self.peak_population, fitness, components, self.metrics.raw(), self.state_hash(), self.profile)


class CheckpointRepository:
    ARRAY_NAMES = ("W1", "b1", "W2", "b2", "W3", "b3")
    MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024
    MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024

    @classmethod
    def _preflight_npz(cls, path: Path) -> None:
        if not path.is_file() or path.stat().st_size > cls.MAX_CHECKPOINT_BYTES:
            raise ValueError("checkpoint is missing, non-regular, or oversized")
        try:
            archive_context = zipfile.ZipFile(path)
        except zipfile.BadZipFile as error:
            raise ValueError("checkpoint is not a valid NPZ/ZIP archive") from error
        with archive_context as archive:
            members = archive.infolist()
            if len(members) > 256 or len({member.filename for member in members}) != len(members):
                raise ValueError("checkpoint member count/uniqueness violation")
            total = 0
            for member in members:
                if member.flag_bits & 1 or "/" in member.filename or "\\" in member.filename or not member.filename.endswith(".npy"):
                    raise ValueError("checkpoint contains unsafe member names or encryption")
                total += member.file_size
                if member.compress_size and member.file_size / member.compress_size > 1000:
                    raise ValueError("checkpoint compression ratio is unsafe")
            if total > cls.MAX_UNCOMPRESSED_BYTES:
                raise ValueError("checkpoint uncompressed content is oversized")

    @classmethod
    def save(cls, path: Path, candidate: Candidate, config: SimulationConfig, master_seed: int, generation: int, checkpoint_kind: str = "brain", approval_digest: str = "UNRECORDED_TEST", experiment_id: str = "test") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        metadata = {
            "schema_version": SCHEMA_VERSION, "app_version": APP_VERSION,
            "checkpoint_kind": checkpoint_kind,
            "approval_digest": approval_digest, "experiment_id": experiment_id,
            "sensor_schema": SENSOR_LABELS, "config": asdict(config), "config_hash": config.fingerprint,
            "master_seed": master_seed, "generation": generation, "candidate_id": candidate.candidate_id,
            "genome_hash": candidate.brain.genome_hash, "selection_fitness": candidate.selection_fitness,
            "median_fitness": candidate.median_fitness, "fitness_stddev": candidate.fitness_stddev,
            "trials": [asdict(trial) for trial in candidate.trials],
            "validation_fitness": candidate.validation_fitness, "validation_median": candidate.validation_median,
            "validation_stddev": candidate.validation_stddev,
            "validation_trials": [asdict(trial) for trial in candidate.validation_trials],
        }
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
                temp_path = Path(handle.name)
                np.savez(handle, metadata=np.frombuffer(canonical_json(metadata).encode(), dtype=np.uint8), **dict(zip(cls.ARRAY_NAMES, candidate.brain.arrays())))
                handle.flush(); os.fsync(handle.fileno())
            loaded, loaded_metadata = cls.load(temp_path, config)
            if loaded.genome_hash != candidate.brain.genome_hash or loaded_metadata["config_hash"] != config.fingerprint:
                raise ValueError("checkpoint verification failed")
            os.replace(temp_path, path)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()

    @classmethod
    def load(cls, path: Path, config: SimulationConfig, allow_config_mismatch: bool = False) -> tuple[Brain, dict[str, object]]:
        cls._preflight_npz(path)
        with np.load(path, allow_pickle=False) as data:
            required = set(cls.ARRAY_NAMES) | {"metadata"}
            if required.difference(data.files):
                raise ValueError("checkpoint is missing required fields")
            raw_metadata = np.asarray(data["metadata"])
            if raw_metadata.dtype != np.uint8 or raw_metadata.ndim != 1 or raw_metadata.nbytes > 8 * 1024 * 1024:
                raise ValueError("checkpoint metadata encoding is invalid")
            metadata = json.loads(bytes(raw_metadata).decode())
            kind = metadata.get("checkpoint_kind", "brain")
            expected_files = set(cls.ARRAY_NAMES) | {"metadata"}
            if kind == "evolution_state":
                population_size = len(metadata.get("population", []))
                expected_files |= {f"population_{index}_{name}" for index in range(population_size) for name in cls.ARRAY_NAMES}
                if metadata.get("validation_hof") is not None:
                    expected_files |= {f"validation_hof_{name}" for name in cls.ARRAY_NAMES}
            if set(data.files) != expected_files:
                raise ValueError("checkpoint contains unexpected or missing members")
            brain = Brain(*(np.array(data[name], copy=True) for name in cls.ARRAY_NAMES))
        brain.validate(config)
        if metadata.get("schema_version") != SCHEMA_VERSION or tuple(metadata.get("sensor_schema", ())) != SENSOR_LABELS:
            raise ValueError("incompatible checkpoint schema or sensor contract")
        if not allow_config_mismatch and metadata.get("config_hash") != config.fingerprint:
            raise ValueError("checkpoint configuration mismatch")
        if metadata.get("genome_hash") != brain.genome_hash:
            raise ValueError("checkpoint genome hash mismatch")
        return brain, metadata

    @classmethod
    def save_population(cls, path: Path, champion: Candidate, population: Sequence[Candidate], config: SimulationConfig, master_seed: int, generation: int, next_candidate_id: int, validation_hof: Candidate | None = None, validation_hof_generation: int | None = None, generation_record: dict[str, object] | None = None, approval_digest: str = "UNRECORDED_TEST", experiment_id: str = "test", execution: ExecutionConfig | None = None, planned_generation_count: int | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptors = []
        arrays: dict[str, np.ndarray] = dict(zip(cls.ARRAY_NAMES, champion.brain.arrays()))
        if validation_hof is not None:
            for name, array in zip(cls.ARRAY_NAMES, validation_hof.brain.arrays()):
                arrays[f"validation_hof_{name}"] = array
        for index, candidate in enumerate(population):
            descriptors.append({"candidate_id": candidate.candidate_id, "origin": candidate.origin, "parent_candidate_id": candidate.parent_candidate_id, "mutation": asdict(candidate.mutation) if candidate.mutation else None, "genome_hash": candidate.brain.genome_hash})
            for name, array in zip(cls.ARRAY_NAMES, candidate.brain.arrays()):
                arrays[f"population_{index}_{name}"] = array
        metadata = {
            "schema_version": SCHEMA_VERSION, "app_version": APP_VERSION, "sensor_schema": SENSOR_LABELS,
            "config": asdict(config), "config_hash": config.fingerprint, "master_seed": master_seed,
            "generation": generation, "next_candidate_id": next_candidate_id, "population": descriptors,
            "planned_generation_count": planned_generation_count if planned_generation_count is not None else config.generations,
            "workflow_state": "TRAINING_COMMITTED", "approval_digest": approval_digest, "experiment_id": experiment_id,
            "engine_fingerprint": (execution or ExecutionConfig()).engine_fingerprint,
            "execution": asdict(execution or ExecutionConfig()),
            "candidate_id": champion.candidate_id, "genome_hash": champion.brain.genome_hash,
            "selection_fitness": champion.selection_fitness, "median_fitness": champion.median_fitness,
            "fitness_stddev": champion.fitness_stddev, "trials": [asdict(trial) for trial in champion.trials],
            "validation_fitness": champion.validation_fitness, "validation_median": champion.validation_median,
            "validation_stddev": champion.validation_stddev,
            "validation_trials": [asdict(trial) for trial in champion.validation_trials],
            "checkpoint_kind": "evolution_state",
            "generation_record": generation_record,
            "generation_record_hash": hashlib.sha256(canonical_json(generation_record).encode()).hexdigest() if generation_record else None,
            "validation_hof": None if validation_hof is None else {
                "candidate_id": validation_hof.candidate_id, "source_generation": validation_hof_generation,
                "genome_hash": validation_hof.brain.genome_hash, "validation_fitness": validation_hof.validation_fitness,
                "validation_median": validation_hof.validation_median, "validation_stddev": validation_hof.validation_stddev,
                "validation_seeds": [trial.seed for trial in validation_hof.validation_trials],
                "validation_trials": [asdict(trial) for trial in validation_hof.validation_trials],
            },
        }
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
                temp_path = Path(handle.name)
                np.savez(handle, metadata=np.frombuffer(canonical_json(metadata).encode(), dtype=np.uint8), **arrays)
                handle.flush(); os.fsync(handle.fileno())
            _, restored, restored_next, restored_generation, restored_seed, restored_hof, restored_hof_generation, _ = cls.load_population_state(temp_path, config)
            if [candidate.brain.genome_hash for candidate in restored] != [candidate.brain.genome_hash for candidate in population] or restored_next != next_candidate_id or restored_generation != generation or restored_seed != master_seed:
                raise ValueError("population checkpoint verification failed")
            if (validation_hof is None) != (restored_hof is None) or (validation_hof and restored_hof and validation_hof.brain.genome_hash != restored_hof.brain.genome_hash) or restored_hof_generation != validation_hof_generation:
                raise ValueError("validation hall-of-fame checkpoint verification failed")
            os.replace(temp_path, path)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()

    @classmethod
    def load_population(cls, path: Path, config: SimulationConfig, allow_config_mismatch: bool = False) -> tuple[Brain, list[Candidate], int, int, int]:
        champion, population, next_id, generation, seed, _, _, _ = cls.load_population_state(path, config, allow_config_mismatch)
        return champion, population, next_id, generation, seed

    @classmethod
    def load_population_state(cls, path: Path, config: SimulationConfig, allow_config_mismatch: bool = False) -> tuple[Brain, list[Candidate], int, int, int, Candidate | None, int | None, dict[str, object]]:
        champion, metadata = cls.load(path, config, allow_config_mismatch)
        required_metadata = {"master_seed", "generation", "next_candidate_id", "population"}
        if required_metadata.difference(metadata):
            raise ValueError("checkpoint does not contain resumable population state")
        if metadata.get("checkpoint_kind") != "evolution_state":
            raise ValueError("checkpoint is not resumable evolution state")
        generation = int(metadata["generation"])
        master_seed = int(metadata["master_seed"])
        generation_record = metadata.get("generation_record")
        if not isinstance(generation_record, dict) or int(generation_record.get("generation", -1)) != generation:
            raise ValueError("checkpoint generation record is missing or inconsistent")
        expected_record_hash = hashlib.sha256(canonical_json(generation_record).encode()).hexdigest()
        if metadata.get("generation_record_hash") != expected_record_hash:
            raise ValueError("checkpoint generation record hash mismatch")
        descriptors = metadata["population"]
        if not isinstance(descriptors, list) or len(descriptors) != config.population_size:
            raise ValueError("checkpoint population is invalid")
        population = []
        with np.load(path, allow_pickle=False) as data:
            for index, descriptor in enumerate(descriptors):
                names = [f"population_{index}_{name}" for name in cls.ARRAY_NAMES]
                if any(name not in data.files for name in names):
                    raise ValueError("checkpoint population arrays are incomplete")
                brain = Brain(*(np.array(data[name], copy=True) for name in names)); brain.validate(config)
                if descriptor.get("genome_hash") != brain.genome_hash:
                    raise ValueError("checkpoint population genome hash mismatch")
                mutation_data = descriptor.get("mutation")
                mutation = MutationRecord(**mutation_data) if mutation_data else None
                population.append(Candidate(int(descriptor["candidate_id"]), brain, str(descriptor["origin"]), descriptor.get("parent_candidate_id"), mutation))
            hof_data = metadata.get("validation_hof")
            validation_hof = None
            validation_hof_generation = None
            if hof_data is not None:
                hof_names = [f"validation_hof_{name}" for name in cls.ARRAY_NAMES]
                if any(name not in data.files for name in hof_names):
                    raise ValueError("checkpoint hall-of-fame arrays are incomplete")
                hof_brain = Brain(*(np.array(data[name], copy=True) for name in hof_names)); hof_brain.validate(config)
                if hof_data.get("genome_hash") != hof_brain.genome_hash:
                    raise ValueError("checkpoint hall-of-fame genome hash mismatch")
                validation_hof = Candidate(int(hof_data["candidate_id"]), hof_brain)
                validation_hof.validation_trials = [trial_summary_from_dict(item) for item in hof_data["validation_trials"]]
                validation_hof_generation = int(hof_data["source_generation"])
                expected_seeds = [stable_seed(master_seed, "fixed_validation", index, "environment") for index in range(config.validation_trials)]
                if len(validation_hof.validation_trials) != config.validation_trials or [trial.seed for trial in validation_hof.validation_trials] != expected_seeds or hof_data.get("validation_seeds") != expected_seeds:
                    raise ValueError("checkpoint hall-of-fame validation seed suite mismatch")
                if not math.isclose(float(hof_data["validation_fitness"]), validation_hof.validation_fitness, rel_tol=0, abs_tol=1e-15) or not math.isclose(float(hof_data["validation_median"]), validation_hof.validation_median, rel_tol=0, abs_tol=1e-15) or not math.isclose(float(hof_data["validation_stddev"]), validation_hof.validation_stddev, rel_tol=0, abs_tol=1e-15):
                    raise ValueError("checkpoint hall-of-fame aggregate mismatch")
                if validation_hof_generation < 0 or validation_hof_generation > generation:
                    raise ValueError("checkpoint hall-of-fame generation is invalid")
                record_best = generation_record.get("validation_best", {})
                if record_best.get("genome_hash") != hof_brain.genome_hash or int(record_best.get("source_generation", -1)) != validation_hof_generation:
                    raise ValueError("checkpoint generation record disagrees with hall of fame")
        return champion, population, int(metadata["next_candidate_id"]), generation, master_seed, validation_hof, validation_hof_generation, metadata

    @classmethod
    def set_workflow_state(cls, path: Path, config: SimulationConfig, workflow_state: str, audit_record_hash: str) -> None:
        cls._preflight_npz(path); temp_path: Path | None = None
        with np.load(path, allow_pickle=False) as data:
            arrays = {name: np.array(data[name], copy=True) for name in data.files if name != "metadata"}
            metadata = json.loads(bytes(np.asarray(data["metadata"], dtype=np.uint8)).decode())
        metadata["workflow_state"] = workflow_state; metadata["audit_record_hash"] = audit_record_hash
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
                temp_path = Path(handle.name); np.savez(handle, metadata=np.frombuffer(canonical_json(metadata).encode(), dtype=np.uint8), **arrays); handle.flush(); os.fsync(handle.fileno())
            cls._preflight_npz(temp_path); os.replace(temp_path, path)
        finally:
            if temp_path and temp_path.exists(): temp_path.unlink()


class EvolutionExperiment:
    def __init__(self, config: SimulationConfig, master_seed: int, checkpoint: Path, results: Path, resume: Path | None = None, allow_config_mismatch: bool = False, validation_checkpoint: Path | None = None, audit_results: Path | None = None, approval_digest: str = "UNRECORDED_TEST", experiment_id: str = "test", allow_released_for_audit: bool = False, execution: ExecutionConfig | None = None):
        self.config = config; self.master_seed = master_seed; self.checkpoint = checkpoint; self.results = results
        self.validation_checkpoint = validation_checkpoint or checkpoint.with_name("validation_hof_v35.npz")
        self.audit_results = audit_results or results.with_name(results.stem + "_audit.json")
        self.approval_digest = approval_digest; self.experiment_id = experiment_id
        self.execution = execution or ExecutionConfig()
        artifact_paths = [self.checkpoint.resolve(), self.validation_checkpoint.resolve(), self.results.resolve(), self.audit_results.resolve()]
        if len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("evolution state, validation hall of fame, results, and audit must use distinct paths")
        for path in (self.checkpoint, self.validation_checkpoint, self.results, self.audit_results):
            if path.is_symlink() or path.parent.is_symlink():
                raise ValueError(f"artifact symlinks/reparse aliases are not allowed: {path}")
        self.mutation_policy = MutationPolicy(); self.next_candidate_id = 1; self.start_generation = 0
        self._executor: ProcessPoolExecutor | None = None
        self.previous_record_hash = "0" * 64
        self.validation_hof: Candidate | None = None
        self.validation_hof_generation: int | None = None
        self.workflow_state = "NEW"
        self.planned_generation_count = config.generations
        if resume:
            _, self.population, self.next_candidate_id, completed_generation, saved_seed, self.validation_hof, self.validation_hof_generation, metadata = CheckpointRepository.load_population_state(resume, config, False)
            if saved_seed != master_seed:
                raise ValueError(f"checkpoint master seed {saved_seed} does not match requested seed {master_seed}")
            if metadata.get("approval_digest") != approval_digest or metadata.get("experiment_id") != experiment_id:
                raise ValueError("checkpoint approval or experiment identity mismatch")
            if metadata.get("engine_fingerprint") != self.execution.engine_fingerprint:
                raise ValueError("checkpoint engine fingerprint mismatch")
            self.workflow_state = str(metadata.get("workflow_state", ""))
            self.planned_generation_count = int(metadata.get("planned_generation_count", metadata["config"]["generations"]))
            if self.workflow_state == "RELEASED" and not allow_released_for_audit:
                raise ValueError("experiment is RELEASED; continuation is prohibited")
            if self.workflow_state not in {"TRAINING_COMMITTED", "RELEASED"}:
                raise ValueError(f"unsupported workflow state: {self.workflow_state}")
            self.start_generation = completed_generation + 1
            if metadata.get("generation_record"):
                self._ensure_result(metadata["generation_record"])
                self.previous_record_hash = str(metadata["generation_record"].get("record_hash", self.previous_record_hash))
            if self.validation_hof is not None:
                CheckpointRepository.save(self.validation_checkpoint, self.validation_hof, self.config, self.master_seed, self.validation_hof_generation, "validation_hof", self.approval_digest, self.experiment_id)
        else:
            occupied = [path for path in (self.checkpoint, self.validation_checkpoint, self.results, self.audit_results) if path.exists() and path.stat().st_size > 0]
            if occupied:
                raise ValueError("v35 artifacts already exist; use continue or choose a distinct experiment ID: " + ", ".join(str(path) for path in occupied))
            self.population = self._founders(None)
            self.workflow_state = "APPROVED"

    def _random_brain(self, *parts: object) -> Brain:
        return Brain.random(self.config, np.random.default_rng(stable_seed(self.master_seed, *parts)))

    def _candidate(self, brain: Brain, origin: str, parent: int | None = None, mutation: MutationRecord | None = None) -> Candidate:
        candidate = Candidate(self.next_candidate_id, brain, origin, parent, mutation); self.next_candidate_id += 1; return candidate

    def _founders(self, champion: Brain | None) -> list[Candidate]:
        if champion is None:
            return [self._candidate(self._random_brain("founder", index), "random") for index in range(self.config.population_size)]
        founders = [self._candidate(champion.copy(), "elite") for _ in range(self.config.elite_count)]
        for index in range(self.config.child_count):
            child, record = self.mutation_policy.mutate(champion, self.config, np.random.default_rng(stable_seed(self.master_seed, "founder_variant", index)))
            founders.append(self._candidate(child, "champion_variant", mutation=record))
        for index in range(self.config.immigrant_count):
            founders.append(self._candidate(self._random_brain("immigrant", index), "immigrant"))
        return founders

    def _trial_seed(self, generation: int, trial: int) -> int:
        return stable_seed(self.master_seed, "generation", generation, "trial", trial, "environment")

    def _task(self, ordinal: int, generation: int, candidate: Candidate, profile: str, seed: int) -> TrialTask:
        arrays = tuple(np.array(array, dtype=np.float64, copy=True) for array in candidate.brain.arrays())
        return TrialTask(ordinal, generation, candidate.candidate_id, profile, seed, self.config, arrays, self.execution.engine_fingerprint, self.execution.kernel_backend, self.execution.inference_backend)

    def _run_tasks(self, tasks: list[TrialTask]) -> list[TrialResult]:
        if len(tasks) > 4096: raise ValueError("evaluation group exceeds task limit")
        started = time.perf_counter()
        label = f"generation={tasks[0].generation} profile={tasks[0].profile}" if tasks else "empty"
        print(f"worker_group_start {label} tasks={len(tasks)} workers={self.execution.workers}", flush=True)
        if self.execution.workers == 1:
            results = [run_trial_task(task) for task in tasks]
        else:
            if self._executor is None:
                context = multiprocessing.get_context(self.execution.start_method)
                self._executor = ProcessPoolExecutor(max_workers=self.execution.workers, mp_context=context,
                                                     initializer=initialize_trial_worker)
            try:
                results = list(self._executor.map(run_trial_task, tasks, chunksize=1))
            except BaseException as error:
                self._executor.shutdown(wait=False, cancel_futures=True); self._executor = None
                if isinstance(error, KeyboardInterrupt): raise
                kind = "broken process pool" if isinstance(error, BrokenProcessPool) else type(error).__name__
                detail = str(error).strip() or repr(error)
                remote = "".join(traceback.format_exception(error)).strip()
                raise ValueError(f"worker evaluation group failed ({kind}: {detail}); no generation was committed\n{remote}") from error
        results.sort(key=lambda result: result.ordinal)
        if [result.ordinal for result in results] != list(range(len(tasks))): raise ValueError("worker results are missing, duplicated, or out of order")
        for task, result in zip(tasks, results):
            expected_hash = Brain(*(np.array(array, copy=False) for array in task.brain_arrays)).genome_hash
            if (result.generation, result.candidate_id, result.profile, result.seed, result.genome_hash, result.engine_fingerprint) != (task.generation, task.candidate_id, task.profile, task.seed, expected_hash, task.engine_fingerprint): raise ValueError("worker result provenance mismatch")
            validate_trial_summary(result.summary, task.config, task.candidate_id, task.seed, task.profile)
        print(f"worker_group_complete {label} tasks={len(tasks)} seconds={time.perf_counter() - started:.3f}", flush=True)
        return results

    def _shutdown_executor(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=False); self._executor = None

    def _challenge_seed(self, generation: int, trial: int) -> int:
        return stable_seed(self.master_seed, "selection_challenge", generation, trial, "environment")

    def _validation_seed(self, trial: int) -> int:
        """Fixed across every generation so validation scores are longitudinally comparable."""
        return stable_seed(self.master_seed, "fixed_validation", trial, "environment")

    def _audit_seed(self, trial: int) -> int:
        return stable_seed(self.master_seed, "terminal_audit", trial, "environment")

    def _write_terminal_audit(self) -> dict[str, object]:
        assert self.validation_hof is not None and self.validation_hof_generation is not None
        def validate(existing: dict[str, object]) -> dict[str, object]:
            claimed = existing.get("record_hash"); unhashed = dict(existing); unhashed.pop("record_hash", None)
            if claimed != hashlib.sha256(canonical_json(unhashed).encode()).hexdigest(): raise ValueError("sealed audit record hash mismatch")
            expected_identity = (self.validation_hof.brain.genome_hash, self.config.fingerprint, self.master_seed, self.approval_digest, self.experiment_id, self.previous_record_hash)
            actual_identity = (existing.get("genome_hash"), existing.get("config_hash"), existing.get("master_seed"), existing.get("approval_digest"), existing.get("experiment_id"), existing.get("results_chain_head"))
            if actual_identity != expected_identity or existing.get("engine_fingerprint") != self.execution.engine_fingerprint or existing.get("suite_id") != "v35-sealed-audit-1" or existing.get("audit_seeds") != [self._audit_seed(index) for index in range(self.config.audit_trials)]: raise ValueError("sealed audit provenance mismatch")
            trials_data = existing.get("trials");
            if not isinstance(trials_data, list) or len(trials_data) != self.config.audit_trials: raise ValueError("sealed audit trial count mismatch")
            expected_seeds = [self._audit_seed(index) for index in range(self.config.audit_trials)]
            for index, item in enumerate(trials_data):
                if not isinstance(item, dict): raise ValueError("sealed audit trial schema is invalid")
                try:
                    trial = trial_summary_from_dict(item)
                    validate_trial_summary(trial, self.config, self.validation_hof.candidate_id, expected_seeds[index], "audit")
                except (KeyError, TypeError, ValueError, OverflowError) as error:
                    raise ValueError("sealed audit trial semantics are invalid") from error
            scores = [float(item["fitness"]) for item in trials_data]
            expected_stddev = pstdev(scores) if len(scores) > 1 else 0.0
            if not math.isclose(float(existing["audit_fitness"]), .75 * median(scores) + .25 * min(scores), abs_tol=1e-15) or not math.isclose(float(existing["audit_median"]), median(scores), abs_tol=1e-15) or not math.isclose(float(existing["audit_stddev"]), expected_stddev, abs_tol=1e-15): raise ValueError("sealed audit aggregate mismatch")
            return existing

        self.audit_results.parent.mkdir(parents=True, exist_ok=True); lock = self.audit_results.with_suffix(self.audit_results.suffix + ".lock")
        try:
            with lock.open("x", encoding="utf-8") as handle: handle.write(self.experiment_id)
        except FileExistsError as error:
            raise ValueError("audit finalization is already in progress") from error
        temp_path: Path | None = None
        try:
            if self.audit_results.exists(): return validate(json.loads(self.audit_results.read_text(encoding="utf-8")))
            tasks = [self._task(index, -1, self.validation_hof, "audit", self._audit_seed(index)) for index in range(self.config.audit_trials)]
            trials = [result.summary for result in self._run_tasks(tasks)]
            scores = [trial.fitness for trial in trials]
            summary = {"schema_version": SCHEMA_VERSION, "app_version": APP_VERSION, "master_seed": self.master_seed, "config_hash": self.config.fingerprint, "approval_digest": self.approval_digest, "experiment_id": self.experiment_id, "engine_fingerprint": self.execution.engine_fingerprint, "execution": self.execution.evidence_contract, "validation_hof_candidate_id": self.validation_hof.candidate_id, "validation_hof_generation": self.validation_hof_generation, "genome_hash": self.validation_hof.brain.genome_hash, "results_chain_head": self.previous_record_hash, "consumed": True, "suite_id": "v35-sealed-audit-1", "audit_seeds": [self._audit_seed(index) for index in range(self.config.audit_trials)], "audit_fitness": .75 * median(scores) + .25 * min(scores), "audit_median": median(scores), "audit_stddev": pstdev(scores) if len(scores) > 1 else 0.0, "trials": [asdict(trial) for trial in trials]}
            summary["record_hash"] = hashlib.sha256(canonical_json(summary).encode()).hexdigest()
            with tempfile.NamedTemporaryFile(dir=self.audit_results.parent, prefix=self.audit_results.name + ".", suffix=".tmp", mode="w", encoding="utf-8", delete=False) as handle:
                temp_path = Path(handle.name); handle.write(canonical_json(summary) + "\n"); handle.flush(); os.fsync(handle.fileno())
            os.replace(temp_path, self.audit_results); return validate(summary)
        finally:
            if temp_path and temp_path.exists(): temp_path.unlink()
            if lock.exists(): lock.unlink()

    def finalize_audit(self) -> dict[str, object]:
        if self.validation_hof is None:
            raise ValueError("cannot finalize audit without a validation hall of fame")
        try:
            return self._write_terminal_audit()
        finally:
            self._shutdown_executor()

    def evaluate_generation(self, generation: int) -> None:
        tasks: list[TrialTask] = []
        for candidate_index, candidate in enumerate(self.population, 1):
            print(f"progress generation={generation} phase=selection candidate={candidate_index}/{len(self.population)}", flush=True)
            candidate.trials = []
            for trial in range(self.config.trials):
                tasks.append(self._task(len(tasks), generation, candidate, "standard", self._trial_seed(generation, trial)))
            for trial in range(self.config.challenge_trials):
                tasks.append(self._task(len(tasks), generation, candidate, "water_fire_challenge", self._challenge_seed(generation, trial)))
        by_id = {candidate.candidate_id: candidate for candidate in self.population}
        for result in self._run_tasks(tasks): by_id[result.candidate_id].trials.append(result.summary)

    def evaluate_validation(self, candidate: Candidate) -> None:
        print(f"progress phase=validation candidate={candidate.candidate_id} trials={self.config.validation_trials}", flush=True)
        tasks = [self._task(index, -1, candidate, "validation", self._validation_seed(index)) for index in range(self.config.validation_trials)]
        candidate.validation_trials = [result.summary for result in self._run_tasks(tasks)]

    @staticmethod
    def _validation_key(candidate: Candidate) -> tuple[float, float, float, str]:
        return candidate.validation_fitness, candidate.validation_median, -candidate.validation_stddev, "".join(chr(255 - ord(ch)) for ch in candidate.brain.genome_hash)

    def _update_validation_hof(self, challenger: Candidate, generation: int) -> bool:
        incumbent = self.validation_hof
        improved = incumbent is None or (
            challenger.validation_fitness > incumbent.validation_fitness
            or (challenger.validation_fitness == incumbent.validation_fitness and challenger.validation_median > incumbent.validation_median)
            or (challenger.validation_fitness == incumbent.validation_fitness and challenger.validation_median == incumbent.validation_median and challenger.validation_stddev < incumbent.validation_stddev)
            or (challenger.validation_fitness == incumbent.validation_fitness and challenger.validation_median == incumbent.validation_median and challenger.validation_stddev == incumbent.validation_stddev and challenger.brain.genome_hash < incumbent.brain.genome_hash)
        )
        if improved:
            self.validation_hof = Candidate(
                challenger.candidate_id, challenger.brain.copy(), "validation_hof",
                challenger.parent_candidate_id, challenger.mutation,
                trials=list(challenger.trials), validation_trials=list(challenger.validation_trials),
            )
            self.validation_hof_generation = generation
        return improved

    @staticmethod
    def rank(population: Sequence[Candidate]) -> list[Candidate]:
        return sorted(population, key=lambda candidate: (-candidate.selection_fitness, candidate.early_extinction_rate, -candidate.median_fitness, candidate.fitness_stddev, candidate.brain.genome_hash, candidate.candidate_id))

    def _next_generation(self, ranked: Sequence[Candidate], generation: int) -> list[Candidate]:
        result = [self._candidate(candidate.brain.copy(), "elite", candidate.candidate_id) for candidate in ranked[:self.config.elite_count]]
        selection_rng = np.random.default_rng(stable_seed(self.master_seed, "selection", generation))
        for child_index in range(self.config.child_count):
            contestants = selection_rng.choice(len(ranked), min(self.config.tournament_size, len(ranked)), replace=False)
            parent = ranked[min(int(index) for index in contestants)]
            child, record = self.mutation_policy.mutate(parent.brain, self.config, np.random.default_rng(stable_seed(self.master_seed, "mutation", generation, child_index)))
            result.append(self._candidate(child, "mutated_child", parent.candidate_id, record))
        for index in range(self.config.immigrant_count):
            result.append(self._candidate(self._random_brain("immigrant", generation, index), "immigrant"))
        return result

    def _generation_record(self, generation: int, ranked: Sequence[Candidate], improved: bool) -> dict[str, object]:
        hof = self.validation_hof
        assert hof is not None and self.validation_hof_generation is not None
        validation_trials = ranked[0].validation_trials
        fire_damages = [float(trial.metrics["lineage_fire_damage"]) for trial in validation_trials]
        avoidance = [float(trial.components["damage_avoidance"]) for trial in validation_trials]
        record = {
            "schema_version": SCHEMA_VERSION, "app_version": APP_VERSION, "generation": generation,
            "master_seed": self.master_seed, "config_hash": self.config.fingerprint,
            "approval_digest": self.approval_digest, "experiment_id": self.experiment_id,
            "engine_fingerprint": self.execution.engine_fingerprint,
            "execution": self.execution.evidence_contract,
            "previous_record_hash": self.previous_record_hash,
            "trial_seeds": [self._trial_seed(generation, trial) for trial in range(self.config.trials)],
            "challenge_seeds": [self._challenge_seed(generation, trial) for trial in range(self.config.challenge_trials)],
            "challenge_policy": {"profile": "water_fire_challenge", "generator_version": 1, "water_fraction": 0.25, "water_spawn_rate_multiplier": 0.5, "additional_fire": 10, "near_fire_radius": 20.0},
            "validation_seeds": [self._validation_seed(trial) for trial in range(self.config.validation_trials)],
            "champion_validation": {
                "candidate_id": ranked[0].candidate_id, "fitness": ranked[0].validation_fitness,
                "median": ranked[0].validation_median, "stddev": ranked[0].validation_stddev,
                "mean_fire_damage": sum(fire_damages) / len(fire_damages),
                "zero_fire_damage_rate": sum(value == 0 for value in fire_damages) / len(fire_damages),
                "mean_damage_avoidance": sum(avoidance) / len(avoidance),
                "trials": [asdict(trial) for trial in validation_trials],
            },
            "validation_best": {
                "candidate_id": hof.candidate_id, "source_generation": self.validation_hof_generation,
                "genome_hash": hof.brain.genome_hash, "fitness": hof.validation_fitness,
                "median": hof.validation_median, "stddev": hof.validation_stddev,
            },
            "validation_best_improved": improved,
            "validation_delta": ranked[0].validation_fitness - hof.validation_fitness,
            "candidates": [{"candidate_id": c.candidate_id, "origin": c.origin, "parent_candidate_id": c.parent_candidate_id, "genome_hash": c.brain.genome_hash, "selection_fitness": c.selection_fitness, "median_fitness": c.median_fitness, "fitness_stddev": c.fitness_stddev, "early_extinction_rate": c.early_extinction_rate, "mutation": asdict(c.mutation) if c.mutation else None, "trials": [asdict(t) for t in c.trials]} for c in ranked],
        }
        record["record_hash"] = hashlib.sha256((self.previous_record_hash + canonical_json(record)).encode()).hexdigest()
        return record

    def _ensure_result(self, record: dict[str, object]) -> None:
        self.results.parent.mkdir(parents=True, exist_ok=True)
        if self.results.is_symlink() or self.results.parent.is_symlink():
            raise ValueError("results path became a symlink/reparse alias")
        generation = int(record["generation"])
        existing_generations: list[int] = []
        matching_record = False
        chain_head = "0" * 64
        if self.results.exists():
            if self.results.stat().st_size > 128 * 1024 * 1024:
                raise ValueError("results file exceeds governed size limit")
            with self.results.open("r", encoding="utf-8") as results_handle:
              for line_number, line in enumerate(results_handle, 1):
                if len(line) > 16 * 1024 * 1024 or line_number > 10_000:
                    raise ValueError("results line/generation limit exceeded")
                try:
                    existing = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"results file has invalid JSON on line {line_number}") from error
                if existing.get("schema_version") != SCHEMA_VERSION or existing.get("config_hash") != self.config.fingerprint or existing.get("master_seed") != self.master_seed or existing.get("approval_digest") != self.approval_digest or existing.get("experiment_id") != self.experiment_id:
                    raise ValueError("results file belongs to a different experiment")
                claimed_hash = existing.get("record_hash")
                unhashed = dict(existing); unhashed.pop("record_hash", None)
                expected_hash = hashlib.sha256((chain_head + canonical_json(unhashed)).encode()).hexdigest()
                if existing.get("previous_record_hash") != chain_head or claimed_hash != expected_hash:
                    raise ValueError(f"results hash chain failed on generation {existing.get('generation')}")
                chain_head = str(claimed_hash)
                existing_generations.append(int(existing["generation"]))
                if existing.get("generation") == generation:
                    if canonical_json(existing) == canonical_json(record):
                        matching_record = True
                    else:
                        raise ValueError(f"results generation {generation} conflicts with authoritative checkpoint")
        if existing_generations:
            if existing_generations != list(range(existing_generations[-1] + 1)):
                raise ValueError("results file contains gaps, duplicates, or out-of-order generations")
            if existing_generations[-1] > generation:
                raise ValueError("results file is ahead of the authoritative evolution-state checkpoint")
            if matching_record:
                return
            if generation != existing_generations[-1] + 1:
                raise ValueError(f"cannot append generation {generation} after generation {existing_generations[-1]}")
        elif generation != 0:
            raise ValueError(f"results history before generation {generation} is missing and cannot be reconstructed")
        with self.results.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(record) + "\n"); handle.flush(); os.fsync(handle.fileno())

    def _run_impl(self) -> ExperimentOutcome:
        champion = self.population[0]
        for generation in range(self.start_generation, self.start_generation + self.config.generations):
            self.evaluate_generation(generation)
            ranked = self.rank(self.population); champion = ranked[0]
            improved = False
            for validation_candidate in ranked[:min(3, len(ranked))]:
                self.evaluate_validation(validation_candidate)
                improved = self._update_validation_hof(validation_candidate, generation) or improved
            record = self._generation_record(generation, ranked, improved)
            next_population = self._next_generation(ranked, generation + 1)
            CheckpointRepository.save_population(self.checkpoint, champion, next_population, self.config, self.master_seed, generation, self.next_candidate_id, self.validation_hof, self.validation_hof_generation, record, self.approval_digest, self.experiment_id, self.execution, self.planned_generation_count)
            self._ensure_result(record)
            self.previous_record_hash = str(record["record_hash"])
            CheckpointRepository.save(self.validation_checkpoint, self.validation_hof, self.config, self.master_seed, self.validation_hof_generation, "validation_hof", self.approval_digest, self.experiment_id)
            print(
                f"generation={generation} champion={champion.candidate_id} "
                f"selection_fitness={champion.selection_fitness:.6f} "
                f"current_validation={champion.validation_fitness:.6f} "
                f"best_validation={self.validation_hof.validation_fitness:.6f} "
                f"best_generation={self.validation_hof_generation} improved={str(improved).lower()}"
            )
            self.population = next_population
        assert self.validation_hof is not None and self.validation_hof_generation is not None
        self._shutdown_executor()
        return ExperimentOutcome(champion.candidate_id, self.validation_hof.candidate_id, self.validation_hof_generation, "TRAINING_COMMITTED", str(self.checkpoint), str(self.validation_checkpoint), str(self.results), "NOT_RUN")

    def run(self) -> ExperimentOutcome:
        try:
            return self._run_impl()
        finally:
            self._shutdown_executor()


def render_trial(config: SimulationConfig, brain: Brain, seed: int, uncapped: bool = False) -> TrialSummary:
    import pygame
    pygame.init(); screen = pygame.display.set_mode((config.width + 325, config.height)); clock = pygame.time.Clock(); font = pygame.font.SysFont(None, 22)
    simulation = Simulation(config, brain, seed); paused = False; step_once = False; show_hud = True; speed_multiplier = 1
    try:
        reason = None
        while reason is None:
            for event in pygame.event.get():
                if event.type == pygame.QUIT or (event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE):
                    fitness, components = simulation.fitness()
                    return TrialSummary(0, seed, TerminationReason.USER_QUIT.value, simulation.frame, len(simulation.creatures), simulation.peak_population, fitness, components, simulation.metrics.raw(), simulation.state_hash())
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_SPACE: paused = not paused
                    elif event.key == pygame.K_PERIOD: step_once = True
                    elif event.key == pygame.K_h: show_hud = not show_hud
                    elif event.key == pygame.K_LEFTBRACKET: speed_multiplier = max(1, speed_multiplier // 2)
                    elif event.key == pygame.K_RIGHTBRACKET: speed_multiplier = min(16, speed_multiplier * 2)
                    elif event.key == pygame.K_r: simulation = Simulation(config, brain, seed); reason = None
            if not paused or step_once:
                for _ in range(speed_multiplier if not paused else 1):
                    reason = simulation.step()
                    if reason is not None: break
                step_once = False
            screen.fill((0, 0, 0))
            for kind, color, radius in (("food", (0, 190, 120), 3), ("water", (70, 130, 255), 3), ("fire", (240, 120, 30), 5)):
                for resource in simulation.resources[kind]: pygame.draw.circle(screen, color, (int(resource.x), int(resource.y)), radius)
            for creature in simulation.creatures: pygame.draw.circle(screen, (255, 255, 255), (int(creature.x), int(creature.y)), 4)
            panel_x = config.width + 10; founder = next((c for c in simulation.creatures if c.creature_id == 1), simulation.creatures[0] if simulation.creatures else None)
            lines = [f"v35 {simulation.profile} frame {simulation.frame}/{config.max_frames}", f"population {len(simulation.creatures)}/{config.lineage_cap} {'PAUSED' if paused else ''}", f"food {len(simulation.resources['food'])} water {len(simulation.resources['water'])}", f"speed x{speed_multiplier}", "Esc quit | Space pause | . step", "[ ] speed | R restart | H HUD"]
            if founder: lines += [f"energy {founder.energy:.1f} speed {founder.speed:.2f}", f"hunger {founder.hunger:.2f} thirst {founder.thirst:.2f}", f"outputs {tuple(round(v,2) for v in founder.last_outputs)}"]
            if show_hud and founder: lines += [f"{name}: {value:+.2f}" for name, value in zip(SENSOR_LABELS, founder.last_inputs)]
            for index, text in enumerate(lines): screen.blit(font.render(text, True, (240, 240, 240)), (panel_x, 10 + index * 22))
            pygame.display.flip()
            if not uncapped: clock.tick(config.fps)
        fitness, components = simulation.fitness()
        return TrialSummary(0, seed, reason.value, simulation.frame, len(simulation.creatures), simulation.peak_population, fitness, components, simulation.metrics.raw(), simulation.state_hash())
    finally:
        pygame.quit()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Blast_Pit v35 accelerated governed evolutionary simulator")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--experiment-id", required=True)
    common.add_argument("--approval-record", type=Path, default=Path(__file__).with_name("approval_v35.json"))
    common.add_argument("--seed", type=int, default=20260710)
    common.add_argument("--artifact-root", type=Path, default=Path(__file__).with_name("artifacts") / "v35")
    common.add_argument("--workers", type=int, default=1, help="spawn workers; 1 is serial reference")
    common.add_argument("--engine", choices=("python", "numba"), default="python")
    common.add_argument("--inference", choices=("scalar", "batch"), default="scalar")

    train = sub.add_parser("train", parents=[common], help="start a fresh approved experiment")
    train.add_argument("--generations", type=int, default=50); train.add_argument("--trials", type=int, default=5)
    train.add_argument("--challenge-trials", type=int, default=2); train.add_argument("--validation-trials", type=int, default=7)
    train.add_argument("--audit-trials", type=int, default=11); train.add_argument("--max-frames", type=int, default=6000)
    train.add_argument("--work-budget", type=int, default=100_000_000)

    cont = sub.add_parser("continue", parents=[common], help="continue committed evolution state")
    cont.add_argument("--resume", type=Path, required=True); cont.add_argument("--additional-generations", type=int, required=True)
    cont.add_argument("--work-budget", type=int, default=100_000_000)

    status = sub.add_parser("status", help="show concise checkpoint workflow and recovery status")
    status.add_argument("--checkpoint", type=Path, required=True)

    inspect = sub.add_parser("inspect", help="inspect complete checkpoint metadata without executing a brain")
    inspect.add_argument("--checkpoint", type=Path, required=True)

    visualize = sub.add_parser("visualize", help="visualize a checkpoint using its behavior configuration")
    visualize.add_argument("--checkpoint", type=Path, required=True); visualize.add_argument("--fps", type=int, default=60)
    visualize.add_argument("--uncapped", action="store_true"); visualize.add_argument("--seed", type=int, default=20260710)

    audit = sub.add_parser("audit", parents=[common], help="consume the sealed audit suite exactly once")
    audit.add_argument("--resume", type=Path, required=True); audit.add_argument("--work-budget", type=int, default=10_000_000)
    return parser


def _raw_checkpoint_metadata(path: Path) -> dict[str, object]:
    CheckpointRepository._preflight_npz(path)
    with np.load(path, allow_pickle=False) as data:
        raw = np.asarray(data["metadata"])
        if raw.dtype != np.uint8 or raw.ndim != 1 or raw.nbytes > 8 * 1024 * 1024:
            raise ValueError("checkpoint metadata encoding is invalid")
        return json.loads(bytes(raw).decode())


def _checkpoint_status(metadata: dict[str, object], checkpoint: Path) -> dict[str, object]:
    """Return the bounded operator-facing subset of checkpoint metadata."""
    generation = int(metadata["generation"])
    planned = int(metadata.get("planned_generation_count", dict(metadata["config"])["generations"]))
    completed = generation + 1
    return {
        "checkpoint": str(checkpoint.resolve()),
        "experiment_id": str(metadata["experiment_id"]),
        "workflow_state": str(metadata["workflow_state"]),
        "last_committed_generation": generation,
        "completed_generations": completed,
        "planned_generations": planned,
        "remaining_generations": max(0, planned - completed),
        "master_seed": int(metadata["master_seed"]),
        "engine_fingerprint": str(metadata["engine_fingerprint"]),
        "execution": dict(metadata["execution"]),
    }


def _occupied_training_error(state: Path, occupied: Sequence[Path]) -> ValueError:
    detail = ", ".join(str(path) for path in occupied)
    if state.is_file():
        try:
            status = _checkpoint_status(_raw_checkpoint_metadata(state), state)
            remaining = int(status["remaining_generations"])
            recovery = (
                f"committed generation={status['last_committed_generation']} "
                f"workflow_state={status['workflow_state']} remaining={remaining}; "
                f"use continue --experiment-id {status['experiment_id']} --resume {state} "
                f"--additional-generations {remaining} --seed {status['master_seed']} "
                f"--engine {status['execution']['kernel_backend']} "
                f"--inference {status['execution']['inference_backend']}"
            )
            return ValueError(f"v35 artifacts already exist; fresh train is prohibited: {detail}; {recovery}")
        except (ValueError, OSError, json.JSONDecodeError, KeyError, TypeError):
            pass
    return ValueError(f"v35 artifacts already exist; fresh train is prohibited; inspect retained artifacts before recovery: {detail}")


def _artifact_paths(root: Path, experiment_id: str) -> tuple[Path, Path, Path, Path]:
    if not experiment_id.replace("-", "").replace("_", "").isalnum():
        raise ValueError("experiment-id may contain only letters, digits, hyphen, and underscore")
    base = (root / experiment_id).resolve(); root_resolved = root.resolve()
    if os.path.commonpath((str(base), str(root_resolved))) != str(root_resolved):
        raise ValueError("experiment artifact path escapes artifact root")
    return base / "evolution_state_v35.npz", base / "validation_hof_v35.npz", base / "generations_v35.jsonl", base / "sealed_audit_v35.json"


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", mode="w", encoding="utf-8", delete=False) as handle:
            temp_path = Path(handle.name); handle.write(canonical_json(value) + "\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and temp_path.exists(): temp_path.unlink()


def _file_evidence(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""): digest.update(block)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def write_experiment_context(base: Path, approval: dict[str, object], approval_digest: str, config: SimulationConfig, experiment_id: str, master_seed: int, execution: ExecutionConfig | None = None) -> None:
    _write_json_atomic(base / "approval_bound_v35.json", {"record": approval, "sha256": approval_digest})
    effective = execution or ExecutionConfig()
    _write_json_atomic(base / "effective_config_v35.json", {"experiment_id": experiment_id, "config": asdict(config), "config_hash": config.fingerprint, "execution": asdict(effective), "engine_fingerprint": effective.engine_fingerprint, "numba_available": NUMBA_AVAILABLE, "numba_version": NUMBA_VERSION, "numpy_version": np.__version__})
    _write_json_atomic(base / "seed_suites_v35.json", {
        "experiment_id": experiment_id, "master_seed": master_seed,
        "selection_namespace": "generation:{g}:trial:{t}:environment",
        "challenge_namespace": "selection_challenge:{g}:{t}:environment",
        "validation_namespace": "fixed_validation:{t}:environment",
        "audit_namespace": "terminal_audit:{t}:environment", "audit_consumption": "explicit_one_shot",
    })
    _write_json_atomic(base / "challenge_registry_v35.json", {"generator_version": 1, "profile": "water_fire_challenge", "source": "phenotype policy, not v32 audit seeds", "water_fraction": 0.25, "water_spawn_multiplier": 0.5, "additional_fire": 10, "near_fire_radius": 20.0})


def write_release_manifest(base: Path, experiment_id: str, config: SimulationConfig, approval_digest: str) -> Path:
    names = ["evolution_state_v35.npz", "validation_hof_v35.npz", "generations_v35.jsonl", "sealed_audit_v35.json", "approval_bound_v35.json", "effective_config_v35.json", "seed_suites_v35.json", "challenge_registry_v35.json"]
    root = Path(__file__).parent
    docs = [root / "README.md", root / "SECURITY.md", root / "CHANGELOG.md", root / "docs" / "OPERATIONS.md", root / "docs" / "EXPERIMENT_DESIGN.md", root / "docs" / "ARTIFACT_SCHEMA.md", root / "docs" / "EVIDENCE.md", root / "docs" / "TESTING.md", root / "docs" / "FINAL_QA.md", root / "test_tmp_2d_simulator_v35.py", root / "benchmark_tmp_2d_simulator_v35.py"]
    files = []
    for name in names:
        path = base / name
        if not path.is_file(): raise ValueError(f"release evidence is missing required artifact: {name}")
        evidence = _file_evidence(path); evidence["path"] = name; files.append(evidence)
    for path in docs:
        if not path.is_file(): raise ValueError(f"release evidence is missing required documentation: {path.name}")
        evidence = _file_evidence(path); evidence["path"] = str(path.relative_to(root)).replace("\\", "/"); files.append(evidence)
    audit_record = json.loads((base / "sealed_audit_v35.json").read_text(encoding="utf-8"))
    state_metadata = _raw_checkpoint_metadata(base / "evolution_state_v35.npz")
    manifest = {
        "schema_version": "evidence.v1", "app_version": APP_VERSION, "experiment_id": experiment_id,
        "approval_digest": approval_digest, "config_hash": config.fingerprint, "workflow_state": "RELEASED",
        "generation_chain_head": state_metadata["generation_record"]["record_hash"],
        "validation_hof_genome_hash": audit_record["genome_hash"], "audit_record_hash": audit_record["record_hash"],
        "audit_suite_id": audit_record["suite_id"],
        "source": {**_file_evidence(Path(__file__)), "path": Path(__file__).name}, "files": files,
        "environment": {"python": sys.version, "platform": platform.platform(), "numpy": np.__version__, "pygame": installed_version("pygame")},
    }
    path = base / "manifest_v35.json"; _write_json_atomic(path, manifest); return path


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            print(canonical_json(_checkpoint_status(_raw_checkpoint_metadata(args.checkpoint), args.checkpoint))); return 0
        if args.command == "inspect":
            print(canonical_json(_raw_checkpoint_metadata(args.checkpoint))); return 0
        if args.command == "visualize":
            metadata = _raw_checkpoint_metadata(args.checkpoint); config = SimulationConfig(**metadata["config"])
            config = SimulationConfig(**{**asdict(config), "fps": args.fps})
            brain = CheckpointRepository.load(args.checkpoint, config)[0]
            summary = render_trial(config, brain, stable_seed(args.seed, "visualize"), args.uncapped)
            print(canonical_json(asdict(summary))); return 0

        action = "finalize_audit" if args.command == "audit" else "local_training"
        approval_record, approval_digest = load_approval_record(args.approval_record, action)
        execution = ExecutionConfig(args.workers, args.engine, args.inference)
        state, hof, results, audit_path = _artifact_paths(args.artifact_root, args.experiment_id)
        if args.command == "train":
            if not (1 <= args.generations <= 10_000 and 1 <= args.max_frames <= 1_000_000 and 1 <= args.trials <= 32 and 1 <= args.challenge_trials <= 16 and 1 <= args.validation_trials <= 32 and 1 <= args.audit_trials <= 64):
                raise ValueError("training arguments exceed governed limits")
            estimated = args.generations * (16 * (args.trials + args.challenge_trials) + 3 * args.validation_trials) * args.max_frames
            if estimated > args.work_budget:
                raise ValueError(f"estimated {estimated} simulation frames exceed work budget {args.work_budget}")
            config = SimulationConfig(generations=args.generations, trials=args.trials, challenge_trials=args.challenge_trials, validation_trials=args.validation_trials, audit_trials=args.audit_trials, max_frames=args.max_frames)
            print(f"preflight experiment={args.experiment_id} generations=0..{args.generations-1} estimated_frames={estimated} state={state.resolve()}", flush=True)
            print(f"execution workers={execution.workers} engine={execution.kernel_backend} inference={execution.inference_backend} fingerprint={execution.engine_fingerprint}", flush=True)
            occupied = [path for path in (state, hof, results, audit_path) if path.exists() and path.stat().st_size > 0]
            if occupied:
                raise _occupied_training_error(state, occupied)
            experiment = EvolutionExperiment(config, args.seed, state, results, validation_checkpoint=hof, audit_results=audit_path, approval_digest=approval_digest, experiment_id=args.experiment_id, execution=execution)
            write_experiment_context(state.parent, approval_record, approval_digest, config, args.experiment_id, args.seed, execution)
            experiment.run()
            print(f"training_complete audit_status=NOT_RUN resume={state}", flush=True); return 0
        metadata = _raw_checkpoint_metadata(args.resume); config_data = dict(metadata["config"])
        if args.resume.resolve() != state.resolve():
            raise ValueError(f"resume path must be the governed evolution state: {state}")
        if args.command == "continue":
            if not 1 <= args.additional_generations <= 10_000:
                raise ValueError("additional-generations must be between 1 and 10000")
            config_data["generations"] = args.additional_generations; config = SimulationConfig(**config_data)
            estimated = args.additional_generations * (config.population_size * (config.trials + config.challenge_trials) + 3 * config.validation_trials) * config.max_frames
            if estimated > args.work_budget:
                raise ValueError(f"estimated {estimated} simulation frames exceed work budget {args.work_budget}")
            print(f"preflight experiment={args.experiment_id} continue_from={int(metadata['generation'])+1} additional={args.additional_generations}", flush=True)
            EvolutionExperiment(config, args.seed, state, results, resume=args.resume, validation_checkpoint=hof, audit_results=audit_path, approval_digest=approval_digest, experiment_id=args.experiment_id, execution=execution).run()
            print(f"continue_complete audit_status=NOT_RUN resume={state}", flush=True); return 0
        config = SimulationConfig(**config_data)
        audit_estimated = config.audit_trials * config.max_frames
        if audit_estimated > args.work_budget:
            raise ValueError(f"estimated {audit_estimated} audit frames exceed work budget {args.work_budget}")
        experiment = EvolutionExperiment(config, args.seed, state, results, resume=args.resume, validation_checkpoint=hof, audit_results=audit_path, approval_digest=approval_digest, experiment_id=args.experiment_id, allow_released_for_audit=True, execution=execution)
        summary = experiment.finalize_audit()
        if metadata.get("workflow_state") == "RELEASED":
            manifest = state.parent / "manifest_v35.json"
            # Recover from a crash after the durable RELEASED transition but
            # before manifest publication. Rebuilding is deterministic and the
            # completed audit is revalidated by finalize_audit above.
            if not manifest.is_file():
                manifest = write_release_manifest(state.parent, args.experiment_id, config, approval_digest)
        else:
            CheckpointRepository.set_workflow_state(state, config, "RELEASED", str(summary["record_hash"]))
            manifest = write_release_manifest(state.parent, args.experiment_id, config, approval_digest)
        print(f"audit_complete fitness={summary['audit_fitness']:.6f} artifact={audit_path} manifest={manifest}", flush=True); return 0
    except KeyboardInterrupt:
        print("interrupted: last committed generation remains resumable", flush=True); return 5
    except (ValueError, OSError, json.JSONDecodeError, KeyError) as error:
        print(f"error: {error}", flush=True); return 3


if __name__ == "__main__":
    raise SystemExit(main())
