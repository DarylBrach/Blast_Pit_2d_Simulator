from __future__ import annotations

import argparse
import importlib.util
import time
import sys
from pathlib import Path

ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("simulator_v35", ROOT / "tmp_2d_simulator_v35.py")
assert SPEC and SPEC.loader
sim = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sim
SPEC.loader.exec_module(sim)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frames", type=int, default=500)
    parser.add_argument("--trials", type=int, default=4)
    args = parser.parse_args()
    config = sim.SimulationConfig(max_frames=args.frames)
    brain = sim.Brain.random(config, sim.np.random.default_rng(20260711))
    started = time.perf_counter()
    summaries = [sim.Simulation(config, brain, sim.stable_seed(20260711, i)).run() for i in range(args.trials)]
    elapsed = time.perf_counter() - started
    frames = sum(item.frames for item in summaries)
    print(f"v35 trials={args.trials} frames={frames} seconds={elapsed:.3f} frames_per_second={frames / elapsed:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
