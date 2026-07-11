# Changelog

## v36.0 experimental

- Added dependency-light NumPy PPO for the shared continuous controller.
- Added fixed-bin exploration/reproduction MAP-Elites archive.
- Added training-only rollout, action, and minibatch seed namespaces.
- Added actor-critic and Adam numeric checkpoint state.
- Added per-generation PPO and QD evidence records.
- Added bounded configuration, finite-value, path, lock, and checkpoint checks.
- Added unit and smoke tests plus algorithm, reward, governance, security,
  operations, and limitation documentation.

Compatibility: v35 checkpoints cannot resume as v36 PPO checkpoints. The v35
actor layout is evaluation-compatible, but importing a v35 brain as a governed
v36 warm start is not implemented in this release.

## v36.1 lifecycle hardening

- Added hardened checkpoint loading and exact legacy emitter reconstruction.
- Added `continue`, `status`, `inspect`, HoF/archive export, and archive SVG commands.
- Added checkpoint/JSONL reconciliation with fail-closed divergence handling.
- Added scoped v36 human approval, independent comparison audit, and conditional release manifest.
- Added archive/Hall-of-Fame provenance and source-generation persistence.
- Expanded lifecycle, recovery, export, CLI, and retained-artifact tests.
- Recorded that the retained lineage is generation 19 with 11 cells; its unchanged HoF originated at generation 12, when the archive had 10 cells.
