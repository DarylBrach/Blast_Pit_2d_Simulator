# Changelog

## v35

- Added concise checkpoint `status` output and actionable fresh-train collision recovery guidance.
- Rebuilt the pytest suite after the test module was found replaced by a simulator copy.
- Corrected workflow documentation to distinguish durable states from transient in-process conditions.
- Documented continuation increments, Numba interpreter/engine boundaries, and current audit/governance limitations.
- Replaced unsafe runtime `threadpoolctl` mutation with pre-NumPy inherited BLAS/OpenMP limits after corrupted callable and abrupt worker failures on Windows.
- Made Numba/LLVM lazy and engine-gated so installing the optional compiler cannot alter Python-engine worker runtime state.

- Centralized the fitness policy used by execution and evidence validation.
- Corrected offspring survival using accumulated possible post-birth frames.
- Added founder, lineage, population-integral, and terminal-population survival.
- Added hydration maintenance and severe-thirst exposure metrics.
- Replaced hard count caps with smooth saturating resource/reproduction scores.
- Replaced distance-reward efficiency with useful outcome per energy.
- Added explicit 70/30 standard/challenge suite aggregation.
- Maintained static resource indexes incrementally; only moving creatures rebuild.
- Added recoverable release-manifest publication.
- Versioned artifacts, approvals, checkpoints, and documentation as v35.

See `CHANGELOG_v36.md` for the experimental QD-PPO lifecycle implementation. v35 remains the production baseline after v36 failed the current comparison release gate.

See `CHANGELOG_v37.md` for the robustness lineage and governed eight-hour operator workflow. Neither v36 nor v37 has cleared its empirical release gate.
