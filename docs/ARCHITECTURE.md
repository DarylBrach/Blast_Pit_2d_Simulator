# Architecture

The v35 launcher contains six logical layers: immutable scientific/execution configuration; brain and mutation policy; deterministic world simulation; fitness and suite aggregation; evolution orchestration; and checkpoint/evidence persistence. Independent trials may execute in spawned processes. Workers return validated summaries; the parent restores canonical order and is the only artifact writer.

The Python engine is the semantic reference. It senses every living creature from the same pre-action spatial snapshot, performs batched or scalar inference, then applies actions in creature-ID order. Resource contention is deterministic. Fire is static and food/water indexes are incrementally maintained; only the moving-creature index rebuilds each frame. Engine and inference choices are fingerprinted so numerically distinct checkpoints cannot be mixed.

The next performance boundary, if profiling justifies it, is a structure-of-arrays full-frame engine. It must reproduce reference ordering on golden fixtures or declare a new scientific engine contract. A scalar Numba distance function alone is not represented as full-engine acceleration.

Numba/LLVM is lazy-loaded only when `--engine numba` is explicitly selected. The Python reference engine does not import or initialize the optional compiled runtime.

Operator recovery is checkpoint-led: `status` exposes a bounded metadata subset, `train` rejects occupied governed artifacts, and `continue` advances from the last atomic generation commit. Full `inspect` remains an evidence/debug surface and may emit a large embedded generation record.
