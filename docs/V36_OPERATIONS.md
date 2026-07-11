# v36 Operations

Use an activated DOS virtual environment and commands from `README_v36.md`.

`status` is read-only and concise. `inspect` emits complete metadata. `continue` requires the governed checkpoint path, matching experiment ID, seed, lineage fingerprint, and scoped approval. `--additional-generations` is an increment beyond the last committed generation.

Fresh `train` never overwrites an occupied directory. The current approval explicitly does not authorize a new training lineage.

Recovery permits only checkpoint generation N with JSONL through N-1 when the embedded record extends the JSONL head exactly. It appends the validated record once. Interior malformed JSON, gaps, divergent hashes, or JSONL ahead of checkpoint are rejected.

Archive exports are immutable per-cell policy NPZ files plus a hash-bound manifest. The SVG uses labels and text in every cell, so meaning is not color-only.
