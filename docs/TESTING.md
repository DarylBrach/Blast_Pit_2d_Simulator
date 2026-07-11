# Testing

Run `run_tests.bat`. The fast suite checks positional CLI parsing, concise status math, actionable/non-mutating collision recovery, scalar/batch inference parity, deterministic simulation hashes, experiment-path containment, and the retained production checkpoint when present.

Release qualification should additionally compare workers 1 and N, uninterrupted versus resumed evolution, repeated golden seeds, corrupt/oversized NPZ rejection, audit idempotency, manifest recovery, Windows spawn, headless visualization, and a 20-generation soak. Benchmark before selecting worker count because process startup can dominate short trials.

Fast pytest success is necessary but does not claim completion of the release/soak checklist. Retain commands, timestamps, interpreter/package versions, exit codes, and artifact hashes for release evidence.
