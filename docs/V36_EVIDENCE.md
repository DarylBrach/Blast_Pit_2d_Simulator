# v36 Evidence and Governance

`approval_v36.json` records the direct human-owner authorization for the retained `qdppo-evaluation-001` lineage. It is local, unsigned, and scoped; it does not authorize fresh training or override audit results.

Generation records are hash chained. Checkpoints bind the embedded record, candidate and archive policy hashes, optimizer state, seed/configuration, and lineage fingerprint. Exports bind the source checkpoint SHA-256 and policy hashes.

The terminal comparison uses an `unseen_terminal_comparison` namespace and identical seeds, profiles, environment contract, deterministic v35 engine, and candidate ID normalization for both actors. These seeds were not used by PPO, selection, challenge, or fixed validation.

Current comparison: v36 median 0.661055, mean 0.521093, minimum 0.087388, early extinction 0.454545; v35 median 0.727102, mean 0.576079, minimum 0.081815, early extinction 0.363636. Release gate: failed.
