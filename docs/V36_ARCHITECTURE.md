# v36 Architecture

v36 layers NumPy PPO and a deterministic MAP-Elites archive over the authoritative v35 environment and fitness implementation. PPO training, selection/challenge evaluation, archive insertion, and fixed validation are separate seed namespaces.

The atomic checkpoint contains evaluated candidates, actor/critic policies, Adam moments, archive policies, Hall-of-Fame policy, embedded generation record, next candidate ID, configuration, and lineage fingerprint. Legacy continuation deterministically replays the emitter after the last commit before training generation N+1. New commits persist Hall-of-Fame source generation and implementation hash without rewriting the legacy lineage fingerprint.

Durable state is `TRAINING_COMMITTED`. Terminal comparison produces separate `AUDIT_COMMITTED` evidence. `RELEASED` is published only by a conditional manifest after approval and performance gates pass.
