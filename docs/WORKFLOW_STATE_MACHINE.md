# Workflow State Machine

Durable observable lifecycle: no checkpoint -> `TRAINING_COMMITTED` -> `RELEASED`.

`NEW`, `APPROVED`, and active `TRAINING` are in-process conditions, not persisted workflow states. Audit evidence is atomically written and validated before the checkpoint transitions directly from `TRAINING_COMMITTED` to `RELEASED`; there is no durable `AUDITED` intermediate state. The approval record is checked before mutation. Training and continuation never invoke audit. The parent process commits complete generations. RELEASED is terminal for training and continuation. Status, inspect, and visualize are read-only.

On interruption during evaluation, no partial generation is committed. On interruption after release-state persistence but before manifest publication, an identical audit invocation reconstructs the manifest from validated artifacts.

Current governance boundary: the code does not enforce completion of the initially requested generation count before audit. Operators must verify `status.remaining_generations == 0` before authorizing audit. An enforceable target-generation release gate remains required future work.
