# Workflow State Machine

v37 separates execution outcome, durable training state, and terminal audit evidence.

`NEW` and active `TRAINING` are transient. Each completed generation atomically advances the checkpoint and append-only hash chain. A graceful time-budget boundary yields `BUDGET_EXHAUSTED` only after preserving the last complete commit; a validated resume re-enters `TRAINING` under the identical fingerprint, approval, configuration, and total generation ceiling. Reaching that ceiling yields `TRAINING_COMPLETE`.

Only `TRAINING_COMPLETE` is audit-eligible. Audit writes immutable `AUDIT_COMMITTED` evidence and an empirical `PASS` or `FAIL`; it does not turn a failed comparison into release. `RELEASED`, if ever implemented and authorized, must require a passing audit and a distinct publication decision. Status is read-only.

```text
NEW -> TRAINING -> BUDGET_EXHAUSTED -> TRAINING (validated resume)
                  |                         |
                  +-------------------------+
TRAINING -> TRAINING_COMPLETE -> AUDIT_COMMITTED(PASS|FAIL)
```

Timeout, kill, or interruption during evaluation cannot commit a partial generation. The last validated checkpoint remains authoritative. Divergent checkpoint/JSONL history, configuration drift, approval drift, or an occupied directory without a valid resume checkpoint fails closed.

## Improvement controller v2

Controller execution and review disposition are separate. Terminal controller states include `DRY_RUN_COMPLETE`, `COMPLETE`, `COMPLETE_WITH_REJECTIONS`, `COMPLETE_WITH_ERRORS`, `TIMEOUT`, and `KILLED`. A successful execution can still be blocked from human review.

Only a sealed decision with execution `SUCCESS`, review `PASS`, promotion state `HUMAN_REVIEW_PENDING`, all twelve gates passing, eight review artifacts passing, no blockers, unmodified production, and a 100/100 rubric is review-ready. Even then, automatic promotion and release remain false. InspectTerminal verifies terminal evidence; partial runs are immutable and are never resumed in place.

Controller v2.1 lease recovery is a prerequisite state machine under one kernel lock: archive the hash-pinned helper, snapshot and fsync, materialize, `SID_DISCOVERED`, `APPLYING`, active child-delete lease, raw filesystem/capability observation, guarded policy canary, candidate work, cleanup, exact-SDDL restore/verify, production guard, seal, and publish. Startup and emergency handling replay any persistent incomplete WAL with the archived helper. A lease that cannot be restored creates a sealed `RECOVERY_REQUIRED` recovery event and latest hazard pointer; it blocks guard, run sealing/publication, Status/Review readiness, and new candidate execution. It is not a resumable candidate run.

Launcher Recover enters only the locked recovery subgraph: fixed-path/archived-helper-hash validation, persisted-WAL replay, exact-SDDL restore/verify, recovery decision/manifest/ledger/latest update, disposable workspace removal, then exit. It bypasses the candidate clean-check but cannot transition a partial run back to execution. Status and Verify remain separate read-only candidate-evidence paths while also surfacing host recovery status.

Ten requested cycles are at most ten attempts. Rubric `10/10` means ten full-credit dimensions totaling 100/100 and only `HUMAN_REVIEW_PENDING` eligibility.

## Controller v2.2 Docker state machine

The v2.1 audit-guard sequence above is historical. Current ordering under one kernel lock is: governed-container recovery, ACL recovery, authorization-bound Docker host/image/attestation preflight, ACL lease activation, container qualification, containerized compile/tests/train/trusted score, container removal and verified quiescence, exact-SDDL restoration, production guard, seal, ledger, and publish. Container intent is durable before create. Recover performs container-first then ACL recovery. Either latest hazard blocks readiness.

Runner v3.1 separately holds its publication kernel lock, recovers pending WAL, and validates name binding before allocation. Terminal publication advances through intent fsynced, terminal-ledger anchored, pointer/latest published, verified, then WAL removed. The terminal row records `name_binding_hash`, and the pointer binds the row by `ledger_hash`. A present WAL blocks ordinary latest verification. `_terminal` is authoritative; `_state` is advisory/live. This is process-crash qualified, not sudden-power-loss qualified, and independent of the controller seal.
