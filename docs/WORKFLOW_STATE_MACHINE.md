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
