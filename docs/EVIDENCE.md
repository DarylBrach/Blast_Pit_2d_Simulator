# Evidence and Governance

The experiment binds configuration, approval digest, experiment ID, master seed, engine fingerprint, genome hashes, ordered trial seeds, and previous generation hash. Worker count is operational metadata and does not alter scientific semantics. Only the parent writes evidence.

The local approval record expresses operator authorization but is not cryptographically signed, expiring, or bound to a single experiment/configuration. Audit is lifecycle-held but not secret: its deterministic seeds are derivable from the published master seed. Do not describe it as an independently blind holdout. Release evidence should be retained with the complete experiment directory. Any manual artifact edit invalidates its hash or semantic checks.

Before audit, independently verify that the planned run is complete; v35 currently does not enforce that release gate in code. Approval scoping/signing, an independent audit-seed commitment, and an enforced target-generation gate remain governance backlog.

Controller v2 retains an append-only transition chain, exact per-cycle manifests chained by the previous cycle-manifest hash, a root evidence manifest, production guard, schema-valid operator decision, and `latest.json` hashes. The read-only operator rehashes these surfaces and binds the latest run to a local append-only audit ledger.

The ledger is tamper-evident only relative to the local files that retain it; it is not externally witnessed or cryptographically signed. Fold B/C records are development screening evidence and must never be described as terminal audit evidence. Sealed runs are immutable; later human QA must supersede rather than rewrite them.
