# Evidence and Governance

The experiment binds configuration, approval digest, experiment ID, master seed, engine fingerprint, genome hashes, ordered trial seeds, and previous generation hash. Worker count is operational metadata and does not alter scientific semantics. Only the parent writes evidence.

The local approval record expresses operator authorization but is not cryptographically signed, expiring, or bound to a single experiment/configuration. Audit is lifecycle-held but not secret: its deterministic seeds are derivable from the published master seed. Do not describe it as an independently blind holdout. Release evidence should be retained with the complete experiment directory. Any manual artifact edit invalidates its hash or semantic checks.

Before audit, independently verify that the planned run is complete; v35 currently does not enforce that release gate in code. Approval scoping/signing, an independent audit-seed commitment, and an enforced target-generation gate remain governance backlog.
