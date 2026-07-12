# Evidence and Governance

The experiment binds configuration, approval digest, experiment ID, master seed, engine fingerprint, genome hashes, ordered trial seeds, and previous generation hash. Worker count is operational metadata and does not alter scientific semantics. Only the parent writes evidence.

The local approval record expresses operator authorization but is not cryptographically signed, expiring, or bound to a single experiment/configuration. Audit is lifecycle-held but not secret: its deterministic seeds are derivable from the published master seed. Do not describe it as an independently blind holdout. Release evidence should be retained with the complete experiment directory. Any manual artifact edit invalidates its hash or semantic checks.

Before audit, independently verify that the planned run is complete; v35 currently does not enforce that release gate in code. Approval scoping/signing, an independent audit-seed commitment, and an enforced target-generation gate remain governance backlog.

Controller v2 retains an append-only transition chain, exact per-cycle manifests chained by the previous cycle-manifest hash, a root evidence manifest, production guard, schema-valid operator decision, and `latest.json` hashes. The read-only operator rehashes these surfaces and binds the latest run to a local append-only audit ledger.

The ledger is tamper-evident only relative to the local files that retain it; it is not externally witnessed or cryptographically signed. Fold B/C records are development screening evidence and must never be described as terminal audit evidence. Sealed runs are immutable; later human QA must supersede rather than rewrite them.

Controller v2.1 additionally retains the ACL lease/WAL history, original SDDL and hash, exact rule-multiset discovery evidence, restricted SID, durable `APPLYING`, current and archived helper identities, raw and guarded canary commands/results, and exact restored-SDDL verification. Raw evidence states whether the OS sandbox isolated networking; guarded evidence separately proves the effective candidate policy. Each recovery event has its own decision, manifest, append-only hash-chain ledger, and latest hazard pointer. Production guard, run sealing, run-ledger append, and latest run publication occur only after restoration verification. Both local ledgers are same-machine tamper evidence, not external signatures.

Run `20260711T223022Z-1128b831` failed before canary and was never added to the local ledger. Its unchanged-production sealed files are diagnostic evidence only; operator verification correctly remains blocked. The local ledger is same-machine tamper evidence, not an external signature, timestamp authority, or transparency service.

## Controller v2.2 container evidence

The v2.1 audit-guard evidence description above is historical. Current evidence binds image `sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698`, `candidate_image_attestation_v1.json`, the hash-locked recipe, Docker host identity, exact inspect policy, read-only workspace mount, bounded `/tmp` and `/output`, native canary, lifecycle WAL, removal/quiescence, and container recovery decision/manifest/ledger/latest hazard. Training export evidence records safe paths, sizes, per-file SHA-256, base64 validation, aggregate limits, and trusted host materialization. Run, container-recovery, and ACL-recovery ledgers are local tamper evidence, not external signatures.
