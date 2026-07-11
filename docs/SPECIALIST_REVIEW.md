# Specialist Review Record

The v35 package was reviewed in parallel across architecture/performance, workflow/governance/security, and UI/testing/documentation disciplines.

Implemented high-priority findings include centralized fitness semantics, accumulated offspring opportunity time, explicit suite weights, honest development-confirmation terminology, incremental resource indexing, version separation from v34, release-manifest crash recovery, bounded/offline execution, expanded Windows operations, migration guidance, and deterministic/lifecycle tests.

Recommended future work retained as explicit backlog: durable experiment-wide lock with owner-dead recovery; multi-file commit journal; cryptographically signed approvals when external authority is required; offline `verify` and explicit `release` commands; complete structure-of-arrays compiled frame engine; adaptive mutation state persisted in checkpoints; two-stage candidate evaluation; richer accessible visualization; Windows reparse-point enforcement; fault-injection and concurrency soak suites.

The 2026-07-11 recovery review additionally found a replaced/nonfunctional test module, poor occupied-run recovery UX, inaccurate durable-state wording, no enforced planned-generation audit gate, deterministic non-secret audit seeds, broad unsigned approval scope, and stale-lock risk. This update rebuilt fast tests, added concise status/actionable continuation guidance, and corrected documentation. Target-generation enforcement, stronger approval/audit independence, lock recovery, and expanded fault-injection/soak coverage remain open and are not claimed complete.

These backlog items are not claimed as implemented in v35. The included security and governance documentation states the current boundaries directly.

## Improvement harness v2 panel

The v2 panel has seven fixed tool-less roles: architecture/state, algorithm/objective, workflow/state, governance/evidence, security/sandbox, testing/reliability, and documentation/UX. Findings use stable IDs and mandatory high/critical findings may be remediated for at most two rounds. Independent final QA adjudicates the final evidence packet. Every model role receives bounded inline evidence and cannot invoke tools. A builder or remediator may only return a schema-validated, bounded patch proposal; the controller validates and applies that patch through the qualified sandbox.

Specialist consensus is one gate, not promotion authority. Human review remains mandatory after a 100/100 result.
