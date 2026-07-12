# Testing

Run `run_tests.bat`. The fast suite checks positional CLI parsing, concise status math, actionable/non-mutating collision recovery, scalar/batch inference parity, deterministic simulation hashes, experiment-path containment, and the retained production checkpoint when present.

Release qualification should additionally compare workers 1 and N, uninterrupted versus resumed evolution, repeated golden seeds, corrupt/oversized NPZ rejection, audit idempotency, manifest recovery, Windows spawn, headless visualization, and a 20-generation soak. Benchmark before selecting worker count because process startup can dominate short trials.

Fast pytest success is necessary but does not claim completion of the release/soak checklist. Retain commands, timestamps, interpreter/package versions, exit codes, and artifact hashes for release evidence.

Controller v2.1 qualification covers authorization/source bindings, tool-less role streaming, Job Object termination, kernel-lock exclusion, ACL WAL/startup/emergency recovery, the versioned helper archive, sealed recovery decisions/manifests and recovery ledger/status pointer, exact multiset SID discovery, durable `APPLYING`, exact-SDDL restoration, Python audit-guard socket/process/read/write/delete/rename/link denials, separate raw-versus-guarded canary evidence, build/review/final-QA schemas, cumulative-cycle state, remediation caps, Fold B/C separation, candidate driver/scorer determinism, transition and manifest chains, local ledger verification, and read-only Status/Review/Verify behavior. Platform-dependent Windows containment tests may skip where the required facility is unavailable; skips must be reported, not described as passes.

Install `requirements.txt` into the exact interpreter used for tests and launch. Controller v2 intentionally fails closed without `jsonschema`; schema-validation tests and live role-result validation require it.

Before a governed multi-cycle run, execute the full repository suite and a supported DryRun. Ten cycles are attempts under one time budget; they are not ten test passes or ten guaranteed improvements.

Earlier v2 and v2.1 results predate the final v2.2 Docker boundary and do not qualify it. Current local qualification is 242 passed with 3 reported skips. The historical supported clean-tree DryRun is runner `20260712T005801Z` / controller `20260712T005807Z-709f67a4` and predates v3.1 supervisor sealing.

First live run `20260711T223022Z-1128b831` failed closed before canary on CLI atomic-delete behavior. It proves failure retention and unchanged production only; because it is unanchored in the local ledger, it is not a passing evidence-verification or DryRun result.

## Controller v2.2 qualification

The v2.1 counts and audit-guard qualification above are historical and do not qualify v2.2. Qualification must cover the attested immutable image, hash-locked recipe, exact Docker policy, read-only workspace bind, bounded 256 MiB `/tmp` and `/output` tmpfs, native canary, lifecycle/recovery/quiescence, and trusted stdout exporter safe-path/base64/per-file-hash/aggregate-bound validation. Compile, focused and complete tests, training, and trusted scoring must all be containerized. Windows audit-guard tests are defense in depth only.

Final local qualification is 242 passed and 3 skipped in 70.73 seconds. The skips are governed-host live binding opt-in, unavailable file symlink creation, and unavailable directory symlink creation. Exact live `load_authorization` separately passes 1/1 with `BLAST_PIT_RUN_GOVERNED_HOST_TESTS=1`. Hosted CI runs mandatory static authorization plus a sanitized Windows-native ACL integration attempt; it never synthesizes bound Codex/Docker/image identity. The static test uses the authorization's bound external roots while hashing the actual checkout. For each text-only image-build input it rejects BOMs and bare CR, normalizes only CRLF to LF, and requires the result to equal the attested LF-byte hash before substituting only that raw-byte observation in the real validator; governed-host validation remains byte-exact. ACL integration reports a capability skip unless the host preserves an independent exact-SDDL round trip. Focused runner remains 27 passed. Exact-entrypoint DryRun runner `20260712T014740Z-04461e70` / controller `20260712T014742Z-2a8b7152` passes retained verification. The draft PR must retain a passing GitHub `tests` check before merge.

Live Docker integration tests use collision-resistant run IDs, assert only their own run labels, and hold the named daemon-scoped test mutex for the complete create/recover/absence lifecycle. A two-process recovery concurrency proof passed 2/2. The mutex coordinates pytest processes, not an active governed controller; stop the controller and confirm container quiescence before running host integration qualification.

The workflow runs for pull requests and pushes to `main` only, avoiding duplicate branch-push and pull-request jobs. It invokes `pytest -q -ra` so every platform and opt-in skip reason is visible in CI output.
