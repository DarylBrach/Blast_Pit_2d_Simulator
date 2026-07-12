# Changelog

- Upgraded CodexLightRunner to v3.1 with manifest v2 exact directory/file sealing, kernel locks, persistent publication-WAL recovery, terminal and name-binding hash-chain ledgers, ledger-bound pointers, and `name_binding_hash`. Process-crash recovery is qualified; sudden-power-loss durability is not claimed. Final suite: 240 passed/2 skipped in 54.66 seconds; focused runner: 27 passed. Post-v3.1 supported DryRun runner `20260712T014740Z-04461e70` and controller `20260712T014742Z-2a8b7152` completed successfully with no publication WAL, no active containers/leases, and unchanged production.

- Replaced the v2.1 Python audit-hook candidate boundary with controller v2.2's authorization-bound Linux Docker boundary. Compile, tests, training, and trusted scoring use immutable image `sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698`, tied to `candidate_image_attestation_v1.json` and the hash-locked image recipe.
- Made the single disposable-workspace bind read-only. Candidate writes are limited to bounded 256 MiB `/tmp` and `/output` tmpfs mounts. Training artifacts return only through the trusted bounded stdout exporter, which validates safe relative paths, per-file SHA-256, and base64 before materialization.
- Added durable governed-container lifecycle evidence and container-first recovery before ACL recovery. The Windows audit guard remains defense in depth only. Runner `20260712T005650Z` exposed an own-lock preflight defect: stale-worktree scanning rejected the fixed live `.controller-v2.lock`. After excluding only that lock entry, the exact BAT/CodexLightRunner DryRun succeeded as runner `20260712T005801Z` and controller `20260712T005807Z-709f67a4`. That retained DryRun predates v3.1 supervisor sealing; the current full suite passes 240 tests with 2 reported platform skips.

- Hardened the improvement harness to controller v2.1 with a child-only inheritance-only `DELETE` ACL lease, exact multiset restricted-SID discovery, durable `APPLYING` write-ahead state, a kernel controller lock, startup and emergency lease recovery, a per-lease hash-pinned recovery-helper archive, separately sealed/hash-chain-ledgered recovery events, and exact SDDL restoration before production guard, sealing, or publication.
- Added a candidate Python audit guard that denies socket/process operations, external reads/writes, and path mutations outside candidate roots; the complete gate now combines the trusted protected-harness suite with the guarded complete v37 candidate tests. Expanded the raw filesystem canary with lease-root delete, `WRITE_DAC`, `WRITE_OWNER`, rename, hardlink, and symlink probes, while separately recording raw OS network capability and effective guard denial without conflating them.
- Retained first live run `20260711T223022Z-1128b831` as unanchored diagnostic failure evidence: it failed closed before canary on CLI atomic-delete behavior and did not modify production.

- Added the governed v2 tool-less improvement harness with seven independent specialist roles, final QA, paired private Fold B and held-out Fold C evaluation, qualified unelevated Windows sandboxing, kill-on-close Job Objects, transition/cycle/run manifests, and a local tamper-evident ledger.
- Added supported Run, DryRun, Status, Review, Verify, Stop, and terminal-only InspectTerminal launcher modes with an eight-hour outer supervisor cap.
- Added strict read-only operator decisions: execution success is separate from human-review readiness, and promotion/release authority is always false.
- Qualified the frozen v2 source with the launch interpreter: 188 tests passed; two symlink-containment tests skipped because this Windows host does not permit symlink creation. Python compilation and PowerShell launcher parsing passed.

- Added a CodexLightRunner-supervised, worktree-isolated Codex improvement controller with structured proposals, security and test gates, trusted deterministic scoring, and candidate-branch-only retention.
- Bound the controller to an expiring parent human authorization and explicitly labeled disposable fixture records as controller development delegations.
- Added an eight-hour supervisor/authorization ceiling, minimal and redacted Codex environment, raw-filesystem comparison, pre/post production evidence, and recursive SHA-256 evidence sealing.
- Carried accepted and rejected lessons across multiple completed controller runs, including summaries, risks, scores, and raw-gate failures.
- Compacted multi-run lessons to decision-relevant metrics and bounded text so Windows can launch Codex reliably.
- Bounded the combined cross-run and same-run lesson window to the six most recent cycles, preventing Windows command-line overflow late in long controller runs.
- Completed ten-cycle controller run `20260711T183548Z` with a successful supervisor result, six controller-accepted cycles, four rejected cycles, 89 final-candidate tests, unchanged production, and a fully revalidated 206-file evidence seal.
- Recorded final-QA rejection of cycle 10 commit `ff38a1b`: an algorithmic Hall-of-Fame promotion change self-labeled as process and bypassed the v1.1 improvement threshold. Retained evidence remains immutable; `de3be87` is the last pre-failure v1.1 accepted ancestor, is not v1.2-revalidated, and remains pending human review.
- Fail-closed every simulator-source change as effective category `algorithm`, regardless of the proposing agent's label, so renamed or novel training behavior cannot bypass the improvement threshold.
- Redirected Codex `TEMP`/`TMP` and cooperative disposable work to an evidence-sealed per-cycle scratch directory; the prompt forbids other paths, while documentation explicitly retains the elevated-backend containment limitation.
- Preserved the immutable v1.1 authorization and added a separate hash-linked v1.2 authorization amendment selected by the launcher.
- Validated the shipped v1.2 amendment and controller through supported-launcher dry run `20260711T200515Z`; baseline evaluation, production guard, evidence sealing, and runner classification all passed.

## v35

- Added concise checkpoint `status` output and actionable fresh-train collision recovery guidance.
- Rebuilt the pytest suite after the test module was found replaced by a simulator copy.
- Corrected workflow documentation to distinguish durable states from transient in-process conditions.
- Documented continuation increments, Numba interpreter/engine boundaries, and current audit/governance limitations.
- Replaced unsafe runtime `threadpoolctl` mutation with pre-NumPy inherited BLAS/OpenMP limits after corrupted callable and abrupt worker failures on Windows.
- Made Numba/LLVM lazy and engine-gated so installing the optional compiler cannot alter Python-engine worker runtime state.

- Centralized the fitness policy used by execution and evidence validation.
- Corrected offspring survival using accumulated possible post-birth frames.
- Added founder, lineage, population-integral, and terminal-population survival.
- Added hydration maintenance and severe-thirst exposure metrics.
- Replaced hard count caps with smooth saturating resource/reproduction scores.
- Replaced distance-reward efficiency with useful outcome per energy.
- Added explicit 70/30 standard/challenge suite aggregation.
- Maintained static resource indexes incrementally; only moving creatures rebuild.
- Added recoverable release-manifest publication.
- Versioned artifacts, approvals, checkpoints, and documentation as v35.

See `CHANGELOG_v36.md` for the experimental QD-PPO lifecycle implementation. v35 remains the production baseline after v36 failed the current comparison release gate.

See `CHANGELOG_v37.md` for the robustness lineage and governed eight-hour operator workflow. Neither v36 nor v37 has cleared its empirical release gate.
