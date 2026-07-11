# v37 Final QA

- New v37 lineage fingerprint and scoped approval recorded.
- Immutable v36 generation-20 source checkpoint used.
- Protected v36 HoF and four challenge specialists retained with hashes.
- One planned v37 generation committed.
- Critic schema: local 19 plus lineage 5.
- Larger audit: 64 unique committed seeds, balanced 32/32 profiles, identical across three actors.
- Corrected lineage: `robustness-v37-002`; the original `-001` remains failed pre-hardening evidence.
- CVaR: v37 0.264035, v36 0.318688, v35 0.365859.
- Early extinction: v37 0.093750, v36 0.062500, v35 0.046875.
- Mean fitness: v37 0.513997, v36 0.542010, v35 0.620690.
- Release gate: FAIL. No RELEASED state or manifest authorized.
- Historical `-001` and `-002` evidence predates repository onboarding; their retained hashes remain authoritative for those runs.

## Eight-hour workflow QA gate

- `run_v37_8h.ps1` added with clean-Git, exact-approval, seed commitment, hash/dependency, dry-run, scoped-stop, zero-retry, no-Ollama, 28,200-second graceful, and 28,800-second hard-limit controls.
- Fresh and checkpoint-resume routes preserve one approved total generation ceiling.
- `BUDGET_EXHAUSTED` is resumable but not audit-eligible; only `TRAINING_COMPLETE` may advance to terminal audit.
- Fresh approval and 64-seed commitment are bound to `robustness-v37-8h-001`, the frozen source/checkpoint, 100-generation ceiling, and 28,200-second graceful runtime.
- Python compilation, PowerShell AST parsing, approval validation, and the expanded repository suite passed locally and in GitHub Actions on 2026-07-11; the source identity is line-ending canonical across checkouts.
- A clean-commit supervised dry run remains the final pre-execution check; no eight-hour workload was started during implementation.
- No eight-hour result, improvement, audit pass, or release is claimed by documentation implementation.
