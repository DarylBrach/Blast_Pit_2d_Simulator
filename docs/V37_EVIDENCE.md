# v37 Evidence and Audit

`approval_v37_002.json` is the corrected lineage's unsigned, scoped local human authorization. It does not authorize release or override empirical gates. `audit_seeds_v37_002_committed.txt` contains 64 fresh externally generated unique seeds bound into the corrected fingerprint before training. The original approval/seeds remain consumed evidence for `-001`.

The approval's declared `issued_utc` was future-dated by drafting error. Direct user authorization and filesystem ordering establish that the file existed before training; `approval_timing_clarification_v37.json` records this without rewriting retained approval evidence.

The terminal audit evaluates v35, v36, and v37 actors on the identical ordered seed/profile suite, balanced 32 standard and 32 challenge. It records per-seed components and hydration/fire/recovery metrics, aggregate mean/median/minimum/CVaR/extinction, and paired bootstrap confidence intervals.

Observed corrected audit result: v37 mean 0.513997, median 0.546083, CVaR 0.264035, extinction 0.093750; v36 mean 0.542010, median 0.602798, CVaR 0.318688, extinction 0.062500; v35 mean 0.620690, median 0.696105, CVaR 0.365859, extinction 0.046875. The predeclared robustness gate failed.

Specialist policies and the v36 positive-delta HoF are retained under `robustness_specialists_v37/` with SHA-256 bindings. `failure_analysis_v37.json` is the machine-readable seed-level analysis surface.
