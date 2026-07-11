# v37 Implementation Review

Architecture, workflow, governance, security, UI/testing, documentation, and final-QA specialists reviewed the design. v37 is correctly a new migration lineage because critic dimensions, reward semantics, seed schedules, and optimization objectives differ from v36.

The corrected implementation preserves the v36 actor and initializes five new critic context columns to zero. Training uses explicit challenge profiles, per-creature GAE trajectories, one deterministic permutation per PPO epoch, and deterministic namespaces. Specialist selection uses six training-only challenge seeds, never terminal audit seeds. The protected v36 HoF and four strongest challenge archive policies are retained with hashes.

The original exploratory run was retained after review found interleaved-trajectory and checkpoint defects. A distinct corrected lineage with new approval and unseen seeds completed generation 0. Its larger audit still showed worse CVaR and extinction than both baselines, so the empirical gate failed and no release claim is made.
