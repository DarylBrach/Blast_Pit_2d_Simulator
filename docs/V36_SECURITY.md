# v36 Security Boundary

Checkpoint loading uses `allow_pickle=False`, bounded ZIP/member counts and decompression, strict member names, exact array allowlists, finite float64 shape validation, and policy/record hash verification. Experiment paths are contained beneath the artifact root and symlinks are rejected. Training uses an exclusive owner-token lock with stale-owner retention.

The program is offline and invokes no shell or network client. It is not an operating-system sandbox and runs with the invoking user's filesystem permissions. Keep artifacts on trusted local storage; Windows reparse-point enforcement beyond Python symlink detection remains a deployment control.
