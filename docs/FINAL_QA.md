# Final QA

## Retained 2026-07-11 evidence

- Active interpreter: `E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe`, Python 3.11.0, NumPy 2.2.0.
- Fast suite: `9 passed` after rebuilding the replaced test module.
- Disposable lifecycle: fresh train, continuation, and concise status completed.
- Exact-load stress: 8 workers completed three disposable 112-task generations, but repeated production/disposable evolved workloads exposed Windows process-pool termination at generation 3; 2 workers later terminated at production generation 8.
- Serial replay committed the same deterministic generation, establishing `--workers 1` as the qualified production path on this interpreter.
- Production `v35-production-001`: generation 9 was committed and the serial continuation proceeded into generation 10 during monitoring. Audit remains `NOT_RUN`; no release claim is authorized.

The following checklist remains release qualification work; unchecked narrative is not evidence of completion.

- Extract into a clean Python 3.11 environment, including a path containing spaces.
- Install `requirements.txt` and run all tests.
- Run the same golden trial twice and compare final-state hashes.
- Compare workers 1 and 2/4 for ordered semantic equivalence.
- Compare uninterrupted and train/continue runs.
- Exercise interrupt recovery and audit/manifest recovery on a disposable experiment.
- Reject corrupted checkpoints, mismatched approval/config/seed/engine, and unsafe experiment IDs.
- Execute README and Operations commands verbatim on Windows.
- Confirm the source contains no network or subprocess calls.
- Record benchmark, ZIP SHA-256, and release inventory.
- Exclude `.venv`, caches, temporary artifacts, and real audit outputs from distribution.
