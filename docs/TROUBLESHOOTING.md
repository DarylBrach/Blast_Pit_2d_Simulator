# Troubleshooting

`v35 artifacts already exist`: do not rerun fresh `train`; run `status`, calculate the remaining increment, and use `continue`. `approval record identity/status mismatch`: use the shipped v35 approval or an equivalent reviewed v35 record. `checkpoint ... mismatch`: keep experiment ID, seed, engine, and inference backend identical. `estimated frames exceed work budget`: raise the explicit budget only after reviewing the workload.

`worker evaluation group failed`: the current generation was not committed. If a checkpoint exists, resume it with `continue`; if generation 0 never committed, retain the context files and use a reviewed new experiment ID rather than deleting evidence. Windows multiprocessing failures can also result from removing the `if __name__ == "__main__"` guard.

If the remote traceback reports changing objects such as `range_iterator` or `collections.defaultdict` "is not callable" from otherwise valid spatial-index code, or a worker exits abruptly, verify that the updated source is in use. The corrected worker model sets BLAS/OpenMP limits before NumPy import and does not call `threadpoolctl` inside spawned workers. Retry only from the last committed checkpoint.

Observed 2026-07-11 boundary: Python 3.11.0 on Windows still terminated process pools at 8 workers (generation 3) and later at 2 workers (generation 8), while the serial reference path committed the same deterministic work. Until the base interpreter is upgraded and requalified, use `--workers 1` for production reliability. A worker-count change does not alter the engine fingerprint.

Install into the active interpreter with `python -m pip`, not an ambiguous `pip`. Verify using `python -c "import sys,numba; print(sys.executable, numba.__version__)"`. Numba has first-use JIT/cache overhead and accelerates only the bounded distance kernel in v35, not the full frame. If unavailable, use `--engine python`; v35 never silently substitutes engines and cannot change engine during continuation. If Pygame cannot open a window, update the GPU driver and reinstall Pygame; training does not require a display.
