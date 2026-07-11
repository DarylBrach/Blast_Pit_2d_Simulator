# Benchmarking

Run `python benchmark_tmp_2d_simulator_v35.py --frames 500` before production. Test workers 1, 2, 4, and 8 using the same task/frame count. Report trials/second, frames/second, Python/NumPy/Numba versions, CPU, worker count, engine, and inference mode. Short workloads may favor fewer processes. Resource indexes are incremental in v35, so compare against v34 using identical semantic workloads rather than raw UI FPS.

Treat stability as a benchmark result, not only speed. On 2026-07-11, Windows Python 3.11.0 completed short 8-worker fixtures but terminated process pools as evolved workloads grew; 2 workers later failed as well. The serial reference completed the same retained generation. Production on that interpreter therefore uses one worker pending upgrade and a repeated long-lineage concurrency soak.
