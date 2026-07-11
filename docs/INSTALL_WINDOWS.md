# Windows Installation

Target: `E:\Code\Python\VirtualEnvironments\Blast_Pit\2d_Simulator`.

Extract the ZIP so `README.md` and `run_blast_pit.bat` are directly inside that directory. Open Command Prompt:

```bat
cd /d E:\Code\Python\VirtualEnvironments\Blast_Pit\2d_Simulator
py -3.11 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
run_tests.bat
```

Confirm the active interpreter and optional Numba package before selecting an engine:

```bat
python -c "import sys,numba; print(sys.executable, numba.__version__)"
```

The Python engine is the reference. Select `--engine numba` only after parity testing and benchmarking; it compiles a bounded distance kernel and cannot replace the checkpoint engine during continuation.

v35 sets native BLAS/OpenMP thread limits before NumPy imports so spawned Windows workers inherit a stable one-native-thread contract. It does not mutate loaded native thread pools at worker runtime.

The launchers resolve paths relative to their own location, so they also work when invoked from another current directory. Do not include `.venv` in backups of experiment evidence. Keep artifact storage on the same local volume to preserve atomic replacement semantics.
