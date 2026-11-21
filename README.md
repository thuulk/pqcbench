# pqcbench

## Objective

Implement and validate **ECDH P-256** (classical) and **ML-KEM-768** (post-quantum) on a
Raspberry Pi 4. Characterize both with a repeatable benchmark methodology, compare execution time
and cryptographic object sizes, and document the classical vs. PQC trade-offs and the
platform-specific limitations.


## Requirements

- GNU C Compiler (gcc)
- OpenSSL 3 development headers (`openssl-devel` on Fedora, `libssl-dev` on Debian / Raspberry Pi OS)
- cJSON development headers (`cjson-devel` on Fedora, `libcjson-dev` on Debian / Raspberry Pi OS)
- Python 3 with `pandas`, `numpy` and `matplotlib` (only to analyze the results with `analysis.py`). On a GNU/Linux
  system, install them with your system's package manager, not `pip` (on Debian / Raspberry Pi OS,
  `pip` refuses to install into the system Python with `externally-managed-environment`):
  ```
  sudo dnf install python3-pandas python3-numpy python3-matplotlib   # Fedora
  sudo apt install python3-pandas python3-numpy python3-matplotlib   # Debian / Raspberry Pi OS
  ```
- Go (only for the automated setup; `go.mod` asks for 1.26.10)

There are two ways to run the project:
- **Manual setup:** compile and run each program yourself, in the order of the numbered sections.
- **Go setup:** let `orchestrator.go` compile and run all the programs for you with one command.

Every source file is compiled with the same flags:
```
gcc -fdiagnostics-color=always -g <path-to-file.c> -o <path-to-out-bin> -lssl -lcrypto -lcjson
```

All commands below are run from the repository root. `bin/` and `results/` are not tracked by git,
so create them first:
```
mkdir -p bin results/figs
```


## 1. Set up the benchmark files

Run these two programs once, before the first benchmark run. **Running either one again resets its
file and erases previous results.**

### Benchmark files (`benchmark.c`)
Creates `results/benchmark.csv` with its header row. Every measured operation is appended to this
file as one row. It also creates `results/runs.csv`, where the runner (`runner.c`) logs one row per
execution of `ecdh` or `mlkem` with the conditions of the system at that moment.
```
gcc -fdiagnostics-color=always -g src/benchmark.c -o bin/benchmark -lssl -lcrypto -lcjson
./bin/benchmark
```

### Repetition cache (`cache.c`)
Creates `results/cache.json`, which stores the next repetition number of each operation, plus the
run number used by the runner. This keeps the repetition count going across separate runs of the
benchmark instead of restarting at 1.
```
gcc -fdiagnostics-color=always -g src/cache.c -o bin/cache -lssl -lcrypto -lcjson
./bin/cache
```


## 2. Compile the ECDH P-256 benchmark (`ecdh.c`)

Generates a key pair for each party, derives the shared secret on both sides, checks that both
secrets match and serializes each private key as a raw 32-byte scalar. Before measuring, it runs
10 warm-up rounds of the same operations without logging them. Each key generation, derivation and
private-key serialization is then timed with `CLOCK_MONOTONIC` and appended to
`results/benchmark.csv`, with the time in nanoseconds (`time_ns`).
Each execution measures a single round. You don't run it yourself: the runner (`runner.c`) launches it.
```
gcc -fdiagnostics-color=always -g src/ecdh.c -o bin/ecdh -lssl -lcrypto -lcjson
```


## 3. Compile the ML-KEM-768 benchmark (`mlkem.c`)

Generates one ML-KEM-768 key pair, encapsulates a shared secret against its public key, decapsulates
the ciphertext with its private key, checks that both secrets match and serializes the private key
in its raw form. Before measuring, it runs 10 warm-up rounds of the same operations without logging
them. Key generation, encapsulation, decapsulation and private-key serialization are then timed with
`CLOCK_MONOTONIC` and appended to `results/benchmark.csv`, with the time in nanoseconds (`time_ns`).
Each execution measures a single round. You don't run it yourself: the runner (`runner.c`) launches it.
```
gcc -fdiagnostics-color=always -g src/mlkem.c -o bin/mlkem -lssl -lcrypto -lcjson
```


## 4. Run the benchmark with the runner (`runner.c`)

The runner repeats the benchmark 1000 times. In each iteration it launches `bin/ecdh` and then
`bin/mlkem` as child processes, measures how long each process takes, and reads the SoC
temperature, the CPU frequency (kHz) and the system load average. Each execution is appended to
`results/runs.csv`. `bin/ecdh` and `bin/mlkem` must be compiled before running it.
```
gcc -fdiagnostics-color=always -g src/runner.c -o bin/runner -lssl -lcrypto -lcjson
./bin/runner
```


## 5. Analyze the results (`analysis.py`)

Reads `results/benchmark.csv` and `results/runs.csv`, prints summary tables and saves the figures
in `results/figs/`.
```
python3 analysis.py
```


## Go setup (`orchestrator.go`)

`orchestrator.go` runs the pipeline for you from the repository root: it creates `results/`,
`results/figs/` and `bin/`, compiles and runs `benchmark.c` and `cache.c` if their files do not exist
yet, compiles `ecdh`, `mlkem` and `runner`, runs `bin/runner` and finally runs `analysis.py`. If any
command fails, it prints the error and stops.
```
go run .
```
Or compile it once and run the binary:
```
go build -o bin/orchestrator .
./bin/orchestrator
```
It only compiles a program when its binary is missing. After changing a `.c` file, delete its binary
from `bin/` (or recompile it by hand) so the change is picked up.

On the Raspberry Pi, either install Go there, or cross-compile on the laptop and copy the binary:
```
GOOS=linux GOARCH=arm64 go build -o bin/orchestrator-arm64 .
scp bin/orchestrator-arm64 diegor@raspberrypi:~/pqcbench/bin/orchestrator
```


## Optional: check against the RFC 5903 test vector (`rfc_5903.c`)

Known-answer test that derives the shared secret from the fixed P-256 keys of
[RFC 5903 §8.1](https://www.rfc-editor.org/rfc/rfc5903.html#section-8.1) and compares it with the
expected value. Run it to confirm that the ECDH implementation matches the standard. It does not
write to the benchmark files.
```
gcc -fdiagnostics-color=always -g src/rfc_5903.c -o bin/rfc_5903 -lssl -lcrypto -lcjson
./bin/rfc_5903
```
