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

Every source file is compiled with the same flags:
```
gcc -fdiagnostics-color=always -g <path-to-file.c> -o <path-to-out-bin> -lssl -lcrypto -lcjson
```

All commands below are run from the repository root. `bin/` and `results/` are not tracked by git,
so create them first:
```
mkdir -p bin results
```


## 1. Set up the benchmark files

Run these two programs once, before the first benchmark run. **Running either one again resets its
file and erases previous results.**

### Benchmark file (`csv.c`)
Creates `results/benchmark.csv` with its header row. Every measured operation is appended to this
file as one row.
```
gcc -fdiagnostics-color=always -g src/csv.c -o bin/csv -lssl -lcrypto -lcjson
./bin/csv
```

### Repetition cache (`json.c`)
Creates `results/cache.json`, which stores the next repetition number of each operation. This keeps
the repetition count going across separate runs of the benchmark instead of restarting at 1.
```
gcc -fdiagnostics-color=always -g src/json.c -o bin/json -lssl -lcrypto -lcjson
./bin/json
```


## 2. Run the ECDH P-256 benchmark (`ecdh.c`)

Generates a key pair for each party, derives the shared secret on both sides, checks that both
secrets match and serializes each private key as a raw 32-byte scalar. Before measuring, it runs
11 warm-up rounds of the same operations without logging them. Each key generation, derivation and
private-key serialization is then timed with `CLOCK_MONOTONIC` and appended to
`results/benchmark.csv`, with the time in nanoseconds (`time_ns`).
```
gcc -fdiagnostics-color=always -g src/ecdh.c -o bin/ecdh -lssl -lcrypto -lcjson
./bin/ecdh
```


## 3. Optional: check against the RFC 5903 test vector (`rfc_5903.c`)

Known-answer test that derives the shared secret from the fixed P-256 keys of
[RFC 5903 §8.1](https://www.rfc-editor.org/rfc/rfc5903.html#section-8.1) and compares it with the
expected value. Run it to confirm that the ECDH implementation matches the standard. It does not
write to the benchmark files.
```
gcc -fdiagnostics-color=always -g src/rfc_5903.c -o bin/rfc_5903 -lssl -lcrypto -lcjson
./bin/rfc_5903
```
