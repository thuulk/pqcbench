# pqcbench

## Objective

Implement and validate **ECDH P-256** (classical) and **ML-KEM-768** (post-quantum) on a
Raspberry Pi 4. Characterize both with a repeatable benchmark methodology, compare execution time
and cryptographic object sizes, and document the classical vs. PQC trade-offs and the
platform-specific limitations.


## Compilation
Using the GNU C Compiler (gcc), one is to compile a source file using the following flags: 
gcc -fdiagnostics-color=awlays -g <path-to-file.c> -o <path-to-out-bin> \
-lssl -lcrypto -lcjson

Where \ represents a jump in the line
