# SHA-256 Research Framework v5.1.0

**Hardened stable release candidate bringing 14.5x throughput acceleration to
context shaping, verified self-healing test automation, strict CLI contracts,
and comprehensive integrity protection.**

Full SHA-256 remains unbroken. A reduced-round preimage of a *compression
function* is not a preimage of the padded hash, and nothing in this release
affects collision resistance.

## What changed in v5.1.0

### 1. Multi-Threaded Preimage Search & Hardware Prefetching
`tools/context_shaping.cpp` adds `--threads T` (partitions contexts across worker
threads) and `--batch K` (issues hardware prefetches using `_mm_prefetch`). On
an 8-core CPU (16 logical threads), throughput reaches **1.20e8 swept $a_0$/s**
(a **14.5x speedup** over single-threaded execution).

### 2. Compact Table Format CST3 & Integrity Roundtrip Checks
Eliminated unused bitmap/rank directories to reduce peak resident memory during
table generation. Upgraded header magic to `CST3`, verifying fixed-width headers
and stored root counts. Added `tabletest --roundtrip` (integrated as CTest target
`context-shaping-table-roundtrip`) to ensure reloaded tables match brute force bit-identically.

### 3. Correctness Fixes
- **Root `0xFFFFFFFF` Sentinel Collision**: Corrected search loops to bound by image
  multiplicity rather than filtering on `0xFFFFFFFF`, which is a legitimate root for
  image `0x20000000`.
- **Atomic Counter Carry Hazard**: Replaced non-atomic byte additions with `atomic_add8_sat`
  (spinning 8-bit CAS loop) to eliminate carry propagation across adjacent word counters.

### 4. First-Moment Spectral Analysis (`tools/c3_spectrum.cpp`)
Evaluates the Fourier spectrum of the 20-round residual $c_3 = \sigma_0(W_4) + W_3 - \kappa_3$
to detect potential low-frequency modes against computed null hypotheses.

### 5. Fail-Closed Evidence Verification & Traversal Protection
`reproducibility/verify_evidence.py` enforces strict fail-closed validation:
- Exits with failure code 1 if the experiment manifest set is empty or missing (unless
  `--allow-empty` is explicitly supplied).
- Prevents path traversal exploits in artifact paths.
- Validates manifests against formal schemas using `jsonschema`.
- Covered by 7 dedicated automated tests in `tests/test_evidence_verifier.py`.

### 6. Standard CLI Contracts & Packaging
- All binaries (`sha-research`, `sha-verifier`, `context_shaping`, `c3_spectrum`)
  implement standard `--version` and `--help` CLI contracts exiting with code 0.
- Native CMake `install()` targets and CPack configuration generating verified
  portable archives.

## Measured Throughput (Context Shaping)

Grid of swept $a_0$ per second at width $2^{30}$ (Ryzen 7 7735HS, 8 cores / 16 threads):

| Threads \ Batch | 1 | 16 | 64 |
| :--- | ---: | ---: | ---: |
| 1 | 8.3e6 | 1.07e7 | 1.07e7 |
| 4 | 2.8e7 | 4.36e7 | 4.36e7 |
| 8 | 6.0e7 | 8.0e7 | 8.0e7 |
| 16 | 9.6e7 | **1.20e8** | 1.20e8 |

## Test Suite Coverage

- **CTest Targets**: 17 / 17 passed
- **Python Test Suites**: 82 / 82 passed (including platform, scheduler, witnesses, reference KAT, Z3 cross-check, evidence verification)
- **Independent Verifier**: All NIST KATs and negative anti-cheating controls passed

## Assets in this release

Each archive is built on a runner of the matching operating system. No binary
in this repository is ever cross-labelled.

- `sha256-research-framework-5.1.0-windows-x64.zip`
- `sha256-research-framework-5.1.0-linux-x64.tar.gz`
- `sha256-research-framework-5.1.0-macos-arm64.tar.gz`
- Matching `.sha256` digest files for each archive

## Verifying a download

```bash
sha256sum -c sha256-research-framework-5.1.0-<platform>.<archive>.sha256

# Verify binary integrity
bin/sha-verifier test-vectors
bin/sha-verifier --version
bin/context_shaping selftest
bin/context_shaping --version
```
