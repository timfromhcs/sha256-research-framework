# Framework Architecture Overview

## Layered System Architecture

The SHA-256 Cryptanalysis Research Framework is engineered with strict separation of concerns across multiple layers:

```
+-------------------------------------------------------------------------+
|                  Research Orchestration & CLI (main.cpp)                |
+-------------------------------------------------------------------------+
|    ML Guidance Engine     |     Autonomous Campaign     |  Telemetry &  |
|      (PyTorch / ML)       |         Scheduler           |   Analysis    |
+---------------------------+-----------------------------+---------------+
|     SAT/SMT Encoders      |   Differential Trail Search |  Carry Logic  |
|    (Tseitin Transform)    |     (Biham / Mendel et al.) |   Tracking    |
+---------------------------+-----------------------------+---------------+
|                        Pluggable Solver Layer                           |
|       [CaDiCaL 3.0.1] [Kissat 4.0.4] [CryptoMiniSat] [Z3 SMT]          |
+-------------------------------------------------------------------------+
|                      Execution & Compute Backends                       |
|   [Scalar Reference]  [Optimized CPU (Multicore)]  [Vulkan 1.4 Compute] |
+-------------------------------------------------------------------------+
|                  Independent Verification Gate (verifier.cpp)           |
+-------------------------------------------------------------------------+
|                  Immutable Evidence & SQLite Knowledge Base             |
+-------------------------------------------------------------------------+
```

### 1. Compute Engines
- **Portable Scalar (`Sha256Scalar`)**: Zero-dependency C++20 golden reference implementing exact FIPS 180-4 logic, streaming buffer management, and arbitrary-length padding.
- **Optimized CPU (`Sha256Optimized`)**: Unrolls compression rounds in 8-step blocks, utilizes CPU instruction sets (SSE4.2, AVX, AVX2), and distributes batch workloads across all available CPU threads.
- **Vulkan GPU Compute (`Sha256VulkanEngine`)**: Compiles GLSL shaders into SPIR-V, dynamically binds host-coherent storage buffers, and executes parallel compute dispatches across GPU compute units.

### 2. Cryptanalysis & Solver Modeling
- **Differential Trail Engine (`DifferentialAnalysis`)**: Models XOR/modular differences and bit conditions across round steps.
- **SAT Encoder (`SatEncoder`)**: Translates non-linear SHA-256 operations ($Ch, Maj, \Sigma, \sigma$) and modular additions into Conjunctive Normal Form (CNF) via Tseitin transformation.
- **Pluggable Solver Interface (`ISolver`)**: Normalizes interaction with modern SAT/SMT engines, parsing DIMACS outputs, tracking conflict metrics, and extracting candidate assignments.

### 3. Verification & Evidence
- **Independent Verifier (`IndependentVerifier`)**: Completely segregated verification path that independently hashes candidates using golden reference logic and enforces the strict mathematical definition of cryptographic collisions.
- **Evidence Storage (`ExperimentStorage`)**: Generates globally unique run IDs, computes SHA-256 digests for all output logs, and stores manifests for reproducibility.
