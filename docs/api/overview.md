# C++ Library API Reference

The framework exports a C++20 header-only interface backed by `sha256_core.lib`:

## Header Includes
```cpp
#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/vulkan/sha256_vulkan.hpp"
#include "sha256_research/differential/diff_trail.hpp"
#include "sha256_research/sat/sat_encoder.hpp"
#include "sha256_research/solver/solver_interface.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/storage/experiment_db.hpp"
#include "sha256_research/benchmark/benchmark_suite.hpp"
```

## Core Functions

### Reference Hashing
```cpp
// One-shot hashing
Sha256Digest digest = Sha256Scalar::hash("example message", 15);
std::string hex_str = digest.to_hex();

// Streaming hashing
Sha256Scalar hasher;
hasher.update(data_chunk_1, len1);
hasher.update(data_chunk_2, len2);
Sha256Digest final_digest = hasher.finalize();

// Reduced-round compression
Sha256State state = SHA256_IV;
Sha256Scalar::compress_block(state, block_bytes, 16); // 16 rounds
```

### Multicore Batched Hashing
```cpp
std::vector<Sha256Digest> digests(10000);
Sha256Optimized::hash_batch(input_bytes, 64, 10000, digests.data(), 16);
```

### Vulkan GPU Compute Batching
```cpp
Sha256VulkanEngine engine;
if (engine.initialize("shaders")) {
    std::vector<Sha256Digest> gpu_digests;
    engine.compute_batch(input_blocks, 65536, gpu_digests, 64);
}
```

### SAT Formulation & Solving
```cpp
SatEncoder::Sha256ProblemConfig cfg;
cfg.num_rounds = 10;
cfg.use_standard_iv = true;
cfg.fix_target_digest = true;
cfg.target_digest = target_hash;

auto encoding = SatEncoder::encode_reduced_rounds(cfg);

auto solver = SolverFactory::create(SolverType::Kissat);
SolverResult res = solver->solve_cnf(encoding.cnf, 60);
if (res.is_sat()) {
    auto message_words = SatEncoder::extract_message_from_model(res.model, encoding.message_vars);
}
```
