#pragma once

#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include <vector>
#include <string>
#include <span>
#include <cstdint>
#include <utility>

namespace sha256_research {

struct CpuFeatures {
    bool has_sse42{false};
    bool has_avx{false};
    bool has_avx2{false};
    bool has_sha_ni{false};
    bool has_bmi2{false};

    std::string to_string() const;
    static CpuFeatures detect() noexcept;
};

class Sha256Optimized {
public:
    // Capability matrix (explicit, honest):
    //  - scalar_reference : always available, correctness oracle (Sha256Scalar)
    //  - unrolled_portable: always available, pure-C++ unrolled compression
    //                       (no AVX2/SHA-NI intrinsics in this build; CPUID
    //                       detection below is informational only)
    //  - vulkan_compute   : available only when SHA256_HAVE_VULKAN=1 and a
    //                       compute device initializes at runtime
    //  - sat_smt_solvers  : available only when external solver binaries
    //                       respond at runtime (see SolverFactory)
    enum class Path { ScalarReference, UnrolledPortable };

    // Single-block unrolled fast compression (portable C++; no intrinsics)
    static void compress_block_unrolled(Sha256State& state, const uint8_t block[64]) noexcept;

    // Fast hash of a single message.
    // Dispatch: single-block messages (<=55 bytes) use the portable unrolled
    // path; longer messages use the scalar reference streaming path.
    // Both paths are validated to produce identical digests (see tests).
    static Sha256Digest hash(const void* data, size_t len) noexcept;

    static Sha256Digest hash_path(const void* data, size_t len, Path path) noexcept;

    // Batched multithreaded hashing of uniform-length blocks
    // Dispatches across all available logical CPU cores
    static void hash_batch(
        const uint8_t* in_data,
        size_t message_len,
        size_t count,
        Sha256Digest* out_digests,
        unsigned int thread_count = 0
    ) noexcept;

    // Parallel search / nonce-grinding routine: search for partial preimage / target prefix
    struct SearchTarget {
        uint32_t target_zero_bits{0};
        uint64_t max_iterations{10000000ULL};
    };

    struct SearchResult {
        bool found{false};
        uint64_t nonce{0};
        Sha256Digest digest{};
        uint64_t hashes_computed{0};
        double elapsed_seconds{0.0};
        double hash_rate{0.0}; // hashes/sec
    };

    static SearchResult search_prefix_zeros(
        const uint8_t* prefix,
        size_t prefix_len,
        const SearchTarget& target,
        unsigned int thread_count = 0
    );

    // Exact nonce-range partition used by search_prefix_zeros.
    // Returns [start, end) per worker; union == [0, max_iterations).
    static std::vector<std::pair<uint64_t, uint64_t>> partition_range(
        uint64_t max_iterations, unsigned int thread_count);

    static const CpuFeatures& features() noexcept;
};

} // namespace sha256_research
