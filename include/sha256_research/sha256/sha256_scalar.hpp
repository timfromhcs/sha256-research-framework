#pragma once

#include "sha256_research/core/types.hpp"
#include <vector>
#include <span>

namespace sha256_research {

class Sha256Scalar {
public:
    Sha256Scalar() noexcept { reset(); }

    void reset() noexcept;
    void update(const void* data, size_t len) noexcept;
    Sha256Digest finalize() noexcept;

    static Sha256Digest hash(const void* data, size_t len) noexcept;
    static Sha256Digest hash(const std::string& str) noexcept {
        return hash(str.data(), str.size());
    }

    // Single-block compression function with configurable round count (1..64)
    // Supports standard IV or custom initial state
    static void compress_block(Sha256State& state, const uint8_t block[64], uint32_t num_rounds = 64) noexcept;

    // Detailed compression function recording intermediate states (for cryptanalysis)
    struct RoundTrace {
        std::array<uint32_t, 64> W{};
        std::array<Sha256State, 65> state_at_round{}; // state_at_round[0] is initial, [t] is after round t
    };

    static RoundTrace compress_block_trace(const Sha256State& initial_state, const uint8_t block[64], uint32_t num_rounds = 64) noexcept;

    // Message schedule expansion
    static void expand_schedule(const uint8_t block[64], uint32_t W[64]) noexcept;

    uint64_t total_bytes() const noexcept { return count_; }

private:
    Sha256State state_{};
    std::array<uint8_t, 64> buffer_{};
    size_t buffer_len_{0};
    uint64_t count_{0}; // total message length in bytes
};

} // namespace sha256_research
