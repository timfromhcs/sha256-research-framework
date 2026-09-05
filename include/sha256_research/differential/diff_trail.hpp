#pragma once

#include "sha256_research/core/types.hpp"
#include <vector>
#include <string>
#include <optional>

namespace sha256_research {

enum class BitCondition : char {
    Unconstrained = '-',
    Zero = '0',
    One = '1',
    Equal = '=',
    Opposite = '!',
    Unknown = '?'
};

struct BitConditionWord {
    std::array<BitCondition, 32> bits{};

    BitConditionWord() { bits.fill(BitCondition::Unconstrained); }
    explicit BitConditionWord(const std::string& str);
    std::string to_string() const;

    bool matches(uint32_t val1, uint32_t val2) const noexcept;
};

struct StepDifference {
    uint32_t round{0};
    uint32_t delta_w{0};      // ΔW_t
    uint32_t delta_a{0};      // ΔA_t
    uint32_t delta_e{0};      // ΔE_t
    double log2_probability{0.0};
    BitConditionWord conditions_a{};
    BitConditionWord conditions_e{};
};

struct DifferentialTrail {
    std::string name;
    uint32_t num_rounds{0};
    double total_log2_probability{0.0};
    std::vector<StepDifference> steps;

    // Verify if a pair of concrete message blocks satisfies this differential trail
    struct TrailCheckResult {
        bool satisfied{false};
        uint32_t failed_at_round{0};
        std::string failure_reason;
    };

    TrailCheckResult verify_pair(
        const Sha256State& iv,
        const uint8_t block1[64],
        const uint8_t block2[64]
    ) const;
};

class DifferentialAnalysis {
public:
    // Compute XOR difference between two 32-bit words
    static constexpr uint32_t diff_xor(uint32_t a, uint32_t b) noexcept { return a ^ b; }

    // Compute modular difference (a - b mod 2^32)
    static constexpr uint32_t diff_sub(uint32_t a, uint32_t b) noexcept { return a - b; }

    // Count differing bits (Hamming weight of XOR)
    static uint32_t hamming_distance(uint32_t a, uint32_t b) noexcept;
    static uint32_t hamming_distance(const Sha256Digest& d1, const Sha256Digest& d2) noexcept;

    // Estimate non-linear propagation probability of Δe through Ch and Σ1
    static double estimate_ch_diff_probability(uint32_t delta_e, uint32_t delta_f, uint32_t delta_g) noexcept;
    static double estimate_maj_diff_probability(uint32_t delta_a, uint32_t delta_b, uint32_t delta_c) noexcept;

    // Generate standard reference differential characteristics for reduced rounds
    static DifferentialTrail create_standard_reduced_trail(uint32_t rounds);
};

} // namespace sha256_research
