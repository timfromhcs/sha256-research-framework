#include "sha256_research/differential/diff_trail.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include <cmath>
#include <sstream>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace sha256_research {

namespace {

inline uint32_t popcount32(uint32_t x) noexcept {
#if defined(_MSC_VER)
    return __popcnt(x);
#else
    return __builtin_popcount(x);
#endif
}

} // namespace

BitConditionWord::BitConditionWord(const std::string& str) {
    bits.fill(BitCondition::Unconstrained);
    size_t len = std::min(str.size(), size_t(32));
    for (size_t i = 0; i < len; ++i) {
        bits[31 - i] = static_cast<BitCondition>(str[i]);
    }
}

std::string BitConditionWord::to_string() const {
    std::string s(32, '-');
    for (size_t i = 0; i < 32; ++i) {
        s[31 - i] = static_cast<char>(bits[i]);
    }
    return s;
}

bool BitConditionWord::matches(uint32_t val1, uint32_t val2) const noexcept {
    for (size_t i = 0; i < 32; ++i) {
        uint32_t b1 = (val1 >> i) & 1U;
        uint32_t b2 = (val2 >> i) & 1U;
        BitCondition cond = bits[i];

        switch (cond) {
            case BitCondition::Zero:
                if (b1 != 0 || b2 != 0) return false;
                break;
            case BitCondition::One:
                if (b1 != 1 || b2 != 1) return false;
                break;
            case BitCondition::Equal:
                if (b1 != b2) return false;
                break;
            case BitCondition::Opposite:
                if (b1 == b2) return false;
                break;
            case BitCondition::Unconstrained:
            default:
                break;
        }
    }
    return true;
}

uint32_t DifferentialAnalysis::hamming_distance(uint32_t a, uint32_t b) noexcept {
    return popcount32(a ^ b);
}

uint32_t DifferentialAnalysis::hamming_distance(const Sha256Digest& d1, const Sha256Digest& d2) noexcept {
    uint32_t dist = 0;
    for (size_t i = 0; i < 32; ++i) {
        dist += popcount32(d1.bytes[i] ^ d2.bytes[i]);
    }
    return dist;
}

double DifferentialAnalysis::estimate_ch_diff_probability(
    uint32_t delta_e,
    uint32_t delta_f,
    uint32_t delta_g) noexcept
{
    // Ch(e, f, g) = (e & f) ^ (~e & g)
    // When e has difference: Ch(e^1, f, g) ^ Ch(e, f, g) = f ^ g
    // Each active bit in delta_e introduces condition f_i ^ g_i with prob 1/2 unless controlled
    uint32_t active_bits = popcount32(delta_e | delta_f | delta_g);
    return -static_cast<double>(active_bits);
}

double DifferentialAnalysis::estimate_maj_diff_probability(
    uint32_t delta_a,
    uint32_t delta_b,
    uint32_t delta_c) noexcept
{
    // Maj(a, b, c) active bits
    uint32_t active_bits = popcount32(delta_a | delta_b | delta_c);
    return -static_cast<double>(active_bits);
}

DifferentialTrail::TrailCheckResult DifferentialTrail::verify_pair(
    const Sha256State& iv,
    const uint8_t block1[64],
    const uint8_t block2[64]) const
{
    TrailCheckResult result;

    auto trace1 = Sha256Scalar::compress_block_trace(iv, block1, num_rounds);
    auto trace2 = Sha256Scalar::compress_block_trace(iv, block2, num_rounds);

    for (const auto& step : steps) {
        if (step.round >= num_rounds) continue;

        uint32_t dw = trace1.W[step.round] ^ trace2.W[step.round];
        if (dw != step.delta_w) {
            result.satisfied = false;
            result.failed_at_round = step.round;
            std::ostringstream oss;
            oss << "Round " << step.round << " ΔW mismatch: expected 0x"
                << std::hex << step.delta_w << ", actual 0x" << dw;
            result.failure_reason = oss.str();
            return result;
        }

        uint32_t a1 = trace1.state_at_round[step.round + 1][0];
        uint32_t a2 = trace2.state_at_round[step.round + 1][0];
        uint32_t da = a1 ^ a2;
        if (step.delta_a != 0 && da != step.delta_a) {
            result.satisfied = false;
            result.failed_at_round = step.round;
            std::ostringstream oss;
            oss << "Round " << step.round << " ΔA mismatch: expected 0x"
                << std::hex << step.delta_a << ", actual 0x" << da;
            result.failure_reason = oss.str();
            return result;
        }

        if (!step.conditions_a.matches(a1, a2)) {
            result.satisfied = false;
            result.failed_at_round = step.round;
            result.failure_reason = "Bit conditions on A violated at round " + std::to_string(step.round);
            return result;
        }
    }

    result.satisfied = true;
    return result;
}

DifferentialTrail DifferentialAnalysis::create_standard_reduced_trail(uint32_t rounds) {
    DifferentialTrail trail;
    trail.name = "Standard Linear-Difference Trail (" + std::to_string(rounds) + " rounds)";
    trail.num_rounds = rounds;
    trail.total_log2_probability = 0.0;

    // Single-bit difference injection at word W[1] bit 31
    for (uint32_t r = 0; r < rounds; ++r) {
        StepDifference step;
        step.round = r;
        if (r == 1) {
            step.delta_w = 0x80000000U; // MSB difference
            step.delta_a = 0x80000000U;
            step.delta_e = 0x80000000U;
            step.log2_probability = -1.0;
        } else {
            step.delta_w = 0;
            step.delta_a = 0;
            step.delta_e = 0;
            step.log2_probability = 0.0;
        }
        trail.total_log2_probability += step.log2_probability;
        trail.steps.push_back(step);
    }

    return trail;
}

} // namespace sha256_research
