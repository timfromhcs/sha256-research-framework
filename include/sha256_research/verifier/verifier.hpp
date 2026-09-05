#pragma once

#include "sha256_research/core/types.hpp"
#include <string>
#include <vector>
#include <optional>

namespace sha256_research {

enum class CandidateClassification {
    Invalid,
    ReducedRoundCollision,
    SemiFreeStartCollision,
    ModifiedIvCollision,
    LocalCollision,
    NearCollision,
    DifferentialCharacteristic,
    SolverModelOnly,
    StandardFullCollision
};

std::string to_string(CandidateClassification c);

struct CollisionCandidate {
    std::vector<uint8_t> message_a;
    std::vector<uint8_t> message_b;
    Sha256State iv{SHA256_IV};
    bool custom_iv{false};
    uint32_t claimed_rounds{64};
    std::string generator_metadata;
};

struct VerificationVerdict {
    bool is_valid{false};
    CandidateClassification classification{CandidateClassification::Invalid};
    std::string failure_reason;
    Sha256Digest digest_a{};
    Sha256Digest digest_b{};
    uint32_t actual_rounds{64};
    uint32_t hamming_distance{0};
    double verification_time_us{0.0};
};

class IndependentVerifier {
public:
    IndependentVerifier() = default;

    // Strict verification of collision candidate
    static VerificationVerdict verify_collision_candidate(const CollisionCandidate& candidate);

    // Verify known-answer test vectors (NIST CAVP / FIPS 180-4 standard vectors)
    struct KnownAnswerVector {
        std::string name;
        std::vector<uint8_t> message;
        Sha256Digest expected_digest;
    };

    static bool verify_known_answer(const KnownAnswerVector& kat);
    static std::vector<KnownAnswerVector> get_standard_test_vectors();

    // Negative verification test suite: tests known corrupted/altered inputs to confirm rejection
    static bool run_negative_verifier_tests();
};

} // namespace sha256_research
