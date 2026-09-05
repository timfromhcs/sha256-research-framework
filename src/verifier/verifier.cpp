#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/differential/diff_trail.hpp"
#include <chrono>
#include <iostream>

namespace sha256_research {

std::string to_string(CandidateClassification c) {
    switch (c) {
        case CandidateClassification::Invalid: return "Invalid";
        case CandidateClassification::ReducedRoundCollision: return "ReducedRoundCollision";
        case CandidateClassification::ReducedRoundPreimage: return "ReducedRoundPreimage";
        case CandidateClassification::SemiFreeStartCollision: return "SemiFreeStartCollision";
        case CandidateClassification::ModifiedIvCollision: return "ModifiedIvCollision";
        case CandidateClassification::LocalCollision: return "LocalCollision";
        case CandidateClassification::NearCollision: return "NearCollision";
        case CandidateClassification::DifferentialCharacteristic: return "DifferentialCharacteristic";
        case CandidateClassification::SolverModelOnly: return "SolverModelOnly";
        case CandidateClassification::StandardFullCollision: return "StandardFullCollision";
    }
    return "Unknown";
}

VerificationVerdict IndependentVerifier::verify_collision_candidate(const CollisionCandidate& candidate) {
    auto t0 = std::chrono::high_resolution_clock::now();
    VerificationVerdict verdict;
    // Clamp: compression only supports 0..64 rounds; record effective rounds.
    // NOTE: generator_metadata is never consulted: candidates cannot force
    // a "verified" result through metadata alone (see adversarial tests).
    const uint32_t eff_rounds = (candidate.claimed_rounds > 64U) ? 64U : candidate.claimed_rounds;
    verdict.actual_rounds = eff_rounds;

    // Rule 1: A collision requires distinct inputs (message A != message B)
    if (candidate.message_a.empty() || candidate.message_b.empty()) {
        verdict.is_valid = false;
        verdict.classification = CandidateClassification::Invalid;
        verdict.failure_reason = "Message A or Message B is empty";
        return verdict;
    }

    if (candidate.message_a == candidate.message_b) {
        verdict.is_valid = false;
        verdict.classification = CandidateClassification::Invalid;
        verdict.failure_reason = "Trivial rejection: Message A is identical to Message B";
        return verdict;
    }

    // Compute independent hashes
    if (eff_rounds < 64 || candidate.custom_iv) {
        // Reduced round or custom IV single-block compression evaluation
        if (candidate.message_a.size() != 64 || candidate.message_b.size() != 64) {
            verdict.is_valid = false;
            verdict.classification = CandidateClassification::Invalid;
            verdict.failure_reason = "Reduced-round / custom IV candidate must provide exact 64-byte blocks";
            return verdict;
        }

        Sha256State state_a = candidate.iv;
        Sha256State state_b = candidate.iv;
        Sha256Scalar::compress_block(state_a, candidate.message_a.data(), eff_rounds);
        Sha256Scalar::compress_block(state_b, candidate.message_b.data(), eff_rounds);

        for (size_t i = 0; i < 8; ++i) {
            store_be32(verdict.digest_a.bytes.data() + i * 4, state_a[i]);
            store_be32(verdict.digest_b.bytes.data() + i * 4, state_b[i]);
        }
    } else {
        // Standard full SHA-256 evaluation
        verdict.digest_a = Sha256Scalar::hash(candidate.message_a.data(), candidate.message_a.size());
        verdict.digest_b = Sha256Scalar::hash(candidate.message_b.data(), candidate.message_b.size());
    }

    verdict.hamming_distance = DifferentialAnalysis::hamming_distance(verdict.digest_a, verdict.digest_b);

    if (verdict.digest_a != verdict.digest_b) {
        verdict.is_valid = false;
        if (verdict.hamming_distance <= 16) {
            // Framework heuristic label only (NOT a cryptographic standard):
            // digests within 16 bits are reported as NearCollision for triage.
            verdict.classification = CandidateClassification::NearCollision;
            verdict.failure_reason = "Hashes differ by " + std::to_string(verdict.hamming_distance) + " bits (NearCollision; framework triage threshold 16 bits, not a standard)";
        } else {
            verdict.classification = CandidateClassification::Invalid;
            verdict.failure_reason = "Hashes do not match (Hamming distance = " + std::to_string(verdict.hamming_distance) + ")";
        }
    } else {
        // Hashes match! Classify precisely
        verdict.is_valid = true;
        if (eff_rounds == 64 && !candidate.custom_iv && candidate.iv == SHA256_IV) {
            // Full SHA-256 standard collision gate
            verdict.classification = CandidateClassification::StandardFullCollision;
        } else if (candidate.custom_iv || candidate.iv != SHA256_IV) {
            verdict.classification = CandidateClassification::SemiFreeStartCollision;
        } else if (eff_rounds < 64) {
            verdict.classification = CandidateClassification::ReducedRoundCollision;
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> diff = t1 - t0;
    verdict.verification_time_us = diff.count();

    return verdict;
}

std::vector<IndependentVerifier::KnownAnswerVector> IndependentVerifier::get_standard_test_vectors() {
    return {
        {
            "NIST KAT Empty String",
            {},
            Sha256Digest::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        },
        {
            "NIST KAT 'abc'",
            {'a', 'b', 'c'},
            Sha256Digest::from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        },
        {
            "NIST KAT 56-byte message",
            std::vector<uint8_t>{
                'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e', 'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g',
                'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i', 'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k',
                'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm', 'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o',
                'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q'
            },
            Sha256Digest::from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        },
        {
            "NIST KAT 112-byte message",
            std::vector<uint8_t>{
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u'
            },
            Sha256Digest::from_hex("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
        }
    };
}

bool IndependentVerifier::verify_known_answer(const KnownAnswerVector& kat) {
    Sha256Digest computed = Sha256Scalar::hash(kat.message.data(), kat.message.size());
    return (computed == kat.expected_digest);
}

bool IndependentVerifier::run_negative_verifier_tests() {
    // Negative test 1: Identical messages claimed as collision -> MUST REJECT
    CollisionCandidate cand1;
    cand1.message_a = {'t', 'e', 's', 't'};
    cand1.message_b = {'t', 'e', 's', 't'};
    auto v1 = verify_collision_candidate(cand1);
    if (v1.is_valid || v1.classification != CandidateClassification::Invalid) {
        std::cerr << "[IndependentVerifier] Negative test 1 failed: did not reject identical inputs!\n";
        return false;
    }

    // Negative test 2: Completely different messages with different hashes -> MUST REJECT
    CollisionCandidate cand2;
    cand2.message_a = {'f', 'o', 'o'};
    cand2.message_b = {'b', 'a', 'r'};
    auto v2 = verify_collision_candidate(cand2);
    if (v2.is_valid || v2.classification == CandidateClassification::StandardFullCollision) {
        std::cerr << "[IndependentVerifier] Negative test 2 failed: accepted non-colliding messages!\n";
        return false;
    }

    // Negative test 3: Custom IV candidate falsely claimed as standard full collision -> MUST NOT classify as StandardFullCollision
    CollisionCandidate cand3;
    cand3.message_a.resize(64, 0x01);
    cand3.message_b.resize(64, 0x02);
    cand3.custom_iv = true;
    cand3.iv = {1, 2, 3, 4, 5, 6, 7, 8};
    auto v3 = verify_collision_candidate(cand3);
    if (v3.classification == CandidateClassification::StandardFullCollision) {
        std::cerr << "[IndependentVerifier] Negative test 3 failed: allowed custom IV as StandardFullCollision!\n";
        return false;
    }

    return true;
}

} // namespace sha256_research
