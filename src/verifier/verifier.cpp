#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/differential/diff_trail.hpp"
#include <chrono>
#include <iostream>
#include <cstring>

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

namespace {

// Segregated independent FIPS 180-4 round constants K[0..63]
constexpr uint32_t INDEP_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

constexpr uint32_t INDEP_IV[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

inline constexpr uint32_t indep_rotr(uint32_t x, uint32_t n) noexcept {
    return (x >> n) | (x << ((32 - n) & 31));
}

inline constexpr uint32_t indep_ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

inline constexpr uint32_t indep_maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline constexpr uint32_t indep_sigma0(uint32_t x) noexcept {
    return indep_rotr(x, 2) ^ indep_rotr(x, 13) ^ indep_rotr(x, 22);
}

inline constexpr uint32_t indep_sigma1(uint32_t x) noexcept {
    return indep_rotr(x, 6) ^ indep_rotr(x, 11) ^ indep_rotr(x, 25);
}

inline constexpr uint32_t indep_gamma0(uint32_t x) noexcept {
    return indep_rotr(x, 7) ^ indep_rotr(x, 18) ^ (x >> 3);
}

inline constexpr uint32_t indep_gamma1(uint32_t x) noexcept {
    return indep_rotr(x, 17) ^ indep_rotr(x, 19) ^ (x >> 10);
}

inline uint32_t indep_load_be32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}

inline void indep_store_be32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

void indep_compress(uint32_t state[8], const uint8_t block[64], uint32_t rounds) noexcept {
    uint32_t W[64];
    for (size_t t = 0; t < 16; ++t) {
        W[t] = indep_load_be32(block + t * 4);
    }
    for (size_t t = 16; t < 64; ++t) {
        W[t] = indep_gamma1(W[t - 2]) + W[t - 7] + indep_gamma0(W[t - 15]) + W[t - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (uint32_t t = 0; t < rounds; ++t) {
        uint32_t t1 = h + indep_sigma1(e) + indep_ch(e, f, g) + INDEP_K[t] + W[t];
        uint32_t t2 = indep_sigma0(a) + indep_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

} // namespace

void IndependentVerifier::independent_compress_block(Sha256State& state, const uint8_t block[64], uint32_t num_rounds) noexcept {
    uint32_t rounds = num_rounds > 64 ? 64 : num_rounds;
    indep_compress(state.data(), block, rounds);
}

Sha256Digest IndependentVerifier::independent_hash(const void* data, size_t len) noexcept {
    uint32_t state[8];
    for (size_t i = 0; i < 8; ++i) state[i] = INDEP_IV[i];

    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t total_bits = static_cast<uint64_t>(len) * 8ULL;

    size_t full_blocks = len / 64;
    for (size_t b = 0; b < full_blocks; ++b) {
        indep_compress(state, p + b * 64, 64);
    }

    size_t rem = len % 64;
    uint8_t buffer[128] = {0};
    if (rem > 0) {
        std::memcpy(buffer, p + full_blocks * 64, rem);
    }
    buffer[rem++] = 0x80;

    if (rem > 56) {
        indep_compress(state, buffer, 64);
        uint8_t second_block[64] = {0};
        for (int i = 7; i >= 0; --i) {
            second_block[56 + i] = static_cast<uint8_t>(total_bits & 0xFF);
            total_bits >>= 8;
        }
        indep_compress(state, second_block, 64);
    } else {
        uint8_t block[64] = {0};
        std::memcpy(block, buffer, rem);
        for (int i = 7; i >= 0; --i) {
            block[56 + i] = static_cast<uint8_t>(total_bits & 0xFF);
            total_bits >>= 8;
        }
        indep_compress(state, block, 64);
    }

    Sha256Digest d;
    for (size_t i = 0; i < 8; ++i) {
        indep_store_be32(d.bytes.data() + i * 4, state[i]);
    }
    return d;
}

VerificationVerdict IndependentVerifier::verify_collision_candidate(const CollisionCandidate& candidate) {
    auto t0 = std::chrono::high_resolution_clock::now();
    VerificationVerdict verdict;

    // Reject malformed or impossible configurations explicitly (GEMINI.md requirement)
    if (candidate.claimed_rounds == 0) {
        verdict.actual_rounds = 0;
        verdict.is_valid = false;
        verdict.classification = CandidateClassification::Invalid;
        verdict.failure_reason = "Invalid round count: claimed_rounds cannot be 0";
        return verdict;
    }

    if (candidate.claimed_rounds > 64) {
        verdict.actual_rounds = 64;
        verdict.is_valid = false;
        verdict.classification = CandidateClassification::Invalid;
        verdict.failure_reason = "Invalid round count: claimed_rounds (" + std::to_string(candidate.claimed_rounds) + ") exceeds standard maximum 64";
        return verdict;
    }

    const uint32_t eff_rounds = candidate.claimed_rounds;
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

    // Compute independent hashes using segregated reference engine
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
        independent_compress_block(state_a, candidate.message_a.data(), eff_rounds);
        independent_compress_block(state_b, candidate.message_b.data(), eff_rounds);

        for (size_t i = 0; i < 8; ++i) {
            indep_store_be32(verdict.digest_a.bytes.data() + i * 4, state_a[i]);
            indep_store_be32(verdict.digest_b.bytes.data() + i * 4, state_b[i]);
        }
    } else {
        // Standard full SHA-256 evaluation
        verdict.digest_a = independent_hash(candidate.message_a.data(), candidate.message_a.size());
        verdict.digest_b = independent_hash(candidate.message_b.data(), candidate.message_b.size());
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
    Sha256Digest computed = independent_hash(kat.message.data(), kat.message.size());
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
