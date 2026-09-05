#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/differential/diff_trail.hpp"
#include "sha256_research/sat/sat_encoder.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/vulkan/sha256_vulkan.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <cassert>

using namespace sha256_research;

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define RUN_TEST(fn) \
    do { \
        g_tests_run++; \
        std::cout << "[RUN]  " << #fn << "... "; \
        try { \
            fn(); \
            g_tests_passed++; \
            std::cout << "PASSED\n"; \
        } catch (const std::exception& e) { \
            std::cout << "FAILED (" << e.what() << ")\n"; \
        } catch (...) { \
            std::cout << "FAILED (unknown exception)\n"; \
        } \
    } while(0)

void test_nist_known_answer_vectors() {
    auto kats = IndependentVerifier::get_standard_test_vectors();
    for (const auto& kat : kats) {
        bool ok = IndependentVerifier::verify_known_answer(kat);
        if (!ok) throw std::runtime_error("KAT failed: " + kat.name);
    }
}

void test_streaming_chunked_hashing() {
    Sha256Scalar s1;
    s1.update("hello ", 6);
    s1.update("world", 5);
    Sha256Digest d1 = s1.finalize();

    Sha256Digest d2 = Sha256Scalar::hash("hello world");
    if (d1 != d2) throw std::runtime_error("Chunked update differed from single hash");
}

void test_cpu_backend_equivalence() {
    // Test multiple lengths: 0, 1, 54, 55, 56, 64, 128
    std::vector<size_t> test_lens = {0, 1, 15, 32, 54, 55, 56, 64, 100, 128};
    for (size_t len : test_lens) {
        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>((i * 13 + 37) & 0xFF);

        Sha256Digest scalar_d = Sha256Scalar::hash(data.data(), len);
        Sha256Digest opt_d = Sha256Optimized::hash(data.data(), len);

        if (scalar_d != opt_d) {
            throw std::runtime_error("Scalar and Optimized CPU disagree at length " + std::to_string(len));
        }
    }
}

void test_differential_trail_verification() {
    auto trail = DifferentialAnalysis::create_standard_reduced_trail(2);
    Sha256State iv = SHA256_IV;
    uint8_t b1[64] = {0};
    uint8_t b2[64] = {0};
    b1[4] = 0x80; // W[1] MSB

    auto res = trail.verify_pair(iv, b1, b2);
    if (!res.satisfied) {
        throw std::runtime_error("Differential trail failed: " + res.failure_reason);
    }
}

void test_sat_encoder_tseitin_basic() {
    CnfFormula cnf;
    int a = cnf.new_var();
    int b = cnf.new_var();
    int out = cnf.new_var();
    SatEncoder::encode_xor2(cnf, a, b, out);
    if (cnf.clauses.size() != 4) throw std::runtime_error("encode_xor2 clause count != 4");

    // 1-round reduced SHA-256 CNF generation
    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = 1;
    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    if (enc.cnf.clauses.empty() || enc.cnf.num_vars == 0) {
        throw std::runtime_error("SAT encoding failed to generate variables/clauses");
    }
}

void test_independent_verifier_rejection_gate() {
    bool ok = IndependentVerifier::run_negative_verifier_tests();
    if (!ok) throw std::runtime_error("Verifier negative integrity gate failed");
}

void test_vulkan_smoke() {
    Sha256VulkanEngine vk;
    if (vk.initialize("shaders")) {
        auto res = vk.run_smoke_test(256, 64);
        if (!res.verified_against_cpu) {
            throw std::runtime_error("Vulkan compute mismatch against CPU reference");
        }
    } else {
        std::cout << "[Vulkan unavailable, skipping Vulkan GPU test] ";
    }
}

int main() {
    std::cout << "===============================================================\n"
              << "            SHA-256 Framework Test Suite                       \n"
              << "===============================================================\n";

    RUN_TEST(test_nist_known_answer_vectors);
    RUN_TEST(test_streaming_chunked_hashing);
    RUN_TEST(test_cpu_backend_equivalence);
    RUN_TEST(test_differential_trail_verification);
    RUN_TEST(test_sat_encoder_tseitin_basic);
    RUN_TEST(test_independent_verifier_rejection_gate);
    RUN_TEST(test_vulkan_smoke);

    std::cout << "===============================================================\n"
              << "  Results: " << g_tests_passed << " / " << g_tests_run << " passed\n"
              << "===============================================================\n";

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
