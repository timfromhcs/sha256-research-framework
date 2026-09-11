#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/sat/sat_encoder.hpp"
#include "sha256_research/differential/diff_trail.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>

using namespace sha256_research;

int main() {
    std::cout << "===============================================================\n"
              << "       Deterministic Behavior & Reproducibility Test Suite     \n"
              << "===============================================================\n";

    int passed = 0;
    int total = 0;

    // Test 1: Repeated single-block and multi-block hashing determinism across runs A, B, C
    total++;
    std::cout << "[Test 1] Repeated scalar hashing determinism (Runs A, B, C)... ";
    {
        std::vector<uint8_t> data(128);
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 31 + 7);

        Sha256Digest runA = Sha256Scalar::hash(data.data(), data.size());
        Sha256Digest runB = Sha256Scalar::hash(data.data(), data.size());
        Sha256Digest runC = Sha256Scalar::hash(data.data(), data.size());

        if (runA == runB && runB == runC) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Nondeterministic scalar hashing output)\n";
        }
    }

    // Test 2: Repeated optimized CPU hashing determinism across runs A, B, C
    total++;
    std::cout << "[Test 2] Repeated optimized CPU hashing determinism (Runs A, B, C)... ";
    {
        std::vector<uint8_t> data(256);
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 17 + 3);

        Sha256Digest runA = Sha256Optimized::hash(data.data(), data.size());
        Sha256Digest runB = Sha256Optimized::hash(data.data(), data.size());
        Sha256Digest runC = Sha256Optimized::hash(data.data(), data.size());

        if (runA == runB && runB == runC) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Nondeterministic optimized hashing output)\n";
        }
    }

    // Test 3: Repeated independent verifier hashing determinism across runs A, B, C
    total++;
    std::cout << "[Test 3] Repeated independent verifier hashing determinism (Runs A, B, C)... ";
    {
        std::vector<uint8_t> data(300);
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 43 + 19);

        Sha256Digest runA = IndependentVerifier::independent_hash(data.data(), data.size());
        Sha256Digest runB = IndependentVerifier::independent_hash(data.data(), data.size());
        Sha256Digest runC = IndependentVerifier::independent_hash(data.data(), data.size());

        if (runA == runB && runB == runC) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Nondeterministic independent verifier output)\n";
        }
    }

    // Test 4: Cross-engine determinism parity (Scalar == Optimized == IndependentVerifier)
    total++;
    std::cout << "[Test 4] Cross-engine deterministic parity (Scalar == Opt == Verifier)... ";
    {
        bool all_matched = true;
        for (size_t len : {0, 1, 55, 56, 64, 65, 119, 120, 128, 500}) {
            std::vector<uint8_t> data(len);
            for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>((i * 5 + 11) & 0xFF);

            Sha256Digest s = Sha256Scalar::hash(data.data(), len);
            Sha256Digest o = Sha256Optimized::hash(data.data(), len);
            Sha256Digest v = IndependentVerifier::independent_hash(data.data(), len);

            if (s != o || s != v) {
                all_matched = false;
                break;
            }
        }
        if (all_matched) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Discrepancy among engines)\n";
        }
    }

    // Test 5: Multithreaded batch hashing determinism across thread counts
    total++;
    std::cout << "[Test 5] Parallel batch hashing determinism (1, 2, 4, 8, 16 threads)... ";
    {
        const size_t msg_len = 64;
        const size_t count = 256;
        std::vector<uint8_t> in_data(msg_len * count);
        for (size_t i = 0; i < in_data.size(); ++i) in_data[i] = static_cast<uint8_t>(i & 0xFF);

        std::vector<Sha256Digest> ref(count);
        Sha256Optimized::hash_batch(in_data.data(), msg_len, count, ref.data(), 1);

        bool threads_matched = true;
        for (unsigned int tc : {2, 4, 8, 16}) {
            std::vector<Sha256Digest> out(count);
            Sha256Optimized::hash_batch(in_data.data(), msg_len, count, out.data(), tc);

            for (size_t i = 0; i < count; ++i) {
                if (out[i] != ref[i]) {
                    threads_matched = false;
                    break;
                }
            }
            if (!threads_matched) break;
        }

        if (threads_matched) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Thread-count dependent output)\n";
        }
    }

    // Test 6: Deterministic search range partition
    total++;
    std::cout << "[Test 6] Search range partition determinism... ";
    {
        auto pA = Sha256Optimized::partition_range(1000003, 8);
        auto pB = Sha256Optimized::partition_range(1000003, 8);
        auto pC = Sha256Optimized::partition_range(1000003, 8);

        if (pA == pB && pB == pC && !pA.empty()) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Nondeterministic range partition)\n";
        }
    }

    // Test 7: Deterministic SAT CNF generation and DIMACS serialization
    total++;
    std::cout << "[Test 7] SAT CNF encoding & DIMACS serialization determinism... ";
    {
        SatEncoder::Sha256ProblemConfig cfg;
        cfg.num_rounds = 4;
        cfg.use_standard_iv = true;

        auto encA = SatEncoder::encode_reduced_rounds(cfg);
        auto encB = SatEncoder::encode_reduced_rounds(cfg);

        std::string dimacsA = encA.cnf.to_dimacs();
        std::string dimacsB = encB.cnf.to_dimacs();

        if (encA.cnf.num_vars == encB.cnf.num_vars &&
            encA.cnf.clauses.size() == encB.cnf.clauses.size() &&
            dimacsA == dimacsB) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Nondeterministic CNF formula generation)\n";
        }
    }

    // Test 8: Deterministic differential trail evaluation
    total++;
    std::cout << "[Test 8] Differential trail verification determinism... ";
    {
        auto trail = DifferentialAnalysis::create_standard_reduced_trail(2);
        Sha256State iv = SHA256_IV;
        uint8_t b1[64] = {0};
        uint8_t b2[64] = {0};
        b1[4] = 0x80;

        auto resA = trail.verify_pair(iv, b1, b2);
        auto resB = trail.verify_pair(iv, b1, b2);

        if (resA.satisfied == resB.satisfied &&
            resA.failed_at_round == resB.failed_at_round &&
            resA.failure_reason == resB.failure_reason) {
            passed++;
            std::cout << "PASSED\n";
        } else {
            std::cout << "FAILED (Nondeterministic differential trail verification)\n";
        }
    }

    std::cout << "===============================================================\n"
              << "  Determinism Results: " << passed << " / " << total << " passed\n"
              << "===============================================================\n";

    return (passed == total) ? 0 : 1;
}
