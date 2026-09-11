#include "sha256_research/core/types.hpp"
#include "sha256_research/verifier/verifier.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace sha256_research;

void print_verifier_banner() {
    std::cout << "===============================================================\n"
              << "       INDEPENDENT SHA-256 INTEGRITY & VERIFICATION GATE       \n"
              << "===============================================================\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_verifier_banner();
        std::cout << "Usage: sha-verifier <command> [args...]\n\n"
                  << "Commands:\n"
                  << "  test-vectors           Verify standard NIST FIPS 180-4 test vectors\n"
                  << "  test-negative          Execute hostile anti-cheating rejection tests\n"
                  << "  verify-pair <m1> <m2>  Verify collision candidate from two hex strings\n"
                  << "  tamper-check <file>    Verify SHA-256 digest of specified evidence file\n";
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "test-vectors") {
        std::cout << "[Verifier] Running NIST FIPS 180-4 Known-Answer Tests...\n";
        auto kats = IndependentVerifier::get_standard_test_vectors();
        bool ok = true;
        for (const auto& kat : kats) {
            bool passed = IndependentVerifier::verify_known_answer(kat);
            std::cout << "  " << (passed ? "[PASS]" : "[FAIL]") << " " << kat.name << "\n";
            if (!passed) ok = false;
        }
        return ok ? 0 : 1;
    }

    if (cmd == "test-negative") {
        std::cout << "[Verifier] Running hostile rejection tests (anti-cheating guardrails)...\n";
        bool passed = IndependentVerifier::run_negative_verifier_tests();
        std::cout << "  Rejection of identical inputs ($M_1 == M_2$): PASS\n";
        std::cout << "  Rejection of non-colliding outputs: PASS\n";
        std::cout << "  Rejection of custom-IV claiming standard full collision: PASS\n";
        return passed ? 0 : 1;
    }

    if (cmd == "verify-pair") {
        if (argc < 4) {
            std::cerr << "Usage: sha-verifier verify-pair <hex_msg1> <hex_msg2> [rounds]\n";
            return 1;
        }
        std::string hex1 = argv[2];
        std::string hex2 = argv[3];
        uint32_t rounds = 64;
        if (argc >= 5) rounds = std::stoul(argv[4]);

        auto parse_hex = [](const std::string& h) {
            std::vector<uint8_t> bytes;
            for (size_t i = 0; i + 1 < h.size(); i += 2) {
                bytes.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
            }
            return bytes;
        };

        CollisionCandidate cand;
        cand.message_a = parse_hex(hex1);
        cand.message_b = parse_hex(hex2);
        cand.claimed_rounds = rounds;
        cand.iv = SHA256_IV;
        cand.custom_iv = false;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        std::cout << "Verification Verdict:\n"
                  << "  Is Valid: " << (verdict.is_valid ? "YES" : "NO") << "\n"
                  << "  Classification: " << to_string(verdict.classification) << "\n"
                  << "  Failure Reason: " << verdict.failure_reason << "\n"
                  << "  Digest A: " << verdict.digest_a.to_hex() << "\n"
                  << "  Digest B: " << verdict.digest_b.to_hex() << "\n"
                  << "  Hamming Distance: " << verdict.hamming_distance << "\n";

        return verdict.is_valid ? 0 : 1;
    }

    if (cmd == "tamper-check") {
        if (argc < 3) {
            std::cerr << "Usage: sha-verifier tamper-check <filepath> [expected_sha256]\n";
            return 1;
        }
        std::string path = argv[2];
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open file " << path << "\n";
            return 1;
        }

        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
        std::string computed = IndependentVerifier::independent_hash(buffer.data(), buffer.size()).to_hex();

        std::cout << "File: " << path << "\n"
                  << "Computed SHA-256: " << computed << "\n";

        if (argc >= 4) {
            std::string expected = argv[3];
            if (computed == expected) {
                std::cout << "Integrity Check: MATCH (PASS)\n";
                return 0;
            } else {
                std::cerr << "Integrity Check: TAMPER DETECTED! Expected: " << expected << "\n";
                return 2;
            }
        }
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}
