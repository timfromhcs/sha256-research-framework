#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/storage/experiment_db.hpp"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>

using namespace sha256_research;

int main() {
    std::cout << "===============================================================\n"
              << "       Adversarial & Tamper Detection Test Suite              \n"
              << "===============================================================\n";

    int passed = 0;
    int total = 0;

    // Test 1: Tampered Candidate (1 bit altered) must be detected and rejected
    total++;
    std::cout << "[Test 1] Candidate 1-bit tampering detection... ";
    {
        CollisionCandidate cand;
        cand.message_a = {'A', 'l', 'i', 'c', 'e', '1'};
        cand.message_b = {'A', 'l', 'i', 'c', 'e', '2'};
        cand.claimed_rounds = 64;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (!verdict.is_valid && verdict.classification != CandidateClassification::StandardFullCollision) {
            passed++;
            std::cout << "PASSED (Correctly rejected non-collision)\n";
        } else {
            std::cout << "FAILED (Allowed tampered candidate)\n";
        }
    }

    // Test 2: Identical message spoofing ($M_1 == M_2$)
    total++;
    std::cout << "[Test 2] Identical input spoofing rejection... ";
    {
        CollisionCandidate cand;
        cand.message_a = {'F', 'a', 'k', 'e', 'C', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n'};
        cand.message_b = {'F', 'a', 'k', 'e', 'C', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n'};
        cand.claimed_rounds = 64;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (!verdict.is_valid && verdict.classification == CandidateClassification::Invalid) {
            passed++;
            std::cout << "PASSED (Detected and rejected $M_1 == M_2$)\n";
        } else {
            std::cout << "FAILED (Trivially passed identical messages)\n";
        }
    }

    // Test 3: Artifact file tampering detected via SHA-256 hash mismatch
    total++;
    std::cout << "[Test 3] Artifact file tamper detection... ";
    {
        std::string test_file = (std::filesystem::temp_directory_path() / "test_artifact.bin").string();
        std::ofstream out(test_file, std::ios::binary);
        out << "Original pristine content 123456789";
        out.close();

        std::string original_hash = ExperimentStorage::hash_file(test_file);

        // Tamper with the file (flip one byte)
        std::ofstream tamper(test_file, std::ios::binary | std::ios::in | std::ios::out);
        tamper.seekp(0);
        tamper.put('X');
        tamper.close();

        std::string tampered_hash = ExperimentStorage::hash_file(test_file);
        std::filesystem::remove(test_file);

        if (original_hash != tampered_hash) {
            passed++;
            std::cout << "PASSED (Hash mismatch successfully triggered)\n";
        } else {
            std::cout << "FAILED (Tampered content produced identical hash)\n";
        }
    }

    // Test 4: Custom IV falsely labelled as Standard Full Collision
    total++;
    std::cout << "[Test 4] Reduced/Modified-IV misclassification prevention... ";
    {
        CollisionCandidate cand;
        cand.message_a.resize(64, 0xAA);
        cand.message_b.resize(64, 0x55);
        cand.custom_iv = true;
        cand.iv = {0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888};
        cand.claimed_rounds = 64;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (verdict.classification != CandidateClassification::StandardFullCollision) {
            passed++;
            std::cout << "PASSED (Prevented mislabeling modified-IV as full collision)\n";
        } else {
            std::cout << "FAILED (Allowed modified-IV to pass as full collision)\n";
        }
    }

    // Test 5: Reduced-round (e.g. 10 rounds) claimed as standard full 64 rounds
    total++;
    std::cout << "[Test 5] Reduced-round claimed as full collision... ";
    {
        CollisionCandidate cand;
        cand.message_a.resize(64, 0x12);
        cand.message_b.resize(64, 0x34);
        cand.claimed_rounds = 10; // Claimed 10 rounds

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (verdict.classification != CandidateClassification::StandardFullCollision) {
            passed++;
            std::cout << "PASSED (Reduced-round correctly segregated from full collision)\n";
        } else {
            std::cout << "FAILED (Reduced round classified as standard full collision)\n";
        }
    }

    // Test 6: Zero rounds claimed (impossible configuration) must be rejected
    total++;
    std::cout << "[Test 6] Zero-round configuration rejection... ";
    {
        CollisionCandidate cand;
        cand.message_a = {'A'};
        cand.message_b = {'B'};
        cand.claimed_rounds = 0;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (!verdict.is_valid && verdict.classification == CandidateClassification::Invalid) {
            passed++;
            std::cout << "PASSED (Correctly rejected zero-round configuration)\n";
        } else {
            std::cout << "FAILED (Accepted or misclassified zero rounds)\n";
        }
    }

    // Test 7: Over-claimed rounds (> 64) must be rejected
    total++;
    std::cout << "[Test 7] Over-claimed rounds rejection (> 64)... ";
    {
        CollisionCandidate cand;
        cand.message_a = {'A'};
        cand.message_b = {'B'};
        cand.claimed_rounds = 100;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (!verdict.is_valid && verdict.classification == CandidateClassification::Invalid) {
            passed++;
            std::cout << "PASSED (Correctly rejected rounds > 64)\n";
        } else {
            std::cout << "FAILED (Accepted or misclassified rounds > 64)\n";
        }
    }

    // Test 8: Forged metadata cannot override verification
    total++;
    std::cout << "[Test 8] Forged metadata authority rejection... ";
    {
        CollisionCandidate cand;
        cand.message_a = {'N', 'o', 't'};
        cand.message_b = {'C', 'o', 'l', 'l', 'i', 'd', 'i', 'n', 'g'};
        cand.claimed_rounds = 64;
        cand.generator_metadata = "{\"verified\": true, \"status\": \"CONFIRMED\", \"classification\": \"StandardFullCollision\"}";

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);
        if (!verdict.is_valid && verdict.classification != CandidateClassification::StandardFullCollision) {
            passed++;
            std::cout << "PASSED (Metadata override attempt defeated)\n";
        } else {
            std::cout << "FAILED (Metadata permitted forgery to pass)\n";
        }
    }

    // Test 9: Preimage candidate 1-bit tampering detection
    total++;
    std::cout << "[Test 9] Preimage candidate 1-bit tampering detection... ";
    {
        PreimageCandidate cand;
        cand.message.resize(64, 0xAA);
        cand.claimed_rounds = 16;
        cand.iv = SHA256_IV;
        cand.custom_iv = false;

        // Compute genuine 16-round digest
        Sha256State st = SHA256_IV;
        IndependentVerifier::independent_compress_block(st, cand.message.data(), 16);
        for (size_t i = 0; i < 8; ++i) {
            cand.target_digest.bytes[i * 4 + 0] = static_cast<uint8_t>(st[i] >> 24);
            cand.target_digest.bytes[i * 4 + 1] = static_cast<uint8_t>(st[i] >> 16);
            cand.target_digest.bytes[i * 4 + 2] = static_cast<uint8_t>(st[i] >> 8);
            cand.target_digest.bytes[i * 4 + 3] = static_cast<uint8_t>(st[i]);
        }

        // Tamper 1 byte of message
        cand.message[0] ^= 0x01;

        auto verdict = IndependentVerifier::verify_preimage_candidate(cand);
        if (!verdict.is_valid && verdict.classification == CandidateClassification::Invalid) {
            passed++;
            std::cout << "PASSED (Tampered preimage rejected)\n";
        } else {
            std::cout << "FAILED (Accepted tampered preimage)\n";
        }
    }

    // Test 10: Preimage custom-IV misclassification prevention
    total++;
    std::cout << "[Test 10] Preimage custom-IV misclassification prevention... ";
    {
        PreimageCandidate cand;
        cand.message.resize(64, 0x42);
        cand.claimed_rounds = 64;
        cand.custom_iv = true;
        cand.iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        Sha256State st = cand.iv;
        IndependentVerifier::independent_compress_block(st, cand.message.data(), 64);
        for (size_t i = 0; i < 8; ++i) {
            cand.target_digest.bytes[i * 4 + 0] = static_cast<uint8_t>(st[i] >> 24);
            cand.target_digest.bytes[i * 4 + 1] = static_cast<uint8_t>(st[i] >> 16);
            cand.target_digest.bytes[i * 4 + 2] = static_cast<uint8_t>(st[i] >> 8);
            cand.target_digest.bytes[i * 4 + 3] = static_cast<uint8_t>(st[i]);
        }

        auto verdict = IndependentVerifier::verify_preimage_candidate(cand);
        if (verdict.is_valid && verdict.classification != CandidateClassification::StandardFullPreimage) {
            passed++;
            std::cout << "PASSED (Prevented mislabeling custom-IV as full preimage)\n";
        } else {
            std::cout << "FAILED (Misclassified custom-IV preimage as standard full preimage)\n";
        }
    }

    // Test 11: Preimage forged metadata authority rejection
    total++;
    std::cout << "[Test 11] Preimage forged metadata authority rejection... ";
    {
        PreimageCandidate cand;
        cand.message.resize(64, 0x55);
        cand.target_digest = Sha256Digest::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        cand.claimed_rounds = 64;
        cand.generator_metadata = "{\"verified\": true, \"status\": \"CONFIRMED\", \"classification\": \"StandardFullPreimage\"}";

        auto verdict = IndependentVerifier::verify_preimage_candidate(cand);
        if (!verdict.is_valid && verdict.classification != CandidateClassification::StandardFullPreimage) {
            passed++;
            std::cout << "PASSED (Metadata override attempt on preimage defeated)\n";
        } else {
            std::cout << "FAILED (Metadata permitted forged preimage to pass)\n";
        }
    }

    std::cout << "===============================================================\n"
              << "  Adversarial Results: " << passed << " / " << total << " passed\n"
              << "===============================================================\n";

    return (passed == total) ? 0 : 1;
}
