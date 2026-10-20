#include "sha256_research/core/types.hpp"
#include "sha256_research/verifier/verifier.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace sha256_research;

#ifndef SHA256_RESEARCH_VERSION
#define SHA256_RESEARCH_VERSION "5.1.0"
#endif

void print_verifier_banner() {
    std::cout << "===============================================================\n"
              << "   INDEPENDENT SHA-256 INTEGRITY & VERIFICATION GATE (v" << SHA256_RESEARCH_VERSION << ") \n"
              << "===============================================================\n";
}

namespace {

// Minimal JSON string escaper. The verifier is the trust boundary for the
// Python platform, so its machine-readable output must be unambiguous.
std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c);
                    out += oss.str();
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// Emit a VerificationVerdict as a single-line JSON object.
// Schema is stable: consumers must parse this, never human-readable stdout.
void emit_verdict_json(const std::string& kind, const VerificationVerdict& v) {
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"" << json_escape(kind) << "\","
        << "\"is_valid\":" << (v.is_valid ? "true" : "false") << ","
        << "\"classification\":\"" << json_escape(to_string(v.classification)) << "\","
        << "\"failure_reason\":\"" << json_escape(v.failure_reason) << "\","
        << "\"digest_a\":\"" << v.digest_a.to_hex() << "\","
        << "\"digest_b\":\"" << v.digest_b.to_hex() << "\","
        << "\"actual_rounds\":" << v.actual_rounds << ","
        << "\"claimed_rounds\":" << v.actual_rounds << ","
        << "\"hamming_distance\":" << v.hamming_distance << ","
        << "\"verification_time_us\":" << v.verification_time_us << ","
        << "\"verifier_engine\":\"IndependentVerifier\","
        << "\"engine_segregated\":true"
        << "}";
    std::cout << oss.str() << std::endl;
}

bool wants_json(int argc, char** argv, int from) {
    for (int i = from; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") return true;
    }
    return false;
}

std::vector<uint8_t> parse_hex_bytes(const std::string& h) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_verifier_banner();
        std::cout << "Usage: sha-verifier <command> [args...]\n\n"
                  << "Commands:\n"
                  << "  test-vectors           Verify standard NIST FIPS 180-4 test vectors\n"
                  << "  test-negative          Execute hostile anti-cheating rejection tests\n"
                  << "  verify-pair <m1> <m2> [rounds] [--json]  Verify collision candidate from two hex strings\n"
                  << "  verify-preimage <m> <t> [rounds] [--json] Verify preimage candidate against target digest\n"
                  << "  tamper-check <file>    Verify SHA-256 digest of specified evidence file\n\n"
                  << "Global options:\n"
                  << "  --json                 Emit the verdict as a single-line JSON object on stdout.\n"
                  << "                         Machine-readable contract for the Python platform; exit\n"
                  << "                         code 0 = valid, 1 = invalid.\n";
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "--version" || cmd == "-v" || cmd == "version") {
        std::cout << "sha-verifier " << SHA256_RESEARCH_VERSION << "\n";
        return 0;
    }

    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_verifier_banner();
        std::cout << "Usage: sha-verifier <command> [args...]\n\n"
                  << "Commands:\n"
                  << "  test-vectors           Verify standard NIST FIPS 180-4 test vectors\n"
                  << "  test-negative          Execute hostile anti-cheating rejection tests\n"
                  << "  verify-pair <m1> <m2> [rounds] [--json]  Verify collision candidate from two hex strings\n"
                  << "  verify-preimage <m> <t> [rounds] [--json] Verify preimage candidate against target digest\n"
                  << "  tamper-check <file>    Verify SHA-256 digest of specified evidence file\n\n"
                  << "Global options:\n"
                  << "  --json                 Emit the verdict as a single-line JSON object on stdout.\n"
                  << "                         Machine-readable contract for the Python platform; exit\n"
                  << "                         code 0 = valid, 1 = invalid.\n";
        return 0;
    }

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
            std::cerr << "Usage: sha-verifier verify-pair <hex_msg1> <hex_msg2> [rounds] [--json]\n";
            return 1;
        }
        std::string hex1 = argv[2];
        std::string hex2 = argv[3];
        uint32_t rounds = 64;
        if (argc >= 5) rounds = std::stoul(argv[4]);

        CollisionCandidate cand;
        cand.message_a = parse_hex_bytes(hex1);
        cand.message_b = parse_hex_bytes(hex2);
        cand.claimed_rounds = rounds;
        cand.iv = SHA256_IV;
        cand.custom_iv = false;

        auto verdict = IndependentVerifier::verify_collision_candidate(cand);

        if (wants_json(argc, argv, 4)) {
            emit_verdict_json("collision", verdict);
        } else {
            std::cout << "Verification Verdict:\n"
                      << "  Is Valid: " << (verdict.is_valid ? "YES" : "NO") << "\n"
                      << "  Classification: " << to_string(verdict.classification) << "\n"
                      << "  Failure Reason: " << verdict.failure_reason << "\n"
                      << "  Digest A: " << verdict.digest_a.to_hex() << "\n"
                      << "  Digest B: " << verdict.digest_b.to_hex() << "\n"
                      << "  Hamming Distance: " << verdict.hamming_distance << "\n";
        }

        return verdict.is_valid ? 0 : 1;
    }

    if (cmd == "verify-preimage") {
        if (argc < 4) {
            std::cerr << "Usage: sha-verifier verify-preimage <hex_msg> <hex_target> [rounds] [--json]\n";
            return 1;
        }
        std::string hex_msg = argv[2];
        std::string hex_target = argv[3];
        uint32_t rounds = 64;
        if (argc >= 5) rounds = std::stoul(argv[4]);

        PreimageCandidate cand;
        cand.message = parse_hex_bytes(hex_msg);
        cand.target_digest = Sha256Digest::from_hex(hex_target);
        cand.claimed_rounds = rounds;
        cand.iv = SHA256_IV;
        cand.custom_iv = false;

        auto verdict = IndependentVerifier::verify_preimage_candidate(cand);

        if (wants_json(argc, argv, 4)) {
            emit_verdict_json("preimage", verdict);
        } else {
            std::cout << "Preimage Verification Verdict:\n"
                      << "  Is Valid: " << (verdict.is_valid ? "YES" : "NO") << "\n"
                      << "  Classification: " << to_string(verdict.classification) << "\n"
                      << "  Failure Reason: " << verdict.failure_reason << "\n"
                      << "  Computed Digest: " << verdict.digest_a.to_hex() << "\n"
                      << "  Target Digest:   " << verdict.digest_b.to_hex() << "\n"
                      << "  Hamming Distance: " << verdict.hamming_distance << "\n";
        }

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
