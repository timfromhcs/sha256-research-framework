#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include <iostream>
#include <vector>
#include <string>

int main() {
    // Create a vector of 1,000,000 'a's
    std::vector<uint8_t> data(1000000, 'a');

    // Compute using scalar reference
    sha256_research::Sha256Scalar scalar;
    scalar.update(data.data(), data.size());
    sha256_research::Sha256Digest hash_scalar = scalar.finalize();

    // Compute using optimized backend
    sha256_research::Sha256Digest hash_optimized = sha256_research::Sha256Optimized::hash(data.data(), data.size());

    // Compute using segregated independent verifier
    sha256_research::Sha256Digest hash_verifier = sha256_research::IndependentVerifier::independent_hash(data.data(), data.size());

    // Known value from OpenSSL for 1,000,000 'a's
    const char* known_hex = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    std::cout << "Scalar hash:   " << hash_scalar.to_hex() << std::endl;
    std::cout << "Optimized hash:" << hash_optimized.to_hex() << std::endl;
    std::cout << "Verifier hash: " << hash_verifier.to_hex() << std::endl;
    std::cout << "Known hash:    " << known_hex << std::endl;

    if (hash_scalar.to_hex() == known_hex &&
        hash_optimized.to_hex() == known_hex &&
        hash_verifier.to_hex() == known_hex) {
        std::cout << "PASS: Million 'a' test matches known value across all engines." << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Hash mismatch." << std::endl;
        return 1;
    }
}