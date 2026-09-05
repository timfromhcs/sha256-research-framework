#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace sha256_research {

// 32-bit word rotation and bitwise operations (FIPS 180-4 compliant)
inline constexpr uint32_t rotr32(uint32_t x, uint32_t n) noexcept {
    return (x >> n) | (x << ((32 - n) & 31));
}

inline constexpr uint32_t rotl32(uint32_t x, uint32_t n) noexcept {
    return (x << n) | (x >> ((32 - n) & 31));
}

inline constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

inline constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline constexpr uint32_t sigma0(uint32_t x) noexcept {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

inline constexpr uint32_t sigma1(uint32_t x) noexcept {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

inline constexpr uint32_t gamma0(uint32_t x) noexcept {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

inline constexpr uint32_t gamma1(uint32_t x) noexcept {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

// Big-endian conversion helpers
inline constexpr uint32_t load_be32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}

inline constexpr void store_be32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

inline constexpr void store_be64(uint8_t* p, uint64_t v) noexcept {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

// Standard SHA-256 Initial Hash Values H^(0)
inline constexpr std::array<uint32_t, 8> SHA256_IV = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

// Standard SHA-256 Round Constants K[0..63]
inline constexpr std::array<uint32_t, 64> SHA256_K = {
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

// 32-byte Digest struct
struct Sha256Digest {
    std::array<uint8_t, 32> bytes{};

    bool operator==(const Sha256Digest& other) const noexcept {
        return bytes == other.bytes;
    }

    bool operator!=(const Sha256Digest& other) const noexcept {
        return bytes != other.bytes;
    }

    std::string to_hex() const {
        std::ostringstream oss;
        for (uint8_t b : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }

    static Sha256Digest from_hex(const std::string& hex) {
        Sha256Digest d;
        if (hex.length() != 64) return d;
        for (size_t i = 0; i < 32; ++i) {
            std::string byteString = hex.substr(i * 2, 2);
            d.bytes[i] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        }
        return d;
    }
};

using Sha256Block = std::array<uint8_t, 64>;
using Sha256State = std::array<uint32_t, 8>;

} // namespace sha256_research
