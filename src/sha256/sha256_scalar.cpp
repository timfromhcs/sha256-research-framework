#include "sha256_research/sha256/sha256_scalar.hpp"
#include <algorithm>
#include <cstring>

namespace sha256_research {

void Sha256Scalar::reset() noexcept {
    state_ = SHA256_IV;
    buffer_len_ = 0;
    count_ = 0;
    buffer_.fill(0);
}

void Sha256Scalar::expand_schedule(const uint8_t block[64], uint32_t W[64]) noexcept {
    for (size_t t = 0; t < 16; ++t) {
        W[t] = load_be32(block + t * 4);
    }
    for (size_t t = 16; t < 64; ++t) {
        W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
    }
}

void Sha256Scalar::compress_block(Sha256State& state, const uint8_t block[64], uint32_t num_rounds) noexcept {
    uint32_t W[64];
    expand_schedule(block, W);

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    const uint32_t rounds = std::min(num_rounds, 64U);
    for (uint32_t t = 0; t < rounds; ++t) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + SHA256_K[t] + W[t];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
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

Sha256Scalar::RoundTrace Sha256Scalar::compress_block_trace(
    const Sha256State& initial_state,
    const uint8_t block[64],
    uint32_t num_rounds) noexcept
{
    RoundTrace trace;
    expand_schedule(block, trace.W.data());

    uint32_t a = initial_state[0];
    uint32_t b = initial_state[1];
    uint32_t c = initial_state[2];
    uint32_t d = initial_state[3];
    uint32_t e = initial_state[4];
    uint32_t f = initial_state[5];
    uint32_t g = initial_state[6];
    uint32_t h = initial_state[7];

    trace.state_at_round[0] = {a, b, c, d, e, f, g, h};

    const uint32_t rounds = std::min(num_rounds, 64U);
    for (uint32_t t = 0; t < rounds; ++t) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + SHA256_K[t] + trace.W[t];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
        trace.state_at_round[t + 1] = {a, b, c, d, e, f, g, h};
    }

    return trace;
}

void Sha256Scalar::update(const void* data, size_t len) noexcept {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    count_ += len;

    // If buffer already has partial data, fill it first
    if (buffer_len_ > 0) {
        size_t needed = 64 - buffer_len_;
        if (len < needed) {
            std::memcpy(buffer_.data() + buffer_len_, p, len);
            buffer_len_ += len;
            return;
        }
        std::memcpy(buffer_.data() + buffer_len_, p, needed);
        compress_block(state_, buffer_.data(), 64);
        p += needed;
        len -= needed;
        buffer_len_ = 0;
    }

    // Process full 64-byte blocks
    while (len >= 64) {
        compress_block(state_, p, 64);
        p += 64;
        len -= 64;
    }

    // Store remaining bytes in buffer
    if (len > 0) {
        std::memcpy(buffer_.data(), p, len);
        buffer_len_ = len;
    }
}

Sha256Digest Sha256Scalar::finalize() noexcept {
    // Total bits = count_ * 8
    uint64_t total_bits = count_ * 8;

    // Standard SHA-256 padding: append 0x80, then 0x00 bytes, then 64-bit length
    buffer_[buffer_len_++] = 0x80;

    if (buffer_len_ > 56) {
        // Not enough space for 8-byte length; pad to 64, compress, and pad another block
        std::memset(buffer_.data() + buffer_len_, 0, 64 - buffer_len_);
        compress_block(state_, buffer_.data(), 64);
        buffer_.fill(0);
        buffer_len_ = 0;
    } else {
        std::memset(buffer_.data() + buffer_len_, 0, 56 - buffer_len_);
    }

    // Store big-endian 64-bit length into last 8 bytes
    store_be64(buffer_.data() + 56, total_bits);
    compress_block(state_, buffer_.data(), 64);

    Sha256Digest digest;
    for (size_t i = 0; i < 8; ++i) {
        store_be32(digest.bytes.data() + i * 4, state_[i]);
    }

    // Reset state after finalization for safe reuse
    reset();
    return digest;
}

Sha256Digest Sha256Scalar::hash(const void* data, size_t len) noexcept {
    Sha256Scalar hasher;
    hasher.update(data, len);
    return hasher.finalize();
}

} // namespace sha256_research
