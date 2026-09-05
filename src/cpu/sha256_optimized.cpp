#include "sha256_research/cpu/sha256_optimized.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <sstream>
#include <cstring>
#include <utility>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

namespace sha256_research {

namespace {

void cpuid_native(int info[4], int leaf, int subleaf = 0) {
#if defined(_MSC_VER)
    __cpuidex(info, leaf, subleaf);
#elif defined(__x86_64__) || defined(_M_X64)
    __cpuid_count(leaf, subleaf, info[0], info[1], info[2], info[3]);
#else
    info[0] = info[1] = info[2] = info[3] = 0;
#endif
}

} // namespace

CpuFeatures CpuFeatures::detect() noexcept {
    CpuFeatures f;
    int info[4] = {0};

    cpuid_native(info, 0);
    int max_leaf = info[0];

    if (max_leaf >= 1) {
        cpuid_native(info, 1);
        f.has_sse42 = (info[2] & (1 << 20)) != 0;
        f.has_avx = (info[2] & (1 << 28)) != 0;
    }

    if (max_leaf >= 7) {
        cpuid_native(info, 7, 0);
        f.has_bmi2 = (info[1] & (1 << 8)) != 0;
        f.has_avx2 = (info[1] & (1 << 5)) != 0;
        f.has_sha_ni = (info[1] & (1 << 29)) != 0;
    }

    return f;
}

std::string CpuFeatures::to_string() const {
    std::ostringstream oss;
    oss << "SSE4.2: " << (has_sse42 ? "Yes" : "No")
        << ", AVX: " << (has_avx ? "Yes" : "No")
        << ", AVX2: " << (has_avx2 ? "Yes" : "No")
        << ", BMI2: " << (has_bmi2 ? "Yes" : "No")
        << ", SHA-NI: " << (has_sha_ni ? "Yes" : "No");
    return oss.str();
}

static const CpuFeatures g_cpu_features = CpuFeatures::detect();

const CpuFeatures& Sha256Optimized::features() noexcept {
    return g_cpu_features;
}

#define SHA256_ROUND(a, b, c, d, e, f, g, h, k, w) \
    do { \
        uint32_t t1 = (h) + sigma1(e) + ch((e), (f), (g)) + (k) + (w); \
        uint32_t t2 = sigma0(a) + maj((a), (b), (c)); \
        (d) += t1; \
        (h) = t1 + t2; \
    } while(0)

void Sha256Optimized::compress_block_unrolled(Sha256State& state, const uint8_t block[64]) noexcept {
    uint32_t W[64];
    for (size_t t = 0; t < 16; ++t) {
        W[t] = load_be32(block + t * 4);
    }
    for (size_t t = 16; t < 64; ++t) {
        W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    // Fully unrolled 64 rounds in 8-step cycles
    for (size_t i = 0; i < 64; i += 8) {
        SHA256_ROUND(a, b, c, d, e, f, g, h, SHA256_K[i + 0], W[i + 0]);
        SHA256_ROUND(h, a, b, c, d, e, f, g, SHA256_K[i + 1], W[i + 1]);
        SHA256_ROUND(g, h, a, b, c, d, e, f, SHA256_K[i + 2], W[i + 2]);
        SHA256_ROUND(f, g, h, a, b, c, d, e, SHA256_K[i + 3], W[i + 3]);
        SHA256_ROUND(e, f, g, h, a, b, c, d, SHA256_K[i + 4], W[i + 4]);
        SHA256_ROUND(d, e, f, g, h, a, b, c, SHA256_K[i + 5], W[i + 5]);
        SHA256_ROUND(c, d, e, f, g, h, a, b, SHA256_K[i + 6], W[i + 6]);
        SHA256_ROUND(b, c, d, e, f, g, h, a, SHA256_K[i + 7], W[i + 7]);
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

Sha256Digest Sha256Optimized::hash_path(const void* data, size_t len, Path path) noexcept {
    if (path == Path::ScalarReference) {
        return Sha256Scalar::hash(data, len);
    }
    // UnrolledPortable: single-block fast path, otherwise scalar streaming.
    if (len <= 55) {
        Sha256State state = SHA256_IV;
        uint8_t block[64] = {0};
        if (len > 0) std::memcpy(block, data, len);
        block[len] = 0x80;
        store_be64(block + 56, static_cast<uint64_t>(len) * 8);

        compress_block_unrolled(state, block);

        Sha256Digest digest;
        for (size_t i = 0; i < 8; ++i) {
            store_be32(digest.bytes.data() + i * 4, state[i]);
        }
        return digest;
    }

    // General path via streaming scalar reference
    return Sha256Scalar::hash(data, len);
}

Sha256Digest Sha256Optimized::hash(const void* data, size_t len) noexcept {
    return hash_path(data, len, Path::UnrolledPortable);
}

void Sha256Optimized::hash_batch(
    const uint8_t* in_data,
    size_t message_len,
    size_t count,
    Sha256Digest* out_digests,
    unsigned int thread_count) noexcept
{
    if (count == 0) return;

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) thread_count = 4;
    }

    size_t chunk_size = (count + thread_count - 1) / thread_count;
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (unsigned int t = 0; t < thread_count; ++t) {
        size_t start = t * chunk_size;
        size_t end = std::min(start + chunk_size, count);
        if (start >= count) break;

        workers.emplace_back([=]() {
            for (size_t i = start; i < end; ++i) {
                out_digests[i] = hash(in_data + i * message_len, message_len);
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }
}

Sha256Optimized::SearchResult Sha256Optimized::search_prefix_zeros(
    const uint8_t* prefix,
    size_t prefix_len,
    const SearchTarget& target,
    unsigned int thread_count)
{
    SearchResult result;
    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) thread_count = 4;
    }

    std::atomic<bool> stop_flag{false};
    std::atomic<uint64_t> total_hashes{0};
    auto start_time = std::chrono::steady_clock::now();

    // Exact partition of [0, max_iterations) across threads (single source
    // of truth shared with partition_range()): union == full domain.
    auto ranges = partition_range(target.max_iterations, thread_count);
    std::vector<std::thread> threads;
    threads.reserve(thread_count);

    const uint32_t full_zero_bytes = target.target_zero_bits / 8;
    const uint32_t rem_zero_bits = target.target_zero_bits % 8;
    const uint8_t rem_mask = (rem_zero_bits == 0)
        ? static_cast<uint8_t>(0x00)
        : static_cast<uint8_t>(0xFFU << (8 - rem_zero_bits));

    for (unsigned int tid = 0; tid < thread_count; ++tid) {
        threads.emplace_back([&, tid]() {
            std::vector<uint8_t> buffer(prefix_len + sizeof(uint64_t));
            std::memcpy(buffer.data(), prefix, prefix_len);

            uint64_t start_nonce = ranges[tid].first;
            uint64_t end_nonce = ranges[tid].second;

            uint64_t local_count = 0;
            for (uint64_t nonce = start_nonce; nonce < end_nonce && !stop_flag.load(std::memory_order_relaxed); ++nonce) {
                store_be64(buffer.data() + prefix_len, nonce);
                Sha256Digest d = hash(buffer.data(), buffer.size());
                local_count++;

                // Check condition
                bool match = true;
                for (size_t b = 0; b < full_zero_bytes; ++b) {
                    if (d.bytes[b] != 0) { match = false; break; }
                }
                if (match && rem_zero_bits > 0) {
                    if ((d.bytes[full_zero_bytes] & rem_mask) != 0) {
                        match = false;
                    }
                }

                if (match) {
                    if (!stop_flag.exchange(true)) {
                        result.found = true;
                        result.nonce = nonce;
                        result.digest = d;
                    }
                    break;
                }
            }
            total_hashes.fetch_add(local_count, std::memory_order_relaxed);
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;
    result.elapsed_seconds = elapsed.count();
    result.hashes_computed = total_hashes.load();
    result.hash_rate = result.elapsed_seconds > 0.0 ? (result.hashes_computed / result.elapsed_seconds) : 0.0;

    return result;
}

std::vector<std::pair<uint64_t, uint64_t>> Sha256Optimized::partition_range(
    uint64_t max_iterations, unsigned int thread_count)
{
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    if (thread_count == 0 || max_iterations == 0) return ranges;
    const uint64_t base = max_iterations / thread_count;
    const uint64_t rem = max_iterations % thread_count;
    ranges.reserve(thread_count);
    for (unsigned int tid = 0; tid < thread_count; ++tid) {
        uint64_t start = static_cast<uint64_t>(tid) * base + (tid < rem ? tid : rem);
        uint64_t count = base + (tid < rem ? 1 : 0);
        ranges.emplace_back(start, start + count);
    }
    return ranges;
}

} // namespace sha256_research
