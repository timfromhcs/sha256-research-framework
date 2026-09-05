#include "sha256_research/benchmark/benchmark_suite.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/vulkan/sha256_vulkan.hpp"
#include "sha256_research/sat/sat_encoder.hpp"
#include <chrono>
#include <thread>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace sha256_research {

BenchmarkMetric BenchmarkSuite::benchmark_scalar_cpu(size_t num_hashes) {
    BenchmarkMetric m;
    m.name = "SHA-256 Scalar Reference";
    m.backend = "CPU Portable Scalar";
    m.total_iterations = num_hashes;

    uint8_t block[64] = {0};
    const char* sample = "The quick brown fox jumps over the lazy dog 12345678901234567890";
    std::memcpy(block, sample, 64);

    // Warm-up
    for (int i = 0; i < 1000; ++i) {
        Sha256Scalar::hash(block, 64);
    }

    auto t0 = std::chrono::steady_clock::now();
    Sha256Digest d;
    for (size_t i = 0; i < num_hashes; ++i) {
        block[0] = static_cast<uint8_t>(i & 0xFF);
        d = Sha256Scalar::hash(block, 64);
    }
    auto t1 = std::chrono::steady_clock::now();

    std::chrono::duration<double> diff = t1 - t0;
    m.operations_per_second = num_hashes / diff.count();
    m.megabytes_per_second = (num_hashes * 64.0) / (diff.count() * 1024.0 * 1024.0);
    m.mean_latency_us = (diff.count() * 1e6) / num_hashes;
    m.notes = "Final hash: " + d.to_hex().substr(0, 8) + "...";

    return m;
}

BenchmarkMetric BenchmarkSuite::benchmark_optimized_cpu_single(size_t num_hashes) {
    BenchmarkMetric m;
    m.name = "SHA-256 Optimized CPU (1 Thread)";
    m.backend = "CPU Unrolled Fast Path";
    m.total_iterations = num_hashes;

    uint8_t block[55] = "Single-threaded optimized CPU unrolled test message!!!";

    // Warm-up
    for (int i = 0; i < 1000; ++i) {
        Sha256Optimized::hash(block, 55);
    }

    auto t0 = std::chrono::steady_clock::now();
    Sha256Digest d;
    for (size_t i = 0; i < num_hashes; ++i) {
        block[0] = static_cast<uint8_t>(i & 0xFF);
        d = Sha256Optimized::hash(block, 55);
    }
    auto t1 = std::chrono::steady_clock::now();

    std::chrono::duration<double> diff = t1 - t0;
    m.operations_per_second = num_hashes / diff.count();
    m.megabytes_per_second = (num_hashes * 55.0) / (diff.count() * 1024.0 * 1024.0);
    m.mean_latency_us = (diff.count() * 1e6) / num_hashes;
    m.notes = "Features: " + Sha256Optimized::features().to_string();

    return m;
}

BenchmarkMetric BenchmarkSuite::benchmark_optimized_cpu_multi(size_t num_hashes, unsigned int threads) {
    BenchmarkMetric m;
    if (threads == 0) threads = std::thread::hardware_concurrency();
    m.name = "SHA-256 Optimized CPU (" + std::to_string(threads) + " Threads)";
    m.backend = "CPU Multithreaded Unrolled";
    m.total_iterations = num_hashes;

    std::vector<uint8_t> in_data(num_hashes * 55, 0x42);
    std::vector<Sha256Digest> out(num_hashes);

    auto t0 = std::chrono::steady_clock::now();
    Sha256Optimized::hash_batch(in_data.data(), 55, num_hashes, out.data(), threads);
    auto t1 = std::chrono::steady_clock::now();

    std::chrono::duration<double> diff = t1 - t0;
    m.operations_per_second = num_hashes / diff.count();
    m.megabytes_per_second = (num_hashes * 55.0) / (diff.count() * 1024.0 * 1024.0);
    m.mean_latency_us = (diff.count() * 1e6) / num_hashes;
    m.notes = "Dispatched across " + std::to_string(threads) + " logical cores";

    return m;
}

BenchmarkMetric BenchmarkSuite::benchmark_vulkan(size_t batch_size, uint32_t rounds) {
    BenchmarkMetric m;
    m.name = "SHA-256 Vulkan Compute Batch (" + std::to_string(batch_size) + " items, " + std::to_string(rounds) + " rounds)";
    m.backend = "Vulkan Compute (SPIR-V)";
    m.total_iterations = batch_size;

    Sha256VulkanEngine vk;
    if (!vk.initialize("shaders")) {
        m.notes = "Vulkan initialization unavailable or failed";
        return m;
    }

    auto smoke = vk.run_smoke_test(batch_size, rounds);
    m.operations_per_second = smoke.throughput_mhashes_sec * 1e6;
    m.megabytes_per_second = (batch_size * 64.0) / (smoke.execution_time_ms / 1000.0 * 1024.0 * 1024.0);
    m.mean_latency_us = (smoke.execution_time_ms * 1000.0) / batch_size;
    m.notes = "Device: " + smoke.device_name + " | CPU Verified: " + (smoke.verified_against_cpu ? "YES" : "NO");

    return m;
}

BenchmarkMetric BenchmarkSuite::benchmark_sat_encoder(uint32_t rounds) {
    BenchmarkMetric m;
    m.name = "SAT Encoding Throughput (" + std::to_string(rounds) + " rounds)";
    m.backend = "SAT Tseitin Transform Engine";
    m.total_iterations = 10;

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;

    auto t0 = std::chrono::steady_clock::now();
    size_t total_clauses = 0;
    size_t total_vars = 0;
    for (size_t i = 0; i < 10; ++i) {
        auto enc = SatEncoder::encode_reduced_rounds(cfg);
        total_clauses = enc.cnf.clauses.size();
        total_vars = enc.cnf.num_vars;
    }
    auto t1 = std::chrono::steady_clock::now();

    std::chrono::duration<double> diff = t1 - t0;
    m.operations_per_second = 10.0 / diff.count();
    m.mean_latency_us = (diff.count() * 1e6) / 10.0;
    m.notes = std::to_string(total_vars) + " variables, " + std::to_string(total_clauses) + " clauses per problem";

    return m;
}

std::string BenchmarkReport::to_markdown() const {
    std::ostringstream oss;
    oss << "# Performance Benchmark Report\n\n";
    oss << "- **Timestamp**: " << timestamp << "\n";
    oss << "- **CPU**: " << cpu_model << "\n";
    oss << "- **GPU**: " << gpu_model << "\n\n";
    oss << "| Benchmark Category | Backend | Throughput (hashes/s) | Bandwidth (MB/s) | Latency (us/op) | Notes |\n";
    oss << "| :--- | :--- | :--- | :--- | :--- | :--- |\n";

    for (const auto& m : metrics) {
        oss << "| " << m.name
            << " | " << m.backend
            << " | " << std::fixed << std::setprecision(0) << m.operations_per_second
            << " | " << std::fixed << std::setprecision(2) << m.megabytes_per_second
            << " | " << std::fixed << std::setprecision(3) << m.mean_latency_us
            << " | " << m.notes << " |\n";
    }

    return oss.str();
}

BenchmarkReport BenchmarkSuite::run_full_suite() {
    BenchmarkReport rep;
    rep.timestamp = "2026-09-05";
    rep.cpu_model = "AMD Ryzen 7 7735HS (8C/16T)";
    rep.gpu_model = "AMD Radeon 680M Graphics (Vulkan 1.4)";

    rep.metrics.push_back(benchmark_scalar_cpu(100000));
    rep.metrics.push_back(benchmark_optimized_cpu_single(200000));
    rep.metrics.push_back(benchmark_optimized_cpu_multi(1000000));
    rep.metrics.push_back(benchmark_sat_encoder(16));
    rep.metrics.push_back(benchmark_vulkan(32768, 64));

    return rep;
}

} // namespace sha256_research
