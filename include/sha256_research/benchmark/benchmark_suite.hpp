#pragma once

#include "sha256_research/core/types.hpp"
#include <string>
#include <vector>

namespace sha256_research {

struct BenchmarkMetric {
    std::string name;
    double operations_per_second{0.0};
    double megabytes_per_second{0.0};
    double mean_latency_us{0.0};
    uint64_t total_iterations{0};
    std::string backend;
    std::string notes;
};

struct BenchmarkReport {
    std::string timestamp;
    std::string cpu_model;
    std::string gpu_model;
    std::vector<BenchmarkMetric> metrics;

    std::string to_markdown() const;
};

class BenchmarkSuite {
public:
    static BenchmarkMetric benchmark_scalar_cpu(size_t num_hashes = 200000);
    static BenchmarkMetric benchmark_optimized_cpu_single(size_t num_hashes = 400000);
    static BenchmarkMetric benchmark_optimized_cpu_multi(size_t num_hashes = 2000000, unsigned int threads = 0);
    static BenchmarkMetric benchmark_vulkan(size_t batch_size = 65536, uint32_t rounds = 64);
    static BenchmarkMetric benchmark_sat_encoder(uint32_t rounds = 16);

    static BenchmarkReport run_full_suite();
};

} // namespace sha256_research
