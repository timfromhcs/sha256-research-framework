// CPU-only stub for Sha256VulkanEngine (built when SHA256_HAVE_VULKAN=0).
// Provides the same interface but reports Vulkan as unavailable.
#include "sha256_research/vulkan/sha256_vulkan.hpp"

namespace sha256_research {

bool Sha256VulkanEngine::compute_batch(
    const uint8_t*,
    size_t,
    std::vector<Sha256Digest>& out_digests,
    uint32_t)
{
    out_digests.clear();
    return false;
}

VulkanBenchmarkResult Sha256VulkanEngine::run_smoke_test(size_t test_count, uint32_t num_rounds) {
    VulkanBenchmarkResult res;
    res.batch_size = test_count;
    res.rounds = num_rounds;
    res.device_name = "none (CPU-only build)";
    res.verified_against_cpu = false;
    res.execution_time_ms = 0.0;
    res.throughput_mhashes_sec = 0.0;
    return res;
}

} // namespace sha256_research
