#pragma once

#include "sha256_research/core/types.hpp"
#include <vector>
#include <string>

#if SHA256_HAVE_VULKAN
#include "sha256_research/vulkan/vulkan_context.hpp"
#endif

namespace sha256_research {

struct VulkanBenchmarkResult {
    size_t batch_size{0};
    uint32_t rounds{64};
    double execution_time_ms{0.0};
    double throughput_mhashes_sec{0.0};
    bool verified_against_cpu{false};
    std::string device_name;
};

// Capability query: true only when compiled with Vulkan SDK support.
inline constexpr bool vulkan_compiled_in() noexcept {
#if SHA256_HAVE_VULKAN
    return true;
#else
    return false;
#endif
}

#if SHA256_HAVE_VULKAN
class Sha256VulkanEngine {
public:
    Sha256VulkanEngine();
    ~Sha256VulkanEngine();

    bool initialize(const std::string& shader_dir = "shaders");
    void cleanup() noexcept;

    bool is_ready() const noexcept { return ready_; }
    const VulkanContext& context() const noexcept { return context_; }
#else
// CPU-only stub: identical interface, always reports unavailable.
// Allows CPU-only builds without the Vulkan SDK.
class Sha256VulkanEngine {
public:
    Sha256VulkanEngine() = default;

    bool initialize(const std::string& = "shaders") { return false; }
    void cleanup() noexcept {}

    bool is_ready() const noexcept { return false; }
    std::string device_info_stub() const { return "Vulkan support not compiled in (CPU-only build)"; }
#endif

    // Execute batched SHA-256 on GPU
    // input_blocks: array of 64-byte blocks (size = count * 64 bytes)
    // out_digests: output vector of size count
    bool compute_batch(
        const uint8_t* input_blocks,
        size_t count,
        std::vector<Sha256Digest>& out_digests,
        uint32_t num_rounds = 64
    );

    // Self-test and benchmark against CPU reference
    VulkanBenchmarkResult run_smoke_test(size_t test_count = 1024, uint32_t num_rounds = 64);

#if SHA256_HAVE_VULKAN
private:
    bool ready_{false};
    VulkanContext context_;
    VkDescriptorSetLayout desc_set_layout_{VK_NULL_HANDLE};
    VkPipelineLayout pipeline_layout_{VK_NULL_HANDLE};
    VkPipeline compute_pipeline_{VK_NULL_HANDLE};
    VkDescriptorPool desc_pool_{VK_NULL_HANDLE};
#else
private:
    bool ready_{false};
#endif
};

} // namespace sha256_research
