#include "sha256_research/vulkan/sha256_vulkan.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include <chrono>
#include <iostream>
#include <random>
#include <filesystem>

namespace sha256_research {

Sha256VulkanEngine::Sha256VulkanEngine() = default;

Sha256VulkanEngine::~Sha256VulkanEngine() {
    cleanup();
}

void Sha256VulkanEngine::cleanup() noexcept {
    if (context_.is_initialized()) {
        VkDevice dev = context_.device();
        if (desc_pool_ != VK_NULL_HANDLE) {
            vkDestroyDescriptorPool(dev, desc_pool_, nullptr);
            desc_pool_ = VK_NULL_HANDLE;
        }
        if (compute_pipeline_ != VK_NULL_HANDLE) {
            vkDestroyPipeline(dev, compute_pipeline_, nullptr);
            compute_pipeline_ = VK_NULL_HANDLE;
        }
        if (pipeline_layout_ != VK_NULL_HANDLE) {
            vkDestroyPipelineLayout(dev, pipeline_layout_, nullptr);
            pipeline_layout_ = VK_NULL_HANDLE;
        }
        if (desc_set_layout_ != VK_NULL_HANDLE) {
            vkDestroyDescriptorSetLayout(dev, desc_set_layout_, nullptr);
            desc_set_layout_ = VK_NULL_HANDLE;
        }
    }
    context_.cleanup();
    ready_ = false;
}

bool Sha256VulkanEngine::initialize(const std::string& shader_dir) {
    cleanup();

    if (!context_.initialize(false)) {
        std::cerr << "[Sha256VulkanEngine] Failed to initialize Vulkan context.\n";
        return false;
    }

    VkDevice dev = context_.device();

    // 1. Create Descriptor Set Layout (Binding 0: Input, Binding 1: Output)
    VkDescriptorSetLayoutBinding bindings[2]{};
    bindings[0].binding = 0;
    bindings[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[0].descriptorCount = 1;
    bindings[0].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;

    bindings[1].binding = 1;
    bindings[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    bindings[1].descriptorCount = 1;
    bindings[1].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;

    VkDescriptorSetLayoutCreateInfo layout_info{};
    layout_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout_info.bindingCount = 2;
    layout_info.pBindings = bindings;

    if (vkCreateDescriptorSetLayout(dev, &layout_info, nullptr, &desc_set_layout_) != VK_SUCCESS) {
        cleanup();
        return false;
    }

    // 2. Create Pipeline Layout with Push Constants
    VkPushConstantRange push_range{};
    push_range.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    push_range.offset = 0;
    push_range.size = sizeof(uint32_t) * 2; // total_items, num_rounds

    VkPipelineLayoutCreateInfo pipeline_layout_info{};
    pipeline_layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipeline_layout_info.setLayoutCount = 1;
    pipeline_layout_info.pSetLayouts = &desc_set_layout_;
    pipeline_layout_info.pushConstantRangeCount = 1;
    pipeline_layout_info.pPushConstantRanges = &push_range;

    if (vkCreatePipelineLayout(dev, &pipeline_layout_info, nullptr, &pipeline_layout_) != VK_SUCCESS) {
        cleanup();
        return false;
    }

    // 3. Load Shader Module
    std::string candidate_paths[] = {
        shader_dir + "/sha256.spv",
        "shaders/sha256.spv",
        "../shaders/sha256.spv",
        "../../shaders/sha256.spv",
        "C:/Users/hcsme/Desktop/SHA256Solver/shaders/sha256.spv"
    };

    VkShaderModule shader_module = VK_NULL_HANDLE;
    for (const auto& p : candidate_paths) {
        if (std::filesystem::exists(p)) {
            shader_module = context_.load_shader_module_file(p);
            if (shader_module != VK_NULL_HANDLE) break;
        }
    }

    if (shader_module == VK_NULL_HANDLE) {
        std::cerr << "[Sha256VulkanEngine] Failed to load sha256.spv shader module.\n";
        cleanup();
        return false;
    }

    // 4. Create Compute Pipeline
    VkComputePipelineCreateInfo pipeline_create_info{};
    pipeline_create_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipeline_create_info.layout = pipeline_layout_;
    pipeline_create_info.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipeline_create_info.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipeline_create_info.stage.module = shader_module;
    pipeline_create_info.stage.pName = "main";

    VkResult res = vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &pipeline_create_info, nullptr, &compute_pipeline_);
    vkDestroyShaderModule(dev, shader_module, nullptr);

    if (res != VK_SUCCESS) {
        cleanup();
        return false;
    }

    // 5. Create Descriptor Pool
    VkDescriptorPoolSize pool_size{};
    pool_size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    pool_size.descriptorCount = 2;

    VkDescriptorPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool_info.maxSets = 1;
    pool_info.poolSizeCount = 1;
    pool_info.pPoolSizes = &pool_size;

    if (vkCreateDescriptorPool(dev, &pool_info, nullptr, &desc_pool_) != VK_SUCCESS) {
        cleanup();
        return false;
    }

    ready_ = true;
    return true;
}

bool Sha256VulkanEngine::compute_batch(
    const uint8_t* input_blocks,
    size_t count,
    std::vector<Sha256Digest>& out_digests,
    uint32_t num_rounds)
{
    if (!ready_ || count == 0) return false;

    VkDevice dev = context_.device();
    out_digests.resize(count);

    // Buffers: input is count * 16 uint32s, output is count * 8 uint32s
    VkDeviceSize in_size = count * 16 * sizeof(uint32_t);
    VkDeviceSize out_size = count * 8 * sizeof(uint32_t);

    VulkanBuffer in_buffer;
    VulkanBuffer out_buffer;

    VkMemoryPropertyFlags mem_flags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    if (!context_.create_buffer(in_size, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, mem_flags, in_buffer)) {
        return false;
    }
    if (!context_.create_buffer(out_size, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, mem_flags, out_buffer)) {
        context_.destroy_buffer(in_buffer);
        return false;
    }

    // Copy input blocks to mapped buffer in big-endian word format
    uint32_t* in_mapped = static_cast<uint32_t*>(in_buffer.mapped);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* block = input_blocks + i * 64;
        for (size_t w = 0; w < 16; ++w) {
            in_mapped[i * 16 + w] = load_be32(block + w * 4);
        }
    }

    // Allocate descriptor set
    VkDescriptorSetAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    alloc_info.descriptorPool = desc_pool_;
    alloc_info.descriptorSetCount = 1;
    alloc_info.pSetLayouts = &desc_set_layout_;

    VkDescriptorSet desc_set;
    if (vkAllocateDescriptorSets(dev, &alloc_info, &desc_set) != VK_SUCCESS) {
        context_.destroy_buffer(in_buffer);
        context_.destroy_buffer(out_buffer);
        return false;
    }

    // Update descriptor set
    VkDescriptorBufferInfo in_desc_info{in_buffer.buffer, 0, in_size};
    VkDescriptorBufferInfo out_desc_info{out_buffer.buffer, 0, out_size};

    VkWriteDescriptorSet writes[2]{};
    writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    writes[0].dstSet = desc_set;
    writes[0].dstBinding = 0;
    writes[0].descriptorCount = 1;
    writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    writes[0].pBufferInfo = &in_desc_info;

    writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    writes[1].dstSet = desc_set;
    writes[1].dstBinding = 1;
    writes[1].descriptorCount = 1;
    writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    writes[1].pBufferInfo = &out_desc_info;

    vkUpdateDescriptorSets(dev, 2, writes, 0, nullptr);

    // Record and execute compute commands
    VkCommandBuffer cmd = context_.begin_single_time_commands();

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, compute_pipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_layout_, 0, 1, &desc_set, 0, nullptr);

    uint32_t push_constants[2] = {static_cast<uint32_t>(count), num_rounds};
    vkCmdPushConstants(cmd, pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push_constants), push_constants);

    uint32_t workgroups = static_cast<uint32_t>((count + 63) / 64);
    vkCmdDispatch(cmd, workgroups, 1, 1);

    context_.end_single_time_commands(cmd);

    // Read back results
    const uint32_t* out_mapped = static_cast<const uint32_t*>(out_buffer.mapped);
    for (size_t i = 0; i < count; ++i) {
        for (size_t w = 0; w < 8; ++w) {
            store_be32(out_digests[i].bytes.data() + w * 4, out_mapped[i * 8 + w]);
        }
    }

    // Free descriptor sets & buffers
    vkFreeDescriptorSets(dev, desc_pool_, 1, &desc_set);
    context_.destroy_buffer(in_buffer);
    context_.destroy_buffer(out_buffer);

    return true;
}

VulkanBenchmarkResult Sha256VulkanEngine::run_smoke_test(size_t test_count, uint32_t num_rounds) {
    VulkanBenchmarkResult res;
    res.batch_size = test_count;
    res.rounds = num_rounds;
    res.device_name = context_.device_info().device_name;

    if (!ready_) return res;

    // Generate test input blocks with deterministic pseudo-random data
    std::vector<uint8_t> input_data(test_count * 64);
    for (size_t i = 0; i < input_data.size(); ++i) {
        input_data[i] = static_cast<uint8_t>((i * 137 + 43) & 0xFF);
    }

    std::vector<Sha256Digest> gpu_digests;
    auto t0 = std::chrono::steady_clock::now();
    bool ok = compute_batch(input_data.data(), test_count, gpu_digests, num_rounds);
    auto t1 = std::chrono::steady_clock::now();

    if (!ok) return res;

    std::chrono::duration<double, std::milli> elapsed_ms = t1 - t0;
    res.execution_time_ms = elapsed_ms.count();
    res.throughput_mhashes_sec = (test_count / (res.execution_time_ms / 1000.0)) / 1e6;

    // Verify against CPU reference
    res.verified_against_cpu = true;
    for (size_t i = 0; i < test_count; ++i) {
        Sha256State cpu_state = SHA256_IV;
        Sha256Scalar::compress_block(cpu_state, input_data.data() + i * 64, num_rounds);

        Sha256Digest expected;
        for (size_t w = 0; w < 8; ++w) {
            store_be32(expected.bytes.data() + w * 4, cpu_state[w]);
        }

        if (gpu_digests[i] != expected) {
            res.verified_against_cpu = false;
            std::cerr << "[Sha256VulkanEngine] Verification mismatch at index " << i << "!\n";
            std::cerr << "  Expected: " << expected.to_hex() << "\n";
            std::cerr << "  Actual:   " << gpu_digests[i].to_hex() << "\n";
            break;
        }
    }

    return res;
}

} // namespace sha256_research
