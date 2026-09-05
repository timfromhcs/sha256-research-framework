#pragma once

#include <vulkan/vulkan.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iostream>

namespace sha256_research {

struct VulkanDeviceInfo {
    std::string device_name;
    uint32_t device_id{0};
    uint32_t vendor_id{0};
    std::string driver_version;
    std::string api_version;
    uint32_t compute_queue_family{0};
    uint32_t max_work_group_invocations{0};
    uint32_t max_work_group_size[3]{0, 0, 0};
    uint64_t vram_bytes{0};
    bool supports_compute{false};
};

struct VulkanBuffer {
    VkBuffer buffer{VK_NULL_HANDLE};
    VkDeviceMemory memory{VK_NULL_HANDLE};
    VkDeviceSize size{0};
    void* mapped{nullptr};
};

class VulkanContext {
public:
    VulkanContext();
    ~VulkanContext();

    // Non-copyable, movable
    VulkanContext(const VulkanContext&) = delete;
    VulkanContext& operator=(const VulkanContext&) = delete;
    VulkanContext(VulkanContext&& other) noexcept;
    VulkanContext& operator=(VulkanContext&& other) noexcept;

    // Initialization with runtime capability detection
    bool initialize(bool enable_validation = false);
    void cleanup() noexcept;

    bool is_initialized() const noexcept { return initialized_; }
    const VulkanDeviceInfo& device_info() const noexcept { return device_info_; }

    VkDevice device() const noexcept { return device_; }
    VkPhysicalDevice physical_device() const noexcept { return physical_device_; }
    VkQueue compute_queue() const noexcept { return compute_queue_; }
    VkCommandPool command_pool() const noexcept { return command_pool_; }

    // Buffer helpers
    bool create_buffer(
        VkDeviceSize size,
        VkBufferUsageFlags usage,
        VkMemoryPropertyFlags properties,
        VulkanBuffer& out_buffer
    );
    void destroy_buffer(VulkanBuffer& buffer) noexcept;

    // Shader & Pipeline helpers
    VkShaderModule create_shader_module(const std::vector<uint32_t>& spirv);
    VkShaderModule load_shader_module_file(const std::string& path);

    // One-time command buffer allocation & execution
    VkCommandBuffer begin_single_time_commands();
    void end_single_time_commands(VkCommandBuffer command_buffer);

    uint32_t find_memory_type(uint32_t type_filter, VkMemoryPropertyFlags properties) const;

    static bool is_vulkan_available() noexcept;

private:
    bool initialized_{false};
    VkInstance instance_{VK_NULL_HANDLE};
    VkDebugUtilsMessengerEXT debug_messenger_{VK_NULL_HANDLE};
    VkPhysicalDevice physical_device_{VK_NULL_HANDLE};
    VkDevice device_{VK_NULL_HANDLE};
    VkQueue compute_queue_{VK_NULL_HANDLE};
    VkCommandPool command_pool_{VK_NULL_HANDLE};
    VulkanDeviceInfo device_info_{};
};

} // namespace sha256_research
