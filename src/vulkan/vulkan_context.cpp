#include "sha256_research/vulkan/vulkan_context.hpp"
#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>

namespace sha256_research {

VulkanContext::VulkanContext() = default;

VulkanContext::~VulkanContext() {
    cleanup();
}

VulkanContext::VulkanContext(VulkanContext&& other) noexcept {
    *this = std::move(other);
}

VulkanContext& VulkanContext::operator=(VulkanContext&& other) noexcept {
    if (this != &other) {
        cleanup();
        initialized_ = other.initialized_;
        instance_ = other.instance_;
        debug_messenger_ = other.debug_messenger_;
        physical_device_ = other.physical_device_;
        device_ = other.device_;
        compute_queue_ = other.compute_queue_;
        command_pool_ = other.command_pool_;
        device_info_ = other.device_info_;

        other.initialized_ = false;
        other.instance_ = VK_NULL_HANDLE;
        other.debug_messenger_ = VK_NULL_HANDLE;
        other.physical_device_ = VK_NULL_HANDLE;
        other.device_ = VK_NULL_HANDLE;
        other.compute_queue_ = VK_NULL_HANDLE;
        other.command_pool_ = VK_NULL_HANDLE;
    }
    return *this;
}

bool VulkanContext::is_vulkan_available() noexcept {
    uint32_t extension_count = 0;
    VkResult res = vkEnumerateInstanceExtensionProperties(nullptr, &extension_count, nullptr);
    return (res == VK_SUCCESS && extension_count > 0);
}

bool VulkanContext::initialize(bool enable_validation) {
    cleanup();

    if (!is_vulkan_available()) {
        std::cerr << "[VulkanContext] Vulkan runtime loader not found or no extensions available.\n";
        return false;
    }

    // 1. Create Instance
    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "SHA256Cryptanalysis";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "ShaResearchCompute";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo create_info{};
    create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create_info.pApplicationInfo = &app_info;

    std::vector<const char*> layers;
    if (enable_validation) {
        layers.push_back("VK_LAYER_KHRONOS_validation");
        create_info.enabledLayerCount = static_cast<uint32_t>(layers.size());
        create_info.ppEnabledLayerNames = layers.data();
    }

    VkResult res = vkCreateInstance(&create_info, nullptr, &instance_);
    if (res != VK_SUCCESS) {
        // Fallback without validation layer if failed
        create_info.enabledLayerCount = 0;
        create_info.ppEnabledLayerNames = nullptr;
        res = vkCreateInstance(&create_info, nullptr, &instance_);
        if (res != VK_SUCCESS) {
            std::cerr << "[VulkanContext] vkCreateInstance failed with code: " << res << "\n";
            return false;
        }
    }

    // 2. Select Physical Device
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance_, &device_count, nullptr);
    if (device_count == 0) {
        std::cerr << "[VulkanContext] No Vulkan physical devices found.\n";
        cleanup();
        return false;
    }

    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(instance_, &device_count, devices.data());

    // Prefer discrete GPU, otherwise integrated GPU
    int best_score = -1;
    VkPhysicalDevice selected_device = VK_NULL_HANDLE;
    uint32_t selected_queue_family = 0;

    for (const auto& dev : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(dev, &props);

        uint32_t queue_family_count = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(dev, &queue_family_count, nullptr);
        std::vector<VkQueueFamilyProperties> queue_families(queue_family_count);
        vkGetPhysicalDeviceQueueFamilyProperties(dev, &queue_family_count, queue_families.data());

        for (uint32_t i = 0; i < queue_family_count; ++i) {
            if (queue_families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                int score = 0;
                if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) score += 1000;
                if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU) score += 500;

                if (score > best_score) {
                    best_score = score;
                    selected_device = dev;
                    selected_queue_family = i;
                }
                break;
            }
        }
    }

    if (selected_device == VK_NULL_HANDLE) {
        std::cerr << "[VulkanContext] No device with compute queue found.\n";
        cleanup();
        return false;
    }

    physical_device_ = selected_device;
    device_info_.compute_queue_family = selected_queue_family;
    device_info_.supports_compute = true;

    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(physical_device_, &props);
    device_info_.device_name = props.deviceName;
    device_info_.device_id = props.deviceID;
    device_info_.vendor_id = props.vendorID;

    std::ostringstream oss;
    oss << VK_VERSION_MAJOR(props.driverVersion) << "."
        << VK_VERSION_MINOR(props.driverVersion) << "."
        << VK_VERSION_PATCH(props.driverVersion);
    device_info_.driver_version = oss.str();

    std::ostringstream api_oss;
    api_oss << VK_VERSION_MAJOR(props.apiVersion) << "."
            << VK_VERSION_MINOR(props.apiVersion) << "."
            << VK_VERSION_PATCH(props.apiVersion);
    device_info_.api_version = api_oss.str();

    device_info_.max_work_group_invocations = props.limits.maxComputeWorkGroupInvocations;
    device_info_.max_work_group_size[0] = props.limits.maxComputeWorkGroupSize[0];
    device_info_.max_work_group_size[1] = props.limits.maxComputeWorkGroupSize[1];
    device_info_.max_work_group_size[2] = props.limits.maxComputeWorkGroupSize[2];

    // 3. Create Logical Device & Compute Queue
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_create_info{};
    queue_create_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_create_info.queueFamilyIndex = selected_queue_family;
    queue_create_info.queueCount = 1;
    queue_create_info.pQueuePriorities = &queue_priority;

    VkDeviceCreateInfo device_create_info{};
    device_create_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_create_info.queueCreateInfoCount = 1;
    device_create_info.pQueueCreateInfos = &queue_create_info;

    res = vkCreateDevice(physical_device_, &device_create_info, nullptr, &device_);
    if (res != VK_SUCCESS) {
        std::cerr << "[VulkanContext] vkCreateDevice failed with code: " << res << "\n";
        cleanup();
        return false;
    }

    vkGetDeviceQueue(device_, selected_queue_family, 0, &compute_queue_);

    // 4. Create Command Pool
    VkCommandPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex = selected_queue_family;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    res = vkCreateCommandPool(device_, &pool_info, nullptr, &command_pool_);
    if (res != VK_SUCCESS) {
        std::cerr << "[VulkanContext] vkCreateCommandPool failed with code: " << res << "\n";
        cleanup();
        return false;
    }

    initialized_ = true;
    return true;
}

void VulkanContext::cleanup() noexcept {
    if (device_ != VK_NULL_HANDLE) {
        if (command_pool_ != VK_NULL_HANDLE) {
            vkDestroyCommandPool(device_, command_pool_, nullptr);
            command_pool_ = VK_NULL_HANDLE;
        }
        vkDestroyDevice(device_, nullptr);
        device_ = VK_NULL_HANDLE;
    }

    if (instance_ != VK_NULL_HANDLE) {
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
    }

    physical_device_ = VK_NULL_HANDLE;
    compute_queue_ = VK_NULL_HANDLE;
    initialized_ = false;
}

uint32_t VulkanContext::find_memory_type(uint32_t type_filter, VkMemoryPropertyFlags properties) const {
    VkPhysicalDeviceMemoryProperties mem_props;
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props);

    for (uint32_t i = 0; i < mem_props.memoryTypeCount; ++i) {
        if ((type_filter & (1 << i)) && (mem_props.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }
    throw std::runtime_error("failed to find suitable memory type!");
}

bool VulkanContext::create_buffer(
    VkDeviceSize size,
    VkBufferUsageFlags usage,
    VkMemoryPropertyFlags properties,
    VulkanBuffer& out_buffer)
{
    out_buffer.size = size;

    VkBufferCreateInfo buffer_info{};
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = size;
    buffer_info.usage = usage;
    buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    if (vkCreateBuffer(device_, &buffer_info, nullptr, &out_buffer.buffer) != VK_SUCCESS) {
        return false;
    }

    VkMemoryRequirements mem_reqs;
    vkGetBufferMemoryRequirements(device_, out_buffer.buffer, &mem_reqs);

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_reqs.size;
    alloc_info.memoryTypeIndex = find_memory_type(mem_reqs.memoryTypeBits, properties);

    if (vkAllocateMemory(device_, &alloc_info, nullptr, &out_buffer.memory) != VK_SUCCESS) {
        vkDestroyBuffer(device_, out_buffer.buffer, nullptr);
        out_buffer.buffer = VK_NULL_HANDLE;
        return false;
    }

    vkBindBufferMemory(device_, out_buffer.buffer, out_buffer.memory, 0);

    if (properties & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) {
        vkMapMemory(device_, out_buffer.memory, 0, size, 0, &out_buffer.mapped);
    }

    return true;
}

void VulkanContext::destroy_buffer(VulkanBuffer& buffer) noexcept {
    if (buffer.mapped != nullptr) {
        vkUnmapMemory(device_, buffer.memory);
        buffer.mapped = nullptr;
    }
    if (buffer.buffer != VK_NULL_HANDLE) {
        vkDestroyBuffer(device_, buffer.buffer, nullptr);
        buffer.buffer = VK_NULL_HANDLE;
    }
    if (buffer.memory != VK_NULL_HANDLE) {
        vkFreeMemory(device_, buffer.memory, nullptr);
        buffer.memory = VK_NULL_HANDLE;
    }
    buffer.size = 0;
}

VkShaderModule VulkanContext::create_shader_module(const std::vector<uint32_t>& spirv) {
    VkShaderModuleCreateInfo create_info{};
    create_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    create_info.codeSize = spirv.size() * sizeof(uint32_t);
    create_info.pCode = spirv.data();

    VkShaderModule module = VK_NULL_HANDLE;
    if (vkCreateShaderModule(device_, &create_info, nullptr, &module) != VK_SUCCESS) {
        return VK_NULL_HANDLE;
    }
    return module;
}

VkShaderModule VulkanContext::load_shader_module_file(const std::string& path) {
    std::ifstream file(path, std::ios::ate | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[VulkanContext] Could not open shader file: " << path << "\n";
        return VK_NULL_HANDLE;
    }

    size_t file_size = static_cast<size_t>(file.tellg());
    std::vector<uint32_t> buffer(file_size / sizeof(uint32_t));
    file.seekg(0);
    file.read(reinterpret_cast<char*>(buffer.data()), file_size);
    file.close();

    return create_shader_module(buffer);
}

VkCommandBuffer VulkanContext::begin_single_time_commands() {
    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandPool = command_pool_;
    alloc_info.commandBufferCount = 1;

    VkCommandBuffer cmd_buffer;
    vkAllocateCommandBuffers(device_, &alloc_info, &cmd_buffer);

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    vkBeginCommandBuffer(cmd_buffer, &begin_info);
    return cmd_buffer;
}

void VulkanContext::end_single_time_commands(VkCommandBuffer command_buffer) {
    vkEndCommandBuffer(command_buffer);

    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &command_buffer;

    vkQueueSubmit(compute_queue_, 1, &submit_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(compute_queue_);

    vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
}

} // namespace sha256_research
