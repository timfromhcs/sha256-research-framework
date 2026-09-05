# Vulkan Compute Architecture & GPU Profile

Reference-machine profile (example, not a requirement). Vulkan is an **optional** capability: CPU-only builds (`-DSHA256_ENABLE_VULKAN=OFF`) work without any SDK, and all GPU results are cross-checked against the CPU reference.

## Example Vulkan Runtime (reference machine)
- **API Version**: Vulkan 1.4.315 / SDK 1.4.357.0
- **Device**: AMD Radeon(TM) Graphics (Device ID: `0x1681`, Vendor ID: `0x1002`)
- **Driver**: AMD Proprietary Driver 2.0.353 (Shader Compiler 26.6.1)
- **Device Type**: Integrated GPU (RDNA 2 Architecture)
- **Compute Queue Family**: Index 0, supports simultaneous compute and memory transfer operations.

## Compute Pipeline
1. **Shader Source**: Written in GLSL 450 compute dialect (`shaders/sha256.comp`, `shaders/differential.comp`, `shaders/search.comp`).
2. **Compilation**: Compiled offline or at build time into binary SPIR-V bytecode using `glslc`.
3. **Memory Buffers**: Uses host-visible, host-coherent storage buffers (`VK_BUFFER_USAGE_STORAGE_BUFFER_BIT`) to avoid synchronization overhead for streaming batch transfers.
4. **Workgroup Configuration**: Local workgroup size of `(64, 1, 1)` invocations per workgroup, aligning with RDNA 2 wavefront execution units.
5. **Cross-Validation**: GPU compute output is verified against golden CPU scalar calculations to guarantee zero hardware floating/bitwise discrepancies.
