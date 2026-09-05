# Build System Architecture

## Overview
The framework utilizes modern CMake (version >= 3.20) with target-based configuration and multi-generator support (Visual Studio 2022, Ninja, GCC/Clang).

## CMake Targets
- `sha256_core`: Static C++20 library encapsulating all core algorithms, solver interfaces, compute runners, and storage primitives.
- `sha-research`: Primary CLI executable providing interactive and scripted access to all framework modules.
- `sha_tests`: Automated test suite runner exercising unit, KAT, backend equivalence, and negative verification gates.
- `compile_shaders`: Custom target invoking the Vulkan SDK's `glslc` compiler to compile `.comp` files into SPIR-V `.spv` binaries.

## CMake Presets
Defined in `CMakePresets.json`:
- `windows-msvc-release`: Uses Visual Studio 17 2022 with 64-bit architecture and Release optimization (`/O2 /arch:AVX2 /utf-8`).
- `windows-ninja-release`: Uses Ninja generator on Windows.
- `wsl-linux-release`: Uses Ninja generator on Linux/WSL2.

## Compiler Flags
- **MSVC**: `/W4 /O2 /permissive- /utf-8 /arch:AVX2`
- **GCC / Clang**: `-Wall -Wextra -O3 -mavx2 -std=c++20`
