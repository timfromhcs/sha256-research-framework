cmake_minimum_required(VERSION 3.20)
project(sha256_research VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if (MSVC)
    add_compile_options(/W4 /O2 /permissive- /utf-8 /arch:AVX2)
else()
    add_compile_options(-Wall -Wextra -O3 -mavx2)
endif()

# Include directories
include_directories(include)

# Vulkan Support
find_package(Vulkan REQUIRED)
if (Vulkan_FOUND)
    message(STATUS "Vulkan found: ${Vulkan_LIBRARIES}")
    message(STATUS "Vulkan include: ${Vulkan_INCLUDE_DIRS}")
endif()

# Core Library Sources
set(CORE_SOURCES
    src/sha256/sha256_scalar.cpp
    src/cpu/sha256_optimized.cpp
    src/vulkan/vulkan_context.cpp
    src/vulkan/sha256_vulkan.cpp
    src/differential/diff_trail.cpp
    src/sat/sat_encoder.cpp
    src/solver/solver_interface.cpp
    src/verifier/verifier.cpp
    src/storage/experiment_db.cpp
    src/benchmark/benchmark_suite.cpp
)

add_library(sha256_core STATIC ${CORE_SOURCES})
target_include_directories(sha256_core PUBLIC include ${Vulkan_INCLUDE_DIRS})
target_link_libraries(sha256_core PUBLIC Vulkan::Vulkan)

# Main CLI Executable
add_executable(sha-research src/cli/main.cpp)
target_link_libraries(sha-research PRIVATE sha256_core)

# Test Runner Executable
file(GLOB_RECURSE TEST_SOURCES tests/*.cpp)
if (TEST_SOURCES)
    add_executable(sha_tests ${TEST_SOURCES})
    target_link_libraries(sha_tests PRIVATE sha256_core)
endif()

# Compile shaders if glslc is available
find_program(GLSLC_EXECUTABLE NAMES glslc HINTS "${Vulkan_GLSLC_EXECUTABLE}" "$ENV{VULKAN_SDK}/bin")
if (GLSLC_EXECUTABLE)
    message(STATUS "Found glslc: ${GLSLC_EXECUTABLE}")
    file(GLOB SHADER_SOURCES shaders/*.comp)
    foreach(SHADER ${SHADER_SOURCES})
        get_filename_component(SHADER_NAME ${SHADER} NAME)
        set(SPIRV_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/shaders/${SHADER_NAME}.spv")
        add_custom_command(
            OUTPUT ${SPIRV_OUTPUT}
            COMMAND ${GLSLC_EXECUTABLE} ${SHADER} -o ${SPIRV_OUTPUT}
            DEPENDS ${SHADER}
            COMMENT "Compiling SPIR-V shader: ${SHADER_NAME}"
        )
        list(APPEND SPIRV_SHADERS ${SPIRV_OUTPUT})
    endforeach()
    add_custom_target(compile_shaders ALL DEPENDS ${SPIRV_SHADERS})
    add_dependencies(sha256_core compile_shaders)
endif()
