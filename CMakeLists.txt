cmake_minimum_required(VERSION 3.20)
project(sha256_research VERSION 2.0.0 LANGUAGES C CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags (portable: no mandatory AVX2; auto-vectorization only)
if (MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG   "/Zi /Ob0 /Od /W4")
    set(CMAKE_CXX_FLAGS_RELEASE "/W4 /O2 /Ob2 /permissive- /utf-8")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "/W4 /O1 /Ob1 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/W4 /Zi /O2 /Ob1 /DNDEBUG")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")
endif()

# Include directories
include_directories(include)

# Vulkan Support (OPTIONAL capability; CPU-only builds must work without SDK)
option(SHA256_ENABLE_VULKAN "Enable Vulkan GPU compute backend" ON)
set(SHA256_HAVE_VULKAN 0)
if (SHA256_ENABLE_VULKAN)
    find_package(Vulkan QUIET)
    if (Vulkan_FOUND)
        set(SHA256_HAVE_VULKAN 1)
        message(STATUS "Vulkan found: ${Vulkan_LIBRARIES}")
        message(STATUS "Vulkan include: ${Vulkan_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "Vulkan enabled (SHA256_ENABLE_VULKAN=ON) but Vulkan SDK was not found. To build without Vulkan, specify -DSHA256_ENABLE_VULKAN=OFF.")
    endif()
else()
    message(STATUS "Vulkan explicitly disabled; building CPU-only.")
endif()

# Core Library Sources (Vulkan sources only when available)
set(CORE_SOURCES
    src/sha256/sha256_scalar.cpp
    src/cpu/sha256_optimized.cpp
    src/differential/diff_trail.cpp
    src/sat/sat_encoder.cpp
    src/solver/solver_interface.cpp
    src/verifier/verifier.cpp
    src/storage/experiment_db.cpp
    src/benchmark/benchmark_suite.cpp
)

if (SHA256_HAVE_VULKAN)
    list(APPEND CORE_SOURCES
        src/vulkan/vulkan_context.cpp
        src/vulkan/sha256_vulkan.cpp
    )
else()
    list(APPEND CORE_SOURCES
        src/vulkan/sha256_vulkan_stub.cpp
    )
endif()

add_library(sha256_core STATIC ${CORE_SOURCES})
target_include_directories(sha256_core PUBLIC include)
target_compile_definitions(sha256_core PUBLIC SHA256_HAVE_VULKAN=${SHA256_HAVE_VULKAN})
if (SHA256_HAVE_VULKAN)
    target_include_directories(sha256_core PUBLIC ${Vulkan_INCLUDE_DIRS})
    target_link_libraries(sha256_core PUBLIC Vulkan::Vulkan)
endif()

# Main CLI Executable
add_executable(sha-research src/cli/main.cpp)
target_link_libraries(sha-research PRIVATE sha256_core)

# Test Runner Executable
add_executable(sha_tests tests/test_main.cpp)
target_link_libraries(sha_tests PRIVATE sha256_core)

# Standalone Verifier Executable
add_executable(sha-verifier verifier/standalone/main.cpp)
target_link_libraries(sha-verifier PRIVATE sha256_core)

# Dedicated NIST million 'a' test executable
add_executable(test_million_a tests/test_million_a.cpp)
target_link_libraries(test_million_a PRIVATE sha256_core)

# Dedicated Determinism & Reproducibility test executable
add_executable(test_determinism tests/test_determinism.cpp)
target_link_libraries(test_determinism PRIVATE sha256_core)

# Adversarial & Tamper Detection Tests
add_executable(sha_adversarial_tests tests/adversarial/test_tamper_detection.cpp)
target_link_libraries(sha_adversarial_tests PRIVATE sha256_core)

# Add tests to CTest
add_test(NAME sha-tests COMMAND $<TARGET_FILE:sha_tests>)
add_test(NAME sha-adversarial-tests COMMAND $<TARGET_FILE:sha_adversarial_tests>)
add_test(NAME test-million-a COMMAND $<TARGET_FILE:test_million_a>)
add_test(NAME test-determinism COMMAND $<TARGET_FILE:test_determinism>)
add_test(NAME verifier-kat COMMAND $<TARGET_FILE:sha-verifier> test-vectors)
add_test(NAME verifier-negative COMMAND $<TARGET_FILE:sha-verifier> test-negative)

# Compile shaders only when Vulkan + glslc are available
find_program(GLSLC_EXECUTABLE NAMES glslc HINTS "${Vulkan_GLSLC_EXECUTABLE}" "$ENV{VULKAN_SDK}/bin")
if (GLSLC_EXECUTABLE AND SHA256_HAVE_VULKAN)
    message(STATUS "Found glslc: ${GLSLC_EXECUTABLE}")
    file(GLOB SHADER_SOURCES shaders/*.comp)
    foreach(SHADER ${SHADER_SOURCES})
        get_filename_component(SHADER_NAME_WE ${SHADER} NAME_WE)
        set(SPIRV_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/shaders/${SHADER_NAME_WE}.spv")
        add_custom_command(
            OUTPUT ${SPIRV_OUTPUT}
            COMMAND ${GLSLC_EXECUTABLE} ${SHADER} -o ${SPIRV_OUTPUT}
            DEPENDS ${SHADER}
            COMMENT "Compiling SPIR-V shader: ${SHADER_NAME_WE}.spv"
        )
        list(APPEND SPIRV_SHADERS ${SPIRV_OUTPUT})
    endforeach()
    add_custom_target(compile_shaders ALL DEPENDS ${SPIRV_SHADERS})
    add_dependencies(sha256_core compile_shaders)
endif()
