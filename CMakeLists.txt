cmake_minimum_required(VERSION 3.20)
project(sha256_research VERSION 5.1.0 LANGUAGES C CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(SHA256_RESEARCH_VERSION="${PROJECT_VERSION}")

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

# Standalone Independent Verifier Core (Segregated trust boundary; no SAT/solver/search/benchmarks)
add_library(sha256_verifier_core STATIC src/verifier/verifier.cpp)
target_include_directories(sha256_verifier_core PUBLIC include)

# Standalone Verifier Executable (linked only to segregated verifier core)
add_executable(sha-verifier verifier/standalone/main.cpp)
target_link_libraries(sha-verifier PRIVATE sha256_verifier_core)

# Dedicated NIST million 'a' test executable
add_executable(test_million_a tests/test_million_a.cpp)
target_link_libraries(test_million_a PRIVATE sha256_core)

# Dedicated Determinism & Reproducibility test executable
add_executable(test_determinism tests/test_determinism.cpp)
target_link_libraries(test_determinism PRIVATE sha256_core)

# Adversarial & Tamper Detection Tests
add_executable(sha_adversarial_tests tests/adversarial/test_tamper_detection.cpp)
target_link_libraries(sha_adversarial_tests PRIVATE sha256_core)

# Context-shaping preimage search. Self-contained: it implements the reduced
# round function itself so that it shares no code with the SAT encoder, which
# is what makes it usable as an independent producer of preimage witnesses.
find_package(Threads REQUIRED)
add_executable(context_shaping tools/context_shaping.cpp)
target_link_libraries(context_shaping PRIVATE Threads::Threads)

# First-moment spectral test for the 20-round residual c3.
add_executable(c3_spectrum tools/c3_spectrum.cpp)

# Add tests to CTest
add_test(NAME sha-tests COMMAND $<TARGET_FILE:sha_tests>)
add_test(NAME sha-adversarial-tests COMMAND $<TARGET_FILE:sha_adversarial_tests>)
add_test(NAME test-million-a COMMAND $<TARGET_FILE:test_million_a>)
add_test(NAME test-determinism COMMAND $<TARGET_FILE:test_determinism>)
add_test(NAME verifier-kat COMMAND $<TARGET_FILE:sha-verifier> test-vectors)
add_test(NAME verifier-negative COMMAND $<TARGET_FILE:sha-verifier> test-negative)
# The self-test proves the backward chain and every algebraic identity of the
# construction on planted states. It is fast and needs no table, so it belongs
# in the default CTest set.
add_test(NAME context-shaping-selftest COMMAND $<TARGET_FILE:context_shaping> selftest)
# Structural statistics of sigma0/sigma1, checked against closed forms.
add_test(NAME context-shaping-multifibre COMMAND $<TARGET_FILE:context_shaping> multifibre)

# The table cache is written by one code path and read by another, and a skew
# between the two produces a table that loads and reports plausible statistics
# while returning wrong roots. This round-trips a table through disk and checks
# the reloaded copy against brute force.
add_test(NAME context-shaping-table-roundtrip COMMAND $<TARGET_FILE:context_shaping> tabletest --roundtrip)

# CLI contract smoke tests
add_test(NAME cli-version COMMAND $<TARGET_FILE:sha-research> --version)
add_test(NAME cli-help COMMAND $<TARGET_FILE:sha-research> --help)
add_test(NAME verifier-version COMMAND $<TARGET_FILE:sha-verifier> --version)
add_test(NAME verifier-help COMMAND $<TARGET_FILE:sha-verifier> --help)
add_test(NAME context-shaping-version COMMAND $<TARGET_FILE:context_shaping> --version)
add_test(NAME context-shaping-help COMMAND $<TARGET_FILE:context_shaping> --help)
add_test(NAME c3-spectrum-version COMMAND $<TARGET_FILE:c3_spectrum> --version)
add_test(NAME c3-spectrum-help COMMAND $<TARGET_FILE:c3_spectrum> --help)

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

# Install & Packaging Rules (CPack)
include(GNUInstallDirs)

install(TARGETS sha-research sha-verifier context_shaping c3_spectrum
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT runtime
)

install(FILES LICENSE README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/sha256-research-framework
    COMPONENT documentation
)

install(DIRECTORY docs/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/sha256-research-framework/docs
    COMPONENT documentation
)

install(FILES tools/verify_published.py tools/z3_bitvector_check.py
    DESTINATION ${CMAKE_INSTALL_DATADIR}/sha256-research-framework/tools
    COMPONENT tools
)

set(CPACK_PACKAGE_NAME "sha256-research-framework")
set(CPACK_PACKAGE_VENDOR "timfromhcs")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

if (WIN32)
    set(CPACK_GENERATOR "ZIP")
elseif (APPLE)
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_GENERATOR "TGZ")
endif()

include(CPack)
