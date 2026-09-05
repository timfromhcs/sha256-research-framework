# Troubleshooting & Diagnostic Guide

## Common Diagnostics

### 1. `vulkaninfo` reports device missing or driver mismatch
- **Cause**: The system's virtual display driver (e.g. Parsec or RDP) took precedence over the physical GPU.
- **Solution**: Check physical device enumeration order. The framework automatically scores physical devices to prioritize discrete and integrated GPUs over virtual adapters.

### 2. WSL Solver invocation fails with `command not found`
- **Cause**: CaDiCaL or Kissat binaries are not in `/usr/local/bin` inside the WSL distribution.
- **Solution**: Run `pwsh -File scripts/bootstrap.ps1` to ensure CaDiCaL and Kissat are compiled and copied into `/usr/local/bin`.

### 3. CMake cannot locate MSVC compiler
- **Cause**: Visual Studio 2022 build tools path is not discovered.
- **Solution**: Use the `-G "Visual Studio 17 2022" -A x64` generator flag, which leverages `vswhere.exe` to automatically locate MSVC.

### 4. SAT Solver reports TIMEOUT on rounds > 20
- **Cause**: The cryptographic step function introduces high non-linearity that saturates CDCL clause learning.
- **Solution**: Use reduced round targets (e.g. 8 to 16 rounds) or apply message schedule degree-of-freedom fixing (`fixed_message_words`).
