# Machine Capability & Environment Inventory

Generated: 2026-09-11 20:16:40 +02:00

## 1. Operating System
| Property | Value |
| :--- | :--- |
| **OS Caption** | Microsoft Windows 11 Pro |
| **Version** | 10.0.26200 |
| **Build Number** | 26200 |
| **Architecture** | 64-Bit |
| **PowerShell Version** | 7.6.6 |
| **Administrator Privilege** | False |

## 2. Hardware Capabilities
### CPU
- **Model**: AMD Ryzen 7 7735HS with Radeon Graphics
- **Physical Cores**: 8
- **Logical Threads**: 16
- **Max Frequency**: 3201 MHz
- **Instruction Sets**: x86-64, AVX, AVX2, FMA3, BMI1, BMI2, SSE4.2, SHA-NI

### Memory & Storage
- **RAM**: 19.79 GB Visible (9.04 GB Free)
- **Storage**: C: Free 154.32 GB, Used 775.91 GB; Temp: Free 154.32 GB, Used 775.91 GB

### GPU & Compute Acceleration
- **GPU Device**: Parsec Virtual Display Adapter
- **Driver Version**: 0.45.0.0
- **Vulkan SDK**: C:\VulkanSDK\1.4.357.0
- **Vulkan API**: 1.4
- **Compute Queue**: Available via AMD Proprietary Driver (RDNA 2 Compute Units)

## 3. Toolchain & Compilers
| Tool | Path | Version |
| :--- | :--- | :--- |
| **Git** | C:\Program Files\Git\cmd\git.exe | git version 2.54.0.windows.1 |
| **CMake** | C:\Program Files\Python314\Scripts\cmake.exe | cmake version 4.4.0 |
| **Ninja** | C:\Users\hcsme\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe\ninja.exe | ninja 1.13.2 |
| **Clang** | C:\Program Files\AMD\ROCm\7.1\bin\clang.exe | clang version 21.0.0git (git@github.com:Compute-Mirrors/llvm-project 5dcc622b51ecd499912c1062ce2b0ecda60d8e93) |
| **MSVC** | C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools | Visual Studio 2022 Community |
| **Python** | C:\Program Files\Python314\python.exe | Python 3.14.6 |
| **Rust** | C:\Users\hcsme\.cargo\bin\rustc.exe | rustc 1.96.0 (ac68faa20 2026-05-25) |

## 4. Solvers & Cryptanalysis Backends
| Solver | Execution Target | Status | Version / Note |
| :--- | :--- | :--- | :--- |
| **Z3 SMT Solver** | Native Python | Available | 4.16.0 |
| **Z3 CLI** | WSL2 (Ubuntu 22.04) | Available | Z3 version 4.8.12 - 64 bit |
| **CaDiCaL SAT Solver** | WSL2 / Local Native | Available | 3.0.1 |
| **CryptoMiniSat** | WSL2 | Available | c CryptoMiniSat version 5.8.0 |
| **MiniSat** | WSL2 | Available | ERROR! Unknown flag "-version". Use '--help' for help. |
| **Kissat** | WSL2 | Available/Building | In build pipeline |

## 5. ML & Data Frameworks
- **PyTorch**: 2.12.1+cpu
- **Scikit-Learn**: 1.9.0
- **SciPy**: 1.18.0
- **SQLite3**: 3.50.4

---
*Verified automatically by scripts/doctor.ps1*.
