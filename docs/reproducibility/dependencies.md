# Dependency Locking & Provenance Manifest

## System Dependencies
| Dependency | Version | Source / Location | License | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **MSVC Toolset** | 19.44.35228.0 | Microsoft Visual Studio 2022 | Commercial / Community | `vswhere.exe` |
| **CMake** | 4.4.0 | Python Scripts / Kitware | BSD 3-Clause | `cmake --version` |
| **Ninja** | 1.13.2 | WinGet Packages | Apache 2.0 | `ninja --version` |
| **Vulkan SDK** | 1.4.357.0 | LunarG | Apache 2.0 | `vulkaninfo --summary` |
| **Python** | 3.14.6 | Python Software Foundation | PSF License | `python --version` |
| **Rust** | 1.96.0 | Rustup / Cargo | MIT / Apache 2.0 | `rustc --version` |

## Solvers
| Solver | Version | Upstream Repository | License | Installed Location |
| :--- | :--- | :--- | :--- | :--- |
| **CaDiCaL** | 3.0.1 | `https://github.com/arminbiere/cadical` | MIT | WSL `/usr/local/bin/cadical` |
| **Kissat** | 4.0.4 | `https://github.com/arminbiere/kissat` | MIT | WSL `/usr/local/bin/kissat` |
| **CryptoMiniSat** | 5.8.0 | `https://github.com/msoos/cryptominisat` | MIT | WSL `/usr/bin/cryptominisat5` |
| **MiniSat** | 2.2.1 | `http://minisat.se/` | MIT | WSL `/usr/bin/minisat` |
| **Z3** | 4.16.0 | `https://github.com/Z3Prover/z3` | MIT | Python `z3-solver` & WSL `/usr/bin/z3` |

## Python Packages
- `torch`: 2.12.1+cpu (PyTorch Foundation, BSD-style)
- `scikit-learn`: 1.9.0 (BSD 3-Clause)
- `scipy`: 1.18.0 (BSD 3-Clause)
- `sqlite3`: 3.50.4 (Public Domain)
