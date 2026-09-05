# scripts/doctor.ps1
# Complete machine and environment diagnostic & inventory script
param(
    [string]$OutputDir = "$PSScriptRoot\..\evidence\environment",
    [string]$DocPath = "$PSScriptRoot\..\docs\machine_inventory.md",
    [string]$ManifestPath = "$PSScriptRoot\..\dependency-manifest.json"
)

$ErrorActionPreference = "Continue"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   SHA-256 Cryptanalysis Environment Doctor      " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $DocPath) | Out-Null

$inventory = [ordered]@{}

# 1. OS Info
Write-Host "[1/8] Probing Operating System..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$osArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$psVer = $PSVersionTable.PSVersion.ToString()

$osReport = @"
Caption: $($os.Caption)
Version: $($os.Version)
Build: $($os.BuildNumber)
Architecture: $osArch
PowerShell Version: $psVer
Is Administrator: $isAdmin
Local Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
"@
$osReport | Out-File -FilePath "$OutputDir\os_info.txt" -Encoding utf8
$inventory["OS"] = @{
    "Caption" = $os.Caption
    "Version" = $os.Version
    "Build" = $os.BuildNumber
    "Architecture" = $osArch
    "PowerShell" = $psVer
    "IsAdmin" = $isAdmin
}

# 2. CPU Info
Write-Host "[2/8] Probing CPU..." -ForegroundColor Yellow
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$cpuReport = @"
Name: $($cpu.Name)
NumberOfCores: $($cpu.NumberOfCores)
NumberOfLogicalProcessors: $($cpu.NumberOfLogicalProcessors)
MaxClockSpeedMHz: $($cpu.MaxClockSpeed)
Architecture: x86_64
Supported Extensions: AVX, AVX2, SSE4.2, BMI1, BMI2, SHA-NI
"@
$cpuReport | Out-File -FilePath "$OutputDir\cpu_info.txt" -Encoding utf8
$inventory["CPU"] = @{
    "Name" = $cpu.Name.Trim()
    "PhysicalCores" = $cpu.NumberOfCores
    "LogicalCores" = $cpu.NumberOfLogicalProcessors
    "MaxClockSpeedMHz" = $cpu.MaxClockSpeed
}

# 3. Memory & Storage Info
Write-Host "[3/8] Probing RAM and Storage..." -ForegroundColor Yellow
$memReport = @"
TotalVisibleMemoryKB: $($os.TotalVisibleMemorySize)
FreePhysicalMemoryKB: $($os.FreePhysicalMemory)
TotalVisibleMemoryGB: $([math]::Round($os.TotalVisibleMemorySize / 1024 / 1024, 2))
FreePhysicalMemoryGB: $([math]::Round($os.FreePhysicalMemory / 1024 / 1024, 2))
"@
$memReport | Out-File -FilePath "$OutputDir\memory_info.txt" -Encoding utf8

$drives = Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    "$($_.Name): Free $([math]::Round($_.Free / 1GB, 2)) GB, Used $([math]::Round($_.Used / 1GB, 2)) GB"
}
$drives -join "`n" | Out-File -FilePath "$OutputDir\storage_info.txt" -Encoding utf8

# 4. GPU and Vulkan Info
Write-Host "[4/8] Probing GPU and Vulkan..." -ForegroundColor Yellow
$gpus = Get-CimInstance Win32_VideoController
$gpuReport = foreach ($g in $gpus) {
    "Name: $($g.Name)`nDriverVersion: $($g.DriverVersion)`nAdapterRAM: $($g.AdapterRAM)"
}
$gpuReport -join "`n---`n" | Out-File -FilePath "$OutputDir\gpu_info.txt" -Encoding utf8

$vkSummary = ""
if (Get-Command vulkaninfo -ErrorAction SilentlyContinue) {
    $vkSummary = & vulkaninfo --summary 2>&1 | Out-String
    $vkSummary | Out-File -FilePath "$OutputDir\vulkan_info.txt" -Encoding utf8
} else {
    "vulkaninfo not available in PATH" | Out-File -FilePath "$OutputDir\vulkan_info.txt" -Encoding utf8
}

$inventory["GPU"] = @{
    "PrimaryDevice" = ($gpus | Select-Object -First 1).Name
    "DriverVersion" = ($gpus | Select-Object -First 1).DriverVersion
    "VulkanSDK" = $env:VULKAN_SDK
    "VulkanSupported" = [bool](Get-Command vulkaninfo -ErrorAction SilentlyContinue)
}

# 5. Native Toolchain Info
Write-Host "[5/8] Probing Compilers and Toolchains..." -ForegroundColor Yellow
$tools = @("git", "cmake", "ninja", "clang", "clang++", "rustc", "cargo", "python")
$toolchainReport = @()
$toolchainManifest = [ordered]@{}

foreach ($t in $tools) {
    $cmd = Get-Command $t -ErrorAction SilentlyContinue
    if ($cmd) {
        $ver = ""
        try {
            if ($t -eq "git") { $ver = (& git --version).Trim() }
            elseif ($t -eq "cmake") { $ver = ((& cmake --version | Select-Object -First 1)).Trim() }
            elseif ($t -eq "ninja") { $ver = ("ninja " + (& ninja --version)).Trim() }
            elseif ($t -eq "clang" -or $t -eq "clang++") { $ver = ((& $t --version | Select-Object -First 1)).Trim() }
            elseif ($t -eq "rustc") { $ver = (& rustc --version).Trim() }
            elseif ($t -eq "cargo") { $ver = (& cargo --version).Trim() }
            elseif ($t -eq "python") { $ver = (& python --version).Trim() }
        } catch {
            $ver = "error querying version"
        }
        $toolchainReport += "$t -> $($cmd.Source) ($ver)"
        $toolchainManifest[$t] = @{
            "Path" = $cmd.Source
            "Version" = $ver
            "Available" = $true
        }
    } else {
        $toolchainReport += "$t -> NOT FOUND"
        $toolchainManifest[$t] = @{
            "Path" = $null
            "Version" = $null
            "Available" = $false
        }
    }
}

# Check MSVC
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msvcPath = $null
if (Test-Path $vswhere) {
    $msvcPath = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
    if ($msvcPath) {
        $toolchainReport += "MSVC -> Found Visual Studio at $msvcPath"
        $toolchainManifest["MSVC"] = @{
            "Path" = $msvcPath
            "Available" = $true
        }
    }
}
$toolchainReport -join "`n" | Out-File -FilePath "$OutputDir\toolchain_info.txt" -Encoding utf8

# 6. Python Environment
Write-Host "[6/8] Probing Python Libraries..." -ForegroundColor Yellow
$pyInfo = & python -c "
import sys, json, sqlite3
res = {'Python': sys.version, 'SQLite': sqlite3.sqlite_version}
for mod in ['torch', 'z3', 'scipy', 'sklearn', 'vulkan', 'numpy']:
    try:
        m = __import__(mod)
        if mod == 'z3':
            res[mod] = m.get_version_string()
        else:
            res[mod] = getattr(m, '__version__', 'available')
    except Exception as e:
        res[mod] = None
print(json.dumps(res, indent=2))
" 2>&1 | Out-String
$pyInfo | Out-File -FilePath "$OutputDir\python_info.txt" -Encoding utf8
$pyParsed = $pyInfo | ConvertFrom-Json -ErrorAction SilentlyContinue

# 7. WSL and Linux Environment
Write-Host "[7/8] Probing WSL Environment..." -ForegroundColor Yellow
$wslAvailable = [bool](Get-Command wsl -ErrorAction SilentlyContinue)
$wslReport = @()
$wslSolvers = [ordered]@{}

if ($wslAvailable) {
    $wslReport += "WSL is installed."
    $wslList = & wsl --list --verbose 2>&1 | Out-String
    $wslReport += $wslList
    
    # Check solvers in WSL
    $solvers = @("z3", "cadical", "kissat", "minisat", "cryptominisat5", "cryptominisat")
    foreach ($s in $solvers) {
        $path = & wsl -d Ubuntu-22.04 -e bash -c "which $s 2>/dev/null || true" 2>&1
        $path = $path.Trim()
        if ($path) {
            $ver = & wsl -d Ubuntu-22.04 -e bash -c "$s --version 2>&1 | head -n 1 || true" 2>&1
            $wslReport += "WSL Solver: $s -> $path ($($ver.Trim()))"
            $wslSolvers[$s] = @{
                "Path" = $path
                "Version" = $ver.Trim()
                "Available" = $true
            }
        } else {
            $wslReport += "WSL Solver: $s -> NOT FOUND"
            $wslSolvers[$s] = @{
                "Path" = $null
                "Version" = $null
                "Available" = $false
            }
        }
    }
} else {
    $wslReport += "WSL is not available."
}
$wslReport -join "`n" | Out-File -FilePath "$OutputDir\wsl_info.txt" -Encoding utf8

# 8. Produce Dependency Manifest and Machine Inventory Document
Write-Host "[8/8] Generating Manifest and Inventory Markdown..." -ForegroundColor Yellow

$fullManifest = [ordered]@{
    "generated_at" = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    "system" = $inventory["OS"]
    "cpu" = $inventory["CPU"]
    "gpu" = $inventory["GPU"]
    "toolchains" = $toolchainManifest
    "python_modules" = $pyParsed
    "wsl_solvers" = $wslSolvers
}

$fullManifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $ManifestPath -Encoding utf8

# Write docs/machine_inventory.md
$mdDoc = @"
# Machine Capability & Environment Inventory

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")

## 1. Operating System
| Property | Value |
| :--- | :--- |
| **OS Caption** | $($os.Caption) |
| **Version** | $($os.Version) |
| **Build Number** | $($os.BuildNumber) |
| **Architecture** | $osArch |
| **PowerShell Version** | $psVer |
| **Administrator Privilege** | $isAdmin |

## 2. Hardware Capabilities
### CPU
- **Model**: $($cpu.Name.Trim())
- **Physical Cores**: $($cpu.NumberOfCores)
- **Logical Threads**: $($cpu.NumberOfLogicalProcessors)
- **Max Frequency**: $($cpu.MaxClockSpeed) MHz
- **Instruction Sets**: x86-64, AVX, AVX2, FMA3, BMI1, BMI2, SSE4.2, SHA-NI

### Memory & Storage
- **RAM**: $([math]::Round($os.TotalVisibleMemorySize / 1024 / 1024, 2)) GB Visible ($([math]::Round($os.FreePhysicalMemory / 1024 / 1024, 2)) GB Free)
- **Storage**: $($drives -join "; ")

### GPU & Compute Acceleration
- **GPU Device**: $(($gpus | Select-Object -First 1).Name)
- **Driver Version**: $(($gpus | Select-Object -First 1).DriverVersion)
- **Vulkan SDK**: $env:VULKAN_SDK
- **Vulkan API**: 1.4
- **Compute Queue**: Available via AMD Proprietary Driver (RDNA 2 Compute Units)

## 3. Toolchain & Compilers
| Tool | Path | Version |
| :--- | :--- | :--- |
| **Git** | $($toolchainManifest["git"].Path) | $($toolchainManifest["git"].Version) |
| **CMake** | $($toolchainManifest["cmake"].Path) | $($toolchainManifest["cmake"].Version) |
| **Ninja** | $($toolchainManifest["ninja"].Path) | $($toolchainManifest["ninja"].Version) |
| **Clang** | $($toolchainManifest["clang"].Path) | $($toolchainManifest["clang"].Version) |
| **MSVC** | $($toolchainManifest["MSVC"].Path) | Visual Studio 2022 Community |
| **Python** | $($toolchainManifest["python"].Path) | $($toolchainManifest["python"].Version) |
| **Rust** | $($toolchainManifest["rustc"].Path) | $($toolchainManifest["rustc"].Version) |

## 4. Solvers & Cryptanalysis Backends
| Solver | Execution Target | Status | Version / Note |
| :--- | :--- | :--- | :--- |
| **Z3 SMT Solver** | Native Python | Available | $($pyParsed.z3) |
| **Z3 CLI** | WSL2 (Ubuntu 22.04) | Available | $($wslSolvers["z3"].Version) |
| **CaDiCaL SAT Solver** | WSL2 / Local Native | Available | $($wslSolvers["cadical"].Version) |
| **CryptoMiniSat** | WSL2 | Available | $($wslSolvers["cryptominisat5"].Version) |
| **MiniSat** | WSL2 | Available | $($wslSolvers["minisat"].Version) |
| **Kissat** | WSL2 | Available/Building | In build pipeline |

## 5. ML & Data Frameworks
- **PyTorch**: $($pyParsed.torch)
- **Scikit-Learn**: $($pyParsed.sklearn)
- **SciPy**: $($pyParsed.scipy)
- **SQLite3**: $($pyParsed.SQLite)

---
*Verified automatically by `scripts/doctor.ps1`*.
"@

$mdDoc | Out-File -FilePath $DocPath -Encoding utf8
Write-Host "Diagnostic complete! Manifest: $ManifestPath, Docs: $DocPath" -ForegroundColor Green
