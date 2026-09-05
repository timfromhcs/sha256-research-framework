# Windows 11 Native Architecture & Hardware Profile

## Host Platform Specification
- **Operating System**: Windows 11 Pro (Build 26200, 64-bit)
- **PowerShell**: PowerShell Core 7.6.5
- **CPU**: AMD Ryzen 7 7735HS with Radeon Graphics
  - Physical Cores: 8
  - Logical Processors: 16
  - Architecture: Zen 3+ (Rembrandt-R)
  - Max Frequency: 3201 MHz
  - Features Detected: AVX, AVX2, FMA3, BMI1, BMI2, SSE4.2, SHA-NI
- **Memory**: ~20 GB Visible RAM (~1.9 GB Free during baseline)
- **Storage**: Fast NVMe SSD storage on drive C:

## Multicore Performance
The CPU backend utilizes hardware concurrency detection to partition batch hashing workloads evenly across all 16 execution threads. Measured all-core throughput reaches **27.18 Million hashes/sec** (over 1.4 GB/s of raw hashing throughput).
