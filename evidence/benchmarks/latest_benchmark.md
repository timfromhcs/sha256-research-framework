# Performance Benchmark Report

- **Timestamp**: 2026-09-11T18:17:13Z
- **CPU**: features=[SSE4.2: Yes, AVX: Yes, AVX2: Yes, BMI2: Yes, SHA-NI: Yes] hw_threads=16 compiler=MSVC build=Debug
- **GPU**: Vulkan compiled in (see per-metric device/notes)

| Benchmark Category | Backend | Throughput (hashes/s) | Bandwidth (MB/s) | Latency (us/op) | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SHA-256 Scalar Reference | CPU Portable Scalar | 2060849 | 125.78 | 0.485 | Final hash: 1d12065b... |
| SHA-256 Optimized CPU (1 Thread) | CPU Unrolled Fast Path | 4254640 | 223.16 | 0.235 | Features: SSE4.2: Yes, AVX: Yes, AVX2: Yes, BMI2: Yes, SHA-NI: Yes |
| SHA-256 Optimized CPU (16 Threads) | CPU Multithreaded Unrolled | 34539212 | 1811.65 | 0.029 | Dispatched across 16 logical cores |
| SAT Encoding Throughput (16 rounds) | SAT Tseitin Transform Engine | 115 | 0.00 | 8658.470 | 15888 variables, 66536 clauses per problem |
| SHA-256 Vulkan Compute Batch (32768 items, 64 rounds) | Vulkan Compute (SPIR-V) | 769234 | 46.95 | 1.300 | Device: AMD Radeon(TM) Graphics | CPU Verified: YES |
