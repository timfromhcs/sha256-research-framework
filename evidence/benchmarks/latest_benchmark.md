# Performance Benchmark Report

- **Timestamp**: 2026-09-05T17:06:57Z
- **CPU**: features=[SSE4.2: Yes, AVX: Yes, AVX2: Yes, BMI2: Yes, SHA-NI: Yes] hw_threads=16 compiler=MSVC build=Release
- **GPU**: Vulkan compiled in (see per-metric device/notes)

| Benchmark Category | Backend | Throughput (hashes/s) | Bandwidth (MB/s) | Latency (us/op) | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SHA-256 Scalar Reference | CPU Portable Scalar | 1852634 | 113.08 | 0.540 | Final hash: 1d12065b... |
| SHA-256 Optimized CPU (1 Thread) | CPU Unrolled Fast Path | 3610917 | 189.40 | 0.277 | Features: SSE4.2: Yes, AVX: Yes, AVX2: Yes, BMI2: Yes, SHA-NI: Yes |
| SHA-256 Optimized CPU (16 Threads) | CPU Multithreaded Unrolled | 22475041 | 1178.86 | 0.044 | Dispatched across 16 logical cores |
| SAT Encoding Throughput (16 rounds) | SAT Tseitin Transform Engine | 62 | 0.00 | 16064.840 | 15888 variables, 66536 clauses per problem |
| SHA-256 Vulkan Compute Batch (32768 items, 64 rounds) | Vulkan Compute (SPIR-V) | 565209 | 34.50 | 1.769 | Device: AMD Radeon(TM) Graphics | CPU Verified: YES |
