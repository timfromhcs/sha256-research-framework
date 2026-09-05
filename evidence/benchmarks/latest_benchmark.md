# Performance Benchmark Report

- **Timestamp**: 2026-09-05
- **CPU**: AMD Ryzen 7 7735HS (8C/16T)
- **GPU**: AMD Radeon 680M Graphics (Vulkan 1.4)

| Benchmark Category | Backend | Throughput (hashes/s) | Bandwidth (MB/s) | Latency (us/op) | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SHA-256 Scalar Reference | CPU Portable Scalar | 1840922 | 112.36 | 0.543 | Final hash: 1d12065b... |
| SHA-256 Optimized CPU (1 Thread) | CPU Unrolled Fast Path | 3427087 | 179.76 | 0.292 | Features: SSE4.2: Yes, AVX: Yes, AVX2: Yes, BMI2: Yes, SHA-NI: Yes |
| SHA-256 Optimized CPU (16 Threads) | CPU Multithreaded Unrolled | 27183220 | 1425.82 | 0.037 | Dispatched across 16 logical cores |
| SAT Encoding Throughput (16 rounds) | SAT Tseitin Transform Engine | 79 | 0.00 | 12661.600 | 15888 variables, 66536 clauses per problem |
| SHA-256 Vulkan Compute Batch (32768 items, 64 rounds) | Vulkan Compute (SPIR-V) | 720470 | 43.97 | 1.388 | Device: AMD Radeon(TM) Graphics | CPU Verified: YES |
