---
title: SHA-256 Cryptanalysis Research Studio
emoji: 🔐
colorFrom: gray
colorTo: indigo
sdk: gradio
sdk_version: 6.20.0
app_file: app.py
pinned: false
license: mit
short_description: Visual CPU SHA-256 Cryptanalysis Research Studio & Verifier
---

# SHA-256 Cryptanalysis Research Studio (v3.0.0)

An interactive, visual, CPU-first cryptanalysis research studio and independent verifier for SHA-256, adhering strictly to FIPS 180-4 and the non-negotiable scientific verification contract.

## Capabilities

- **Visual State Tracer**: Interactive 512-bit block padding breakdown, 64-word message schedule expansion ($W_0 \dots W_{63}$), and round-by-round state stepping ($a, b, c, d, e, f, g, h$, $T_1, T_2$, $\Sigma$, $\text{Ch}, \text{Maj}$).
- **Differential Cryptanalysis**: Bit-level difference injection ($\Delta M$) and round-by-round Hamming weight propagation analysis.
- **Independent Cryptographic Verifier**: Segregated verification boundary for preimages, collisions, and 7 hostile anti-cheating rejection tests.
- **CPU Inversion Experiments**: Automated reduced-round constraint inversion with automatic evidence logging and Independent Verifier confirmation.
- **Continuous Research (Backup & Restore)**: Export complete research state (SQLite DB, manifests, artifacts, campaign state) as a portable ZIP file, and upload previous backups to resume experiments seamlessly across sessions.

> **Scientific Finding**: *No standard full SHA-256 collision demonstrated.* Standard 64-round SHA-256 remains computationally secure and unbroken.
