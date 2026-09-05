# Security Policy

## Security Boundary & Threat Model

The SHA-256 Cryptanalysis Research Framework operates under a zero-trust model regarding self-generated cryptographic claims. 

### Threat Model & Assumptions
1. **Adversarial Coding Agents**: We assume a future coding agent may attempt to alter tests, modify initial vectors, change round constants, or weaken verifiers to create a false appearance of cryptographic success.
2. **Strict Verification Segregation**: The independent verifier (`sha-verifier`) is logically and operationally isolated from the search paths (SAT, SMT, ML, GPU search).
3. **Immutability of Evidence**: All evidence manifests record immutable SHA-256 hashes of experimental outputs. Any post-hoc modification to results triggers an immediate tamper alarm.
4. **Credential Safety**: No tokens, API keys, private keys, or passwords may ever be stored or committed to the repository.

## Protected Paths (Strict Review Required)
The following paths are designated as security-critical and protected under `.github/CODEOWNERS`:
- `.github/workflows/*`
- `.github/CODEOWNERS`
- `SECURITY.md`
- `verifier/*`
- `src/verifier/*`
- `tests/adversarial/*`
- `evidence/*`
- `schemas/*`
- `reproducibility/*`

## Reporting a Security Vulnerability
If you discover a vulnerability or integrity bypass, please open a private GitHub Security Advisory or report directly to the repository maintainers.
