# Release Manifest Semantics & Self-Reference Protection

## 1. The Self-Referential Hash Problem

A Git commit hash is calculated by hashing the commit's header, parent commits, tree object, author/committer metadata, and commit message. The tree object in turn recursively hashes the content of all files in the repository.

Consequently, if a tracked file inside a Git commit `C` asserts:
```json
"commit_sha": "<SHA of C>"
```
a mathematical circular dependency is established:
$$\text{SHA}(C) = H(\dots, \text{Tree}(\dots, \text{File}(\dots, \text{SHA}(C) \dots) \dots))$$

Finding a value that satisfies this fixed-point equation is equivalent to finding a collision or second preimage in Git's cryptographic hash function, which is computationally intractable by design.

---

## 2. Canonical Solution & Architecture

To eliminate this inconsistency and ensure mathematically sound, deterministic, and verifiable releases, the SHA-256 Research Framework defines the following canonical semantics:

### In-Repository Manifest (`evidence/release_manifest.json`)
The in-repository release manifest is version-controlled directly within the repository. Its fields are strictly defined by `schemas/release_manifest.schema.json`:

1. **`manifest_schema_version`**: The schema specification version (`"2.0.0"`).
2. **`source_commit_sha`**: The authoritative Git commit SHA of the exact source tree that was checked out, built, tested, and benchmarked prior to packaging the release.
3. **`commit_sha`**: Retained as a backward-compatible alias identical to `source_commit_sha`.
4. **`release_commit_sha`**: Explicitly set to `null` within the committed repository to eliminate circular dependencies.
5. **`release_commit_semantics`**: Documents that `source_commit_sha` is the authoritative verified source commit.
6. **`root_evidence_hash`**: The deterministic SHA-256 Merkle root hash of all canonical experiment manifests (`evidence/experiments/**/manifest.json`), computed by `tools/generate_release_manifest.py` and enforced by `reproducibility/verify_evidence.py`.

### Standalone Release Manifest (Distribution Asset)
When publishing formal release assets (e.g., GitHub Releases or signed release tarballs), `tools/generate_release_manifest.py` can generate a post-commit distribution manifest where `release_commit_sha` is populated with the tagged release commit hash after `git commit` and `git tag` have finalized.

---

## 3. Verification & Enforcement

The integrity of `evidence/release_manifest.json` is continuously enforced in:
- **Local Verification**: `python reproducibility/verify_evidence.py`
- **Manifest Audit Utility**: `python tools/generate_release_manifest.py --verify`
- **GitHub Actions CI**: `Evidence Integrity & Anti-Tamper` (`.github/workflows/ci-evidence.yml`)
- **JSON Schema Gate**: `Security & Anti-Cheating Controls` (`.github/workflows/ci-security.yml`)
