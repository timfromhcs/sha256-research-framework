# Independent Verification Architecture

## Separation of Concerns
The `IndependentVerifier` class is logically and physically separated from candidate search and solver logic:
- The search engines and SAT solvers do not have permission to mark an experiment outcome as "Confirmed".
- Every candidate is serialized to raw byte blocks and independently re-evaluated using the golden scalar reference implementation (`Sha256Scalar`).
- Trivial cases (e.g. $M_A == M_B$) are explicitly caught and rejected.
- Candidates with custom IVs or modified constants are classified as `SemiFreeStartCollision` (the `ModifiedIvCollision` enum value is reserved for finer future distinction) rather than `StandardFullCollision`.

## Negative Test Integrity Gate
The verifier includes a self-testing negative suite that validates rejection behavior against:
1. Identical candidate messages ($M_A == M_B$).
2. Arbitrary non-colliding messages.
3. Custom-IV candidates masquerading as full collisions.

Any failure in the negative test suite halts the build and test pipeline.
