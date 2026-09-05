# Cryptographic Terminology & Classification Standards

To maintain non-negotiable scientific integrity, the following definitions are enforced across the entire framework:

## Standard Full SHA-256 Collision
A pair of messages $(M_A, M_B)$ constitutes a Standard Full SHA-256 Collision if and only if:
1. $M_A \neq M_B$
2. $\text{SHA256}(M_A) == \text{SHA256}(M_B)$
3. The evaluation uses standard 64 rounds.
4. The evaluation uses the standard NIST Initial Vector (IV).
5. The evaluation uses standard round constants $K[0..63]$ and standard FIPS 180-4 padding.

## Reduced-Round Collision
A pair of messages $(M_A, M_B)$ where $M_A \neq M_B$ and $\text{compress}(IV, M_A, R) == \text{compress}(IV, M_B, R)$ for $R < 64$ rounds with standard IV. **Must never be labelled as a full collision.**

## Semi-Free-Start Collision
A pair of messages $(M_A, M_B)$ where $M_A \neq M_B$ and $\text{compress}(IV', M_A, R) == \text{compress}(IV', M_B, R)$ where the initial state $IV'$ is arbitrary or chosen by the adversary rather than the standard NIST IV.

## Near-Collision
A pair of messages $(M_A, M_B)$ where $M_A \neq M_B$ and the Hamming distance between their digests $HD(\text{SHA256}(M_A), \text{SHA256}(M_B)) \le \epsilon$ for some small threshold $\epsilon \ll 256$.

## Differential Trail / Characteristic
A sequence of differences $(\Delta W_t, \Delta A_t, \Delta E_t)$ across rounds describing how input differences propagate through the step functions with a specific estimated probability.

## Solver Model
A satisfying assignment to a SAT/SMT formula which may or may not satisfy all physical padding and message length requirements until independently reconstructed and checked.
