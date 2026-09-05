# Cryptanalysis Research Methodology

## Scientific Principles
1. **Falsifiable Hypotheses**: Every experiment originates from a concrete hypothesis stating clear falsification conditions.
2. **Progressive Round Analysis**: Research starts with verifiable small-round baselines ($R \in [1..16]$), establishing exact solving profiles, before expanding to higher round boundaries.
3. **Multi-Model Representation**: Cryptographic constraints are analyzed through complementary mathematical representations:
   - Boolean SAT formulas (Tseitin encoding)
   - SMT BitVector expressions
   - Differential characteristics with carry propagation conditions
4. **Independent Certification**: Search processes are strictly decoupled from verification. No search algorithm certifies its own output.
5. **Preservation of Negative Results**: Inconclusive runs and timeouts are preserved as first-class scientific data to guide future heuristic pruning and bounds estimation.

## Order of Investigation
1. Verification of round model and step function correctness against FIPS 180-4.
2. Reduced-round preimage solving ($R = 1..16$).
3. Message schedule constraint solving and degree of freedom analysis.
4. Modular addition carry tracking and differential trail evaluation.
5. Machine learning guidance for trail candidate prioritization.
