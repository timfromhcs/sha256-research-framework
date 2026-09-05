# Machine Learning Search Guidance Architecture

## Philosophy & Integrity Guardrails
1. **No Fake Direct Inversion**: Machine learning is never used to pretend to directly invert a cryptographic hash function via a black-box forward pass.
2. **Search Guidance**: ML models are strictly applied to meta-search tasks:
   - Ranking candidate differential trails by predicted propagation survivability.
   - Branching heuristic prioritization for SAT solvers.
   - Parameter selection for solver search strategies.
3. **Strict Validation Barrier**: An ML model is forbidden from certifying or claiming a collision; every candidate output must pass through `IndependentVerifier`.

## Neural Ranker Architecture
Implemented in `tools/train.py`:
- **Model**: `TrailRanker` (Deep MLP with Layer Normalization and Dropout).
- **Input Features (16 dimensions)**:
  - Active bit distributions per round step
  - Total condition counts
  - Message word Hamming weights
  - Statistical summary moments (mean, std, max, min)
- **Loss**: Mean Squared Error (MSE) against empirical survivability scores.
- **Results**:
  - Test MSE: **15.2350** vs. Baseline linear heuristic MSE: **97.1035** (84.3% improvement).
