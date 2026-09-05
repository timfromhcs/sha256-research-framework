# Pluggable Solver Architecture

## Solvers Integrated
| Solver | Version | Type | Key Features |
| :--- | :--- | :--- | :--- |
| **CaDiCaL** | 3.0.1 | CDCL SAT | Incremental solving, inprocessing, highly optimized for cryptographic instances |
| **Kissat** | 4.0.4 | CDCL SAT | Winner of SAT Competition, highly efficient restart and clause database reduction |
| **CryptoMiniSat** | 5.8.0 | CDCL + XOR | Native Gaussian elimination on XOR clauses, ideal for linear message schedule constraints |
| **MiniSat** | 2.2.1 | CDCL SAT | Baseline classical SAT reference |
| **Z3** | 4.16.0 | SMT / BitVectors | Expressive theory of bitvectors (`_ BitVec 32`), array theory, nonlinear constraints |

## Solver Abstraction Interface (`ISolver`)
All solvers adhere to a uniform C++ virtual interface:
```cpp
class ISolver {
public:
    virtual ~ISolver() = default;
    virtual std::string name() const = 0;
    virtual bool is_available() const = 0;
    virtual SolverResult solve_cnf(const CnfFormula& cnf, uint32_t timeout_seconds = 60) = 0;
};
```

## Performance on Reduced-Round Preimages
Historical example measurements on the reference machine (AMD Ryzen 7 7735HS, WSL2 solvers), not guarantees — rerun `sha-research experiment run [rounds] [solver]` to reproduce on your hardware:
- **8 Rounds**: Solved in 0.179s by CaDiCaL (8,832 variables, 35,520 clauses).
- **10 Rounds**: Solved in 0.130s by Kissat (10,596 variables, 43,338 clauses).
Solvers are optional and environment-dependent: when no solver is installed, SAT-dependent tests skip gracefully and experiments report unavailability instead of fabricating results.
