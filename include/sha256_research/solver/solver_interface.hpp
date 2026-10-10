#pragma once

#include "sha256_research/sat/sat_encoder.hpp"
#include <string>
#include <map>
#include <optional>
#include <chrono>

namespace sha256_research {

enum class SolverType {
    CaDiCaL,
    Kissat,
    CryptoMiniSat,
    MiniSat,
    Z3_SMT
};

enum class SolverStatus {
    Satisfiable,
    Unsatisfiable,
    Timeout,
    Error,
    Unknown
};

// Stable string form, so the result contract carries an unambiguous label and
// "the solver gave up" is never conflated with "no solution exists".
inline const char* to_string(SolverStatus s) noexcept {
    switch (s) {
        case SolverStatus::Satisfiable: return "SAT";
        case SolverStatus::Unsatisfiable: return "UNSAT";
        case SolverStatus::Timeout: return "TIMEOUT";
        case SolverStatus::Error: return "ERROR";
        case SolverStatus::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

struct SolverStatistics {
    SolverStatus status{SolverStatus::Unknown};
    double wall_time_seconds{0.0};
    uint64_t conflicts{0};
    uint64_t decisions{0};
    uint64_t propagations{0};
    uint64_t restarts{0};
    int exit_code{0};
    std::string raw_stdout;
    std::string raw_stderr;
    // Reproducibility / isolation metadata (Phase 7 + Phase 10)
    std::string solver_version;   // best-effort captured version string
    std::string command_line;     // exact command executed (quoted)
    std::string work_dir;         // unique per-run workspace that was used
    size_t assumptions_applied{0}; // how many cube literals pinned this call
};

struct SolverResult {
    SolverStatus status{SolverStatus::Unknown};
    SolverStatistics stats;
    std::map<int, bool> model; // variable -> boolean value

    bool is_sat() const noexcept { return status == SolverStatus::Satisfiable; }
};

class ISolver {
public:
    virtual ~ISolver() = default;
    virtual std::string name() const = 0;
    virtual bool is_available() const = 0;

    virtual SolverResult solve_cnf(
        const CnfFormula& cnf,
        uint32_t timeout_seconds = 60
    ) = 0;

    // Solve the formula under temporary assumptions.
    //
    // This is the primitive behind Cube-and-Conquer: partitioning the search
    // space into disjoint cubes and solving F AND A_i independently. Default
    // implementation pins each assumption as a unit clause, which is exactly
    // equivalent and works with any solver that reads DIMACS.
    //
    // Assumptions are NOT added to `cnf`; they restrict only this call.
    virtual SolverResult solve_under_assumptions(
        const CnfFormula& cnf,
        const std::vector<int>& assumptions,
        uint32_t timeout_seconds = 60
    );
};

// Deterministic partitioning of the search space into cubes over a set of
// chosen coordinates. Cubes are disjoint and their union covers every
// assignment, so exhausting them with UNSAT results is a genuine proof that
// no preimage exists for the given round count and target.
class CubePartition {
public:
    // `coordinates` are the literals whose values define a cube. Cube i fixes
    // coordinate j to bit (i >> j) & 1.
    static std::vector<std::vector<int>> enumerate(
        const std::vector<int>& coordinates,
        uint32_t max_cubes);

    // Unit literals that pin `coordinates` to the pattern of cube index `cube`.
    static std::vector<int> literals_for(
        const std::vector<int>& coordinates,
        uint64_t cube);

    // Clause excluding one cube: the disjunction of the negated literals.
    // Adding this to the master formula prunes that cube permanently.
    static std::vector<int> blocking_clause(
        const std::vector<int>& coordinates,
        uint64_t cube);
};

class SolverFactory {
public:
    static std::unique_ptr<ISolver> create(SolverType type);
    static std::vector<SolverType> get_available_solvers();
    static std::string solver_name(SolverType type);
};

} // namespace sha256_research
