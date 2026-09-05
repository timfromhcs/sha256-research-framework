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
};

class SolverFactory {
public:
    static std::unique_ptr<ISolver> create(SolverType type);
    static std::vector<SolverType> get_available_solvers();
    static std::string solver_name(SolverType type);
};

} // namespace sha256_research
