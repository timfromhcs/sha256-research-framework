#include "sha256_research/solver/solver_interface.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <regex>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace sha256_research {

namespace {

std::string to_wsl_path(const std::string& win_path) {
    std::filesystem::path p = std::filesystem::absolute(win_path);
    std::string s = p.string();
    // Replace C: with /mnt/c
    if (s.size() >= 2 && s[1] == ':') {
        char drive = static_cast<char>(std::tolower(static_cast<unsigned char>(s[0])));
        std::string rest = s.substr(2);
        for (char& c : rest) {
            if (c == '\\') c = '/';
        }
        return "/mnt/" + std::string(1, drive) + rest;
    }
    return s;
}

struct ProcessOutput {
    int exit_code{-1};
    std::string stdout_str;
    std::string stderr_str;
    double duration_sec{0.0};
};

ProcessOutput run_command_capture(const std::string& cmd) {
    ProcessOutput out;
    auto t0 = std::chrono::steady_clock::now();

    // Direct system call redirecting to temp file
    std::string tmp_out = (std::filesystem::temp_directory_path() / "sha_proc_out.txt").string();
    std::string full_cmd = cmd + " > \"" + tmp_out + "\" 2>&1";

    out.exit_code = std::system(full_cmd.c_str());

    auto t1 = std::chrono::steady_clock::now();
    std::chrono::duration<double> diff = t1 - t0;
    out.duration_sec = diff.count();

    std::ifstream f(tmp_out);
    if (f.is_open()) {
        std::stringstream buffer;
        buffer << f.rdbuf();
        out.stdout_str = buffer.str();
        f.close();
        std::filesystem::remove(tmp_out);
    }
    return out;
}

void parse_dimacs_output(const std::string& text, SolverResult& res) {
    std::istringstream iss(text);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        if (line[0] == 's') {
            if (line.find("SATISFIABLE") != std::string::npos && line.find("UNSATISFIABLE") == std::string::npos) {
                res.status = SolverStatus::Satisfiable;
            } else if (line.find("UNSATISFIABLE") != std::string::npos) {
                res.status = SolverStatus::Unsatisfiable;
            }
        } else if (line[0] == 'v') {
            std::istringstream liss(line.substr(1));
            int lit;
            while (liss >> lit) {
                if (lit == 0) break;
                if (lit > 0) {
                    res.model[lit] = true;
                } else {
                    res.model[-lit] = false;
                }
            }
        } else if (line[0] == 'c') {
            // Check for statistics
            if (line.find("conflicts:") != std::string::npos || line.find("conflicts") != std::string::npos) {
                std::smatch m;
                std::regex re(R"(\b(\d+)\s+conflicts\b)");
                if (std::regex_search(line, m, re)) {
                    res.stats.conflicts = std::stoull(m[1].str());
                }
            }
            if (line.find("decisions:") != std::string::npos || line.find("decisions") != std::string::npos) {
                std::smatch m;
                std::regex re(R"(\b(\d+)\s+decisions\b)");
                if (std::regex_search(line, m, re)) {
                    res.stats.decisions = std::stoull(m[1].str());
                }
            }
        }
    }

    if (res.status == SolverStatus::Unknown) {
        if (!res.model.empty()) {
            res.status = SolverStatus::Satisfiable;
        }
    }
}

} // namespace

class GenericSatSolver : public ISolver {
public:
    GenericSatSolver(std::string name, std::string binary, bool run_via_wsl)
        : name_(std::move(name)), binary_(std::move(binary)), run_via_wsl_(run_via_wsl) {}

    std::string name() const override { return name_; }

    bool is_available() const override {
        std::string cmd;
        if (run_via_wsl_) {
            cmd = "wsl -d Ubuntu-22.04 -e which " + binary_;
        } else {
            cmd = "where " + binary_;
        }
        auto out = run_command_capture(cmd);
        return (out.exit_code == 0 && !out.stdout_str.empty());
    }

    SolverResult solve_cnf(const CnfFormula& cnf, uint32_t timeout_seconds) override {
        SolverResult res;
        std::string cnf_path = (std::filesystem::temp_directory_path() / ("sha_" + name_ + ".cnf")).string();

        if (!cnf.write_dimacs_file(cnf_path)) {
            res.status = SolverStatus::Error;
            return res;
        }

        std::string cmd;
        if (run_via_wsl_) {
            std::string wsl_cnf = to_wsl_path(cnf_path);
            cmd = "wsl -d Ubuntu-22.04 -e timeout " + std::to_string(timeout_seconds) + " " + binary_ + " " + wsl_cnf;
        } else {
            cmd = binary_ + " " + cnf_path;
        }

        auto proc = run_command_capture(cmd);
        std::filesystem::remove(cnf_path);

        res.stats.wall_time_seconds = proc.duration_sec;
        res.stats.exit_code = proc.exit_code;
        res.stats.raw_stdout = proc.stdout_str;

        // In standard SAT competition convention:
        // Exit code 10 = SAT, Exit code 20 = UNSAT, 124 = timeout
        if (proc.exit_code == 124) {
            res.status = SolverStatus::Timeout;
        } else {
            parse_dimacs_output(proc.stdout_str, res);
            if (res.status == SolverStatus::Unknown) {
                if (proc.exit_code == 10) res.status = SolverStatus::Satisfiable;
                else if (proc.exit_code == 20) res.status = SolverStatus::Unsatisfiable;
            }
        }

        res.stats.status = res.status;
        return res;
    }

private:
    std::string name_;
    std::string binary_;
    bool run_via_wsl_{false};
};

class Z3SmtSolver : public ISolver {
public:
    std::string name() const override { return "Z3-SMT"; }

    bool is_available() const override {
        auto out = run_command_capture("python -c \"import z3; print(z3.get_version_string())\"");
        return out.exit_code == 0;
    }

    SolverResult solve_cnf(const CnfFormula& cnf, uint32_t timeout_seconds) override {
        // Can solve CNF via Z3 CLI or CaDiCaL
        GenericSatSolver z3_cli("Z3", "z3", true);
        return z3_cli.solve_cnf(cnf, timeout_seconds);
    }
};

std::unique_ptr<ISolver> SolverFactory::create(SolverType type) {
    switch (type) {
        case SolverType::CaDiCaL:
            return std::make_unique<GenericSatSolver>("CaDiCaL", "cadical", true);
        case SolverType::Kissat:
            return std::make_unique<GenericSatSolver>("Kissat", "kissat", true);
        case SolverType::CryptoMiniSat:
            return std::make_unique<GenericSatSolver>("CryptoMiniSat", "cryptominisat5", true);
        case SolverType::MiniSat:
            return std::make_unique<GenericSatSolver>("MiniSat", "minisat", true);
        case SolverType::Z3_SMT:
            return std::make_unique<Z3SmtSolver>();
    }
    return nullptr;
}

std::string SolverFactory::solver_name(SolverType type) {
    switch (type) {
        case SolverType::CaDiCaL: return "CaDiCaL";
        case SolverType::Kissat: return "Kissat";
        case SolverType::CryptoMiniSat: return "CryptoMiniSat";
        case SolverType::MiniSat: return "MiniSat";
        case SolverType::Z3_SMT: return "Z3_SMT";
    }
    return "Unknown";
}

std::vector<SolverType> SolverFactory::get_available_solvers() {
    std::vector<SolverType> avail;
    for (auto type : {SolverType::CaDiCaL, SolverType::Kissat, SolverType::CryptoMiniSat, SolverType::MiniSat, SolverType::Z3_SMT}) {
        auto s = create(type);
        if (s && s->is_available()) {
            avail.push_back(type);
        }
    }
    return avail;
}

} // namespace sha256_research
