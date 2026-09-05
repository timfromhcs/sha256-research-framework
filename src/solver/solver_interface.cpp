#include "sha256_research/solver/solver_interface.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <regex>
#include <atomic>
#include <thread>
#include <cctype>

namespace sha256_research {

namespace {

// Binary-name allowlist to prevent shell injection via solver names.
bool is_safe_token(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (char c : s) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.' || c == '5')) return false;
    }
    return true;
}

std::string quote_for_cmd(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else out += c;
    }
    out += "\"";
    return out;
}

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
    for (char& c : s) {
        if (c == '\\') c = '/';
    }
    return s;
}

std::string read_file_truncated(const std::string& path, size_t max_bytes = 1 << 20) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    std::ostringstream ss;
    char buf[8192];
    size_t total = 0;
    while (f && total < max_bytes) {
        f.read(buf, sizeof(buf));
        std::streamsize n = f.gcount();
        if (n <= 0) break;
        size_t take = static_cast<size_t>(n);
        if (total + take > max_bytes) take = max_bytes - total;
        ss.write(buf, static_cast<std::streamsize>(take));
        total += take;
    }
    return ss.str();
}

struct ProcessOutput {
    int exit_code{-1};
    std::string stdout_str;
    std::string stderr_str;
    double duration_sec{0.0};
};

// Unique per-run workspace: temp/sha256_solver_<time>_<tid>_<ctr>
std::filesystem::path make_unique_workdir(const std::string& tag) {
    static std::atomic<uint64_t> ctr{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::ostringstream oss;
    oss << "sha256_solver_" << tag << "_" << ms << "_"
        << std::this_thread::get_id() << "_" << ctr.fetch_add(1);
    auto dir = std::filesystem::temp_directory_path() / oss.str();
    std::filesystem::create_directories(dir);
    return dir;
}

ProcessOutput run_command_capture(const std::string& cmd,
                                  const std::filesystem::path& workdir) {
    ProcessOutput out;
    auto t0 = std::chrono::steady_clock::now();

    // Separate stdout/stderr files inside the unique workspace (no shared
    // fixed filenames, no merged streams).
    std::filesystem::path out_path = workdir / "stdout.txt";
    std::filesystem::path err_path = workdir / "stderr.txt";
    std::string full_cmd = cmd + " > " + quote_for_cmd(out_path.string()) +
                           " 2> " + quote_for_cmd(err_path.string());

    out.exit_code = std::system(full_cmd.c_str());

    auto t1 = std::chrono::steady_clock::now();
    std::chrono::duration<double> diff = t1 - t0;
    out.duration_sec = diff.count();

    out.stdout_str = read_file_truncated(out_path.string());
    out.stderr_str = read_file_truncated(err_path.string());
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
        if (!is_safe_token(binary_)) return false;
        auto workdir = make_unique_workdir("probe");
        std::string cmd;
        if (run_via_wsl_) {
            cmd = "wsl -d Ubuntu-22.04 -e which " + binary_;
        } else {
            cmd = "where " + quote_for_cmd(binary_);
        }
        auto out = run_command_capture(cmd, workdir);
        std::error_code ec;
        std::filesystem::remove_all(workdir, ec);
        return (out.exit_code == 0 && !out.stdout_str.empty());
    }

    std::string version_string() const {
        if (!is_safe_token(binary_)) return {};
        auto workdir = make_unique_workdir("version");
        std::string cmd;
        if (run_via_wsl_) {
            // Best effort: most SAT solvers print version with --version.
            cmd = "wsl -d Ubuntu-22.04 -e " + binary_ + " --version";
        } else {
            cmd = quote_for_cmd(binary_) + " --version";
        }
        auto out = run_command_capture(cmd, workdir);
        std::error_code ec;
        std::filesystem::remove_all(workdir, ec);
        std::string v = !out.stdout_str.empty() ? out.stdout_str : out.stderr_str;
        // Keep first non-empty line, truncated.
        std::istringstream iss(v);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty() && line.find_first_not_of(" \t\r\n") != std::string::npos) {
                if (line.size() > 256) line.resize(256);
                return line;
            }
        }
        return {};
    }

    SolverResult solve_cnf(const CnfFormula& cnf, uint32_t timeout_seconds) override {
        SolverResult res;
        if (!is_safe_token(binary_)) {
            res.status = SolverStatus::Error;
            return res;
        }
        if (timeout_seconds == 0) timeout_seconds = 60;
        // Cap unreasonable timeouts at 1h to bound resource usage.
        if (timeout_seconds > 3600) timeout_seconds = 3600;

        auto workdir = make_unique_workdir(name_);
        res.stats.work_dir = workdir.string();
        std::filesystem::path cnf_path = workdir / "problem.cnf";

        if (!cnf.write_dimacs_file(cnf_path.string())) {
            res.status = SolverStatus::Error;
            return res;
        }

        std::string cmd;
        if (run_via_wsl_) {
            std::string wsl_cnf = to_wsl_path(cnf_path.string());
            cmd = "wsl -d Ubuntu-22.04 -e timeout " + std::to_string(timeout_seconds) + " " + binary_ + " " + wsl_cnf;
        } else {
            cmd = quote_for_cmd(binary_) + " " + quote_for_cmd(cnf_path.string());
        }
        res.stats.command_line = cmd;
        res.stats.solver_version = version_string();

        auto proc = run_command_capture(cmd, workdir);

        res.stats.wall_time_seconds = proc.duration_sec;
        res.stats.exit_code = proc.exit_code;
        res.stats.raw_stdout = proc.stdout_str;
        res.stats.raw_stderr = proc.stderr_str;

        // In standard SAT competition convention:
        // Exit code 10 = SAT, Exit code 20 = UNSAT, 124 = timeout
        if (proc.exit_code == 124) {
            res.status = SolverStatus::Timeout;
        } else {
            // Parse both streams: version banners often go to stderr.
            parse_dimacs_output(proc.stdout_str, res);
            if (res.status == SolverStatus::Unknown && !proc.stderr_str.empty()) {
                parse_dimacs_output(proc.stderr_str, res);
            }
            if (res.status == SolverStatus::Unknown) {
                if (proc.exit_code == 10) res.status = SolverStatus::Satisfiable;
                else if (proc.exit_code == 20) res.status = SolverStatus::Unsatisfiable;
            }
        }

        // Clean unique workspace (parallel runs never share files).
        std::error_code ec;
        std::filesystem::remove_all(workdir, ec);

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
        auto workdir = make_unique_workdir("z3probe");
        auto out = run_command_capture("python -c \"import z3; print(z3.get_version_string())\"", workdir);
        std::error_code ec;
        std::filesystem::remove_all(workdir, ec);
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
