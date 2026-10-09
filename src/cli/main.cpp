#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/vulkan/sha256_vulkan.hpp"
#include "sha256_research/sat/sat_encoder.hpp"
#include "sha256_research/solver/solver_interface.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/benchmark/benchmark_suite.hpp"
#include "sha256_research/storage/experiment_db.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <ctime>

using namespace sha256_research;

void print_banner() {
    std::cout << "===============================================================\n"
              << "   SHA-256 Cryptanalysis & Research Framework (v2.0.0)        \n"
              << "   Target: Windows 11 / Vulkan Compute / Multicore CPU / WSL  \n"
              << "===============================================================\n";
}

void print_help() {
    std::cout << "Usage: sha-research <command> [options]\n\n"
              << "Core Commands:\n"
              << "  doctor                  Probe environment, hardware, and toolchains\n"
              << "  bootstrap               Verify/setup dependencies and solvers\n"
              << "  build                   Configure and build framework binaries\n"
              << "  test                    Execute test suite (unit, KAT, differential, verifier)\n"
              << "  benchmark               Run CPU, Vulkan, and SAT benchmark suite\n"
              << "  verify                  Verify known answer vectors and negative tests\n"
              << "  status                  Display framework status, devices, and solvers\n\n"
              << "Research & Experimentation:\n"
              << "  hypothesis list         List active and evaluated research hypotheses\n"
              << "  experiment run          Execute an automated cryptanalysis experiment\n"
              << "  experiment inspect <id> Inspect an experiment run and its verification verdict\n"
              << "  campaign start          Start autonomous research campaign\n"
              << "  campaign status         Check current campaign state\n"
              << "  campaign pause          Pause running campaign\n"
              << "  campaign resume         Resume paused campaign\n"
              << "  analyze                 Analyze solver statistics and differential characteristics\n"
              << "  train                   Train/update ML search guidance models\n"
              << "  report                  Generate comprehensive markdown reports\n";
}

int cmd_doctor() {
    std::cout << "[Doctor] Invoking environment doctor...\n";
    int ret = std::system("pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/doctor.ps1");
    return ret;
}

int cmd_bootstrap() {
    std::cout << "[Bootstrap] Running bootstrap verification...\n";
    int ret = std::system("pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1");
    return ret;
}

int cmd_test() {
    std::cout << "[Test] Running SHA-256 test suite...\n\n";

    // 1. NIST KATs
    std::cout << "-> [1/4] NIST Known-Answer Tests (KATs):\n";
    auto kats = IndependentVerifier::get_standard_test_vectors();
    bool all_kat_passed = true;
    for (const auto& kat : kats) {
        bool ok = IndependentVerifier::verify_known_answer(kat);
        std::cout << "   " << (ok ? "[PASS]" : "[FAIL]") << " " << kat.name << "\n";
        if (!ok) all_kat_passed = false;
    }

    // 2. CPU Backend Cross-Verification
    std::cout << "\n-> [2/4] CPU Reference vs. Optimized Backend Equivalence:\n";
    bool cpu_equiv = true;
    for (size_t len = 0; len <= 55; ++len) {
        std::vector<uint8_t> test_msg(len);
        for (size_t i = 0; i < len; ++i) test_msg[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        Sha256Digest d1 = Sha256Scalar::hash(test_msg.data(), len);
        Sha256Digest d2 = Sha256Optimized::hash(test_msg.data(), len);
        if (d1 != d2) {
            std::cout << "   [FAIL] Mismatch at message length " << len << "\n";
            cpu_equiv = false;
            break;
        }
    }
    if (cpu_equiv) {
        std::cout << "   [PASS] Exact equivalence verified across all tested lengths.\n";
    }

    // 3. Verifier Negative Test Suite
    std::cout << "\n-> [3/4] Independent Verifier Negative Tests (Integrity Gate):\n";
    bool neg_ok = IndependentVerifier::run_negative_verifier_tests();
    std::cout << "   " << (neg_ok ? "[PASS]" : "[FAIL]") << " Corrupted/trivial candidate rejection gate.\n";

    // 4. Vulkan Compute Test
    std::cout << "\n-> [4/4] Vulkan Compute Pipeline & CPU Equivalence:\n";
    Sha256VulkanEngine vk;
    bool vk_ok = false;
    if (vk.initialize("shaders")) {
        auto res = vk.run_smoke_test(512, 64);
        if (res.verified_against_cpu) {
            std::cout << "   [PASS] 512 GPU hashes verified exactly against CPU reference ("
                      << res.throughput_mhashes_sec << " MH/s on " << res.device_name << ").\n";
            vk_ok = true;
        } else {
            std::cout << "   [FAIL] Vulkan outputs differed from CPU reference!\n";
        }
    } else {
        std::cout << "   [SKIP] Vulkan runtime not active, no compute device found, or CPU-only build.\n";
        vk_ok = true; // Not an error if platform doesn't support
    }

    bool all_passed = all_kat_passed && cpu_equiv && neg_ok && vk_ok;
    std::cout << "\nTest Suite Result: " << (all_passed ? "ALL PASSED" : "FAILED") << "\n";
    return all_passed ? 0 : 1;
}

int cmd_benchmark() {
    std::cout << "[Benchmark] Executing full performance benchmark suite...\n\n";
    auto report = BenchmarkSuite::run_full_suite();
    std::cout << report.to_markdown() << "\n";

    // Write to evidence/benchmarks/
    std::filesystem::create_directories("evidence/benchmarks");
    std::ofstream out("evidence/benchmarks/latest_benchmark.md");
    if (out.is_open()) {
        out << report.to_markdown();
    }
    std::cout << "Benchmark report saved to evidence/benchmarks/latest_benchmark.md\n";
    return 0;
}

int cmd_status() {
    std::cout << "[Status] SHA-256 Research Framework Status:\n";
    std::cout << " - CPU Features: " << Sha256Optimized::features().to_string() << "\n";

#if SHA256_HAVE_VULKAN
    {
        Sha256VulkanEngine vk;
        if (vk.initialize("shaders")) {
            auto info = vk.context().device_info();
            std::cout << " - Vulkan Compute Device: " << info.device_name
                      << " (Driver: " << info.driver_version << ", API: " << info.api_version << ")\n";
        } else {
            std::cout << " - Vulkan Compute: Not available / Not initialized\n";
        }
    }
#else
    std::cout << " - Vulkan Compute: Not compiled in (CPU-only build)\n";
#endif

    std::cout << " - SAT/SMT Solvers:\n";
    auto solvers = SolverFactory::get_available_solvers();
    for (auto s : solvers) {
        std::cout << "   * " << SolverFactory::solver_name(s) << " [Available]\n";
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Experiment options, shared by `experiment run` and the richer `preimage`
// command. The encoding dialect is a first-class, recorded choice because it
// dominates solver performance on this circuit.
// ---------------------------------------------------------------------------
static std::string dialect_name(EncodingDialect d) {
    return d == EncodingDialect::Xor ? "xor" : "tseitin";
}

int cmd_experiment_run(int rounds, const std::string& solver_str, const std::string& out_dir,
                       EncodingDialect dialect, bool carry_save, uint32_t timeout_seconds) {
    std::cout << "[Experiment] Running automated cryptanalysis experiment: " << rounds << " rounds\n";

    SolverType st = SolverType::CaDiCaL;
    if (solver_str == "kissat") st = SolverType::Kissat;
    else if (solver_str == "cryptominisat" || solver_str == "cms") st = SolverType::CryptoMiniSat;
    else if (solver_str == "minisat") st = SolverType::MiniSat;
    else if (solver_str == "z3") st = SolverType::Z3_SMT;
    else if (solver_str != "cadical") {
        std::cerr << "Error: unknown solver '" << solver_str
                  << "' (expected cadical, kissat, cryptominisat, minisat, or z3)\n";
        return 2;
    }

    if (rounds < 1 || rounds > 64) {
        std::cerr << "Error: Invalid round count " << rounds << ". Rounds must be between 1 and 64.\n";
        return 1;
    }

    // The XOR dialect emits native XOR constraints, which only an XOR-capable
    // solver can read. Reject the combination up front rather than feeding a
    // plain SAT solver a formula it will misparse.
    if (dialect == EncodingDialect::Xor && st != SolverType::CryptoMiniSat) {
        std::cerr << "Error: --encoding xor requires an XOR-capable solver; "
                     "use --solver cryptominisat.\n";
        return 2;
    }

    auto utc_now = []() {
        auto now = std::chrono::system_clock::now();
        std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::tm bt{};
#if defined(_WIN32)
        gmtime_s(&bt, &tt);
#else
        gmtime_r(&tt, &bt);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &bt);
        return std::string(buf);
    };

    ExperimentStorage storage(out_dir);
    ExperimentMetadata meta;
    meta.experiment_id = ExperimentStorage::generate_experiment_id("exp_reduced");
    meta.target_rounds = static_cast<uint32_t>(rounds);
    meta.solver_name = SolverFactory::solver_name(st);
    meta.research_question = "Can SAT solvers find a valid 1-block preimage for " + std::to_string(rounds) + "-round SHA-256?";
    meta.hypothesis = "Modern CDCL solvers will efficiently invert reduced-round SHA-256 for small round counts (e.g. <= 16 rounds).";
    meta.start_time = utc_now();
    meta.deterministic_seed = 0xC0FFEE01u;
    meta.command_line = std::string("sha-research experiment run ") + std::to_string(rounds) + " " + solver_str;
    meta.configuration_json = "{\"rounds\": " + std::to_string(rounds) +
        ", \"solver\": \"" + meta.solver_name + "\""
        ", \"encoding\": \"" + dialect_name(dialect) + "\""
        ", \"carry_save_t1\": " + (carry_save ? "true" : "false") +
        ", \"seed\": 3235824897}";

    std::string exp_dir = storage.create_experiment_run(meta);
    std::cout << "   Created experiment run: " << meta.experiment_id << " in " << exp_dir << "\n";

    // Formulate SAT problem: Find preimage of standard test message under R rounds
    std::vector<uint8_t> known_msg = {'T', 'E', 'S', 'T', '1', '2', '3', '4'};
    known_msg.resize(64, 0);
    Sha256State target_state = SHA256_IV;
    Sha256Scalar::compress_block(target_state, known_msg.data(), rounds);

    Sha256Digest target_digest;
    for (size_t i = 0; i < 8; ++i) store_be32(target_digest.bytes.data() + i * 4, target_state[i]);

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;
    cfg.fix_target_digest = true;
    cfg.target_digest = target_digest;
    cfg.dialect = dialect;
    cfg.carry_save_t1 = carry_save;

    std::cout << "   Encoding " << rounds << "-round SHA-256 constraints to CNF ("
              << dialect_name(dialect) << (carry_save ? ", carry-save" : "") << ")...\n";

    auto encode_t0 = std::chrono::steady_clock::now();
    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    auto encode_t1 = std::chrono::steady_clock::now();
    const double encode_seconds =
        std::chrono::duration<double>(encode_t1 - encode_t0).count();

    std::cout << "   Generated CNF: " << enc.cnf.num_vars << " variables, "
              << enc.cnf.clauses.size() << " clauses, "
              << enc.cnf.xor_constraints.size() << " XOR constraints ("
              << encode_seconds << " s).\n";

    auto solver = SolverFactory::create(st);
    if (!solver || !solver->is_available()) {
        std::cout << "   Error: Solver " << meta.solver_name << " is not available.\n";
        return 1;
    }

    std::cout << "   Invoking solver " << meta.solver_name << "...\n";
    auto sol_res = solver->solve_cnf(enc.cnf, timeout_seconds);
    meta.solver_version = sol_res.stats.solver_version;
    if (!sol_res.stats.command_line.empty()) {
        meta.command_line += std::string(" | solver_cmd: ") + sol_res.stats.command_line;
    }
    std::cout << "   Solver status: " << (sol_res.is_sat() ? "SAT" : "UNSAT/TIMEOUT")
              << " in " << sol_res.stats.wall_time_seconds << " seconds.\n";

    VerificationVerdict verdict;
    std::vector<ArtifactRecord> artifacts;

    // Persist CNF as a hashed evidence artifact.
    {
        std::filesystem::create_directories(std::filesystem::path(exp_dir) / "artifacts");
        std::string cnf_artifact = (std::filesystem::path(exp_dir) / "artifacts" / "problem.cnf").string();
        if (enc.cnf.write_dimacs_file(cnf_artifact)) {
            ArtifactRecord rec;
            rec.relative_path = "artifacts/problem.cnf";
            rec.sha256_hash = ExperimentStorage::hash_file(cnf_artifact);
            std::error_code ec;
            rec.size_bytes = std::filesystem::file_size(cnf_artifact, ec);
            rec.description = "SAT CNF for reduced-round preimage";
            artifacts.push_back(rec);
        }
        std::string log_path = (std::filesystem::path(exp_dir) / "artifacts" / "solver_stdout.txt").string();
        std::ofstream lf(log_path);
        if (lf.is_open()) {
            lf << sol_res.stats.raw_stdout;
            lf.close();
            ArtifactRecord rec;
            rec.relative_path = "artifacts/solver_stdout.txt";
            rec.sha256_hash = ExperimentStorage::hash_file(log_path);
            std::error_code ec;
            rec.size_bytes = std::filesystem::file_size(log_path, ec);
            rec.description = "Solver stdout capture";
            artifacts.push_back(rec);
        }
    }

    if (sol_res.is_sat()) {
        auto msg_words = SatEncoder::extract_message_from_model(sol_res.model, enc.message_vars);
        std::vector<uint8_t> cand_block(64);
        for (size_t i = 0; i < 16; ++i) {
            store_be32(cand_block.data() + i * 4, msg_words[i]);
        }

        std::string cand_path = (std::filesystem::path(exp_dir) / "artifacts" / "candidate_block.bin").string();
        {
            std::ofstream cf(cand_path, std::ios::binary);
            if (cf.is_open()) {
                cf.write(reinterpret_cast<const char*>(cand_block.data()), static_cast<std::streamsize>(cand_block.size()));
                cf.close();
                ArtifactRecord rec;
                rec.relative_path = "artifacts/candidate_block.bin";
                rec.sha256_hash = ExperimentStorage::hash_file(cand_path);
                rec.size_bytes = cand_block.size();
                rec.description = "Reconstructed candidate message block";
                artifacts.push_back(rec);
            }
        }

        // Strictly verify candidate via IndependentVerifier
        PreimageCandidate cand;
        cand.message = cand_block;
        cand.target_digest = target_digest;
        cand.claimed_rounds = static_cast<uint32_t>(rounds);
        cand.iv = SHA256_IV;
        cand.custom_iv = false;
        cand.generator_metadata = "{\"solver\": \"" + meta.solver_name + "\"}";

        verdict = IndependentVerifier::verify_preimage_candidate(cand);

        if (verdict.is_valid) {
            meta.outcome_success = true;
            meta.classification = to_string(verdict.classification);
            meta.conclusion = "Successfully found valid message block producing target digest for " + std::to_string(rounds) + " rounds. Verified via IndependentVerifier.";
            std::cout << "   [VERIFIED via IndependentVerifier] Candidate matches target digest! Classification: " << meta.classification << "\n";
        } else {
            meta.outcome_success = false;
            meta.classification = "ModelExtractionMismatch";
            meta.conclusion = "Solver claimed SAT but candidate failed independent verification: " + verdict.failure_reason;
            std::cout << "   [REJECTED via IndependentVerifier] Candidate failed verification: " << verdict.failure_reason << "\n";
        }

        // Machine-readable result contract consumed by the Python platform.
        // The worker pool must never infer success from prose or exit codes;
        // it reads these two lines and then re-verifies independently.
        std::string cand_abs = std::filesystem::absolute(cand_path).string();
        for (char& ch : cand_abs) if (ch == '\\') ch = '/';
        std::cout << "RESULT_CANDIDATE=" << cand_abs << "\n";
        std::cout << "RESULT_TARGET_DIGEST=" << target_digest.to_hex() << "\n";
        std::cout << "RESULT_ROUNDS=" << rounds << "\n";
        std::cout << "RESULT_CLASSIFICATION=" << meta.classification << "\n";
        std::cout << "RESULT_CNF_VARS=" << enc.cnf.num_vars << "\n";
        std::cout << "RESULT_CNF_CLAUSES=" << enc.cnf.clauses.size() << "\n";
        std::cout << "RESULT_CNF_XORS=" << enc.cnf.xor_constraints.size() << "\n";
        std::cout << "RESULT_ENCODING=" << dialect_name(dialect) << "\n";
        std::cout << "RESULT_CARRY_SAVE=" << (carry_save ? 1 : 0) << "\n";
        std::cout << "RESULT_ENCODE_TIME=" << encode_seconds << "\n";
        std::cout << "RESULT_SOLVER_TIME=" << sol_res.stats.wall_time_seconds << "\n";
        std::cout << "RESULT_SOLVER_STATUS=" << sha256_research::to_string(sol_res.status) << "\n";
        std::cout << "RESULT_SOLVER_EXIT=" << sol_res.stats.exit_code << "\n";
        std::cout.flush();
        meta.end_time = utc_now();
        storage.finalize_experiment(meta.experiment_id, meta, artifacts, verdict);
        std::cout << "   Experiment finalized: " << meta.experiment_id << "\n";
        return verdict.is_valid ? 0 : 2;
    } else {
        meta.outcome_success = false;
        meta.classification = "NoSolutionFound";
        meta.conclusion = "Solver did not find solution within timeout.";
    }

    // No candidate was produced. State so explicitly and unambiguously so the
    // caller records a negative result instead of hunting for a candidate.
    std::cout << "RESULT_CANDIDATE=NONE\n";
    std::cout << "RESULT_TARGET_DIGEST=" << target_digest.to_hex() << "\n";
    std::cout << "RESULT_ROUNDS=" << rounds << "\n";
    std::cout << "RESULT_CLASSIFICATION=" << meta.classification << "\n";
    std::cout << "RESULT_CNF_VARS=" << enc.cnf.num_vars << "\n";
        std::cout << "RESULT_CNF_CLAUSES=" << enc.cnf.clauses.size() << "\n";
        std::cout << "RESULT_CNF_XORS=" << enc.cnf.xor_constraints.size() << "\n";
        std::cout << "RESULT_ENCODING=" << dialect_name(dialect) << "\n";
        std::cout << "RESULT_CARRY_SAVE=" << (carry_save ? 1 : 0) << "\n";
        std::cout << "RESULT_ENCODE_TIME=" << encode_seconds << "\n";
    std::cout << "RESULT_SOLVER_TIME=" << sol_res.stats.wall_time_seconds << "\n";
        std::cout << "RESULT_SOLVER_STATUS=" << sha256_research::to_string(sol_res.status) << "\n";
        std::cout << "RESULT_SOLVER_EXIT=" << sol_res.stats.exit_code << "\n";
    std::cout.flush();

    meta.end_time = utc_now();
    storage.finalize_experiment(meta.experiment_id, meta, artifacts, verdict);
    std::cout << "   Experiment finalized: " << meta.experiment_id << "\n";
    return 1;
}

struct ExperimentOptions {
    uint32_t rounds{8};
    std::string solver_str{"cadical"};
    std::string out_dir{"evidence"};
    EncodingDialect dialect{EncodingDialect::Tseitin};
    bool carry_save{false};
    uint32_t timeout{60};
};

// `sha-research preimage --rounds N [--solver S] [--encoding xor|tseitin]
//                         [--carry-save] [--timeout T] [--out DIR]`
//
// Emits the full machine-readable result contract on stdout, including the
// encoding metrics the autonomous loop needs to make escalation decisions.
int cmd_preimage(const std::vector<std::string>& args) {
    ExperimentOptions opt;

    auto need_value = [&](size_t& i, const char* name) -> std::string {
        if (i + 1 >= args.size()) {
            throw std::invalid_argument(std::string("missing value for ") + name);
        }
        return args[++i];
    };

    try {
        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& a = args[i];
            if (a == "--rounds") {
                opt.rounds = static_cast<uint32_t>(std::stoul(need_value(i, "--rounds")));
            } else if (a == "--solver") {
                opt.solver_str = need_value(i, "--solver");
            } else if (a == "--out") {
                opt.out_dir = need_value(i, "--out");
            } else if (a == "--timeout") {
                opt.timeout = static_cast<uint32_t>(std::stoul(need_value(i, "--timeout")));
            } else if (a == "--encoding") {
                const std::string enc = need_value(i, "--encoding");
                if (enc == "xor") {
                    opt.dialect = EncodingDialect::Xor;
                } else if (enc == "tseitin") {
                    opt.dialect = EncodingDialect::Tseitin;
                } else {
                    throw std::invalid_argument(
                        "unknown --encoding '" + enc + "' (expected 'xor' or 'tseitin')");
                }
            } else if (a == "--carry-save") {
                opt.carry_save = true;
            } else {
                throw std::invalid_argument("unknown option '" + a + "'");
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << "Usage: sha-research preimage --rounds N [--solver S] "
                     "[--encoding xor|tseitin] [--carry-save] [--timeout T] [--out DIR]\n";
        return 2;
    }

    return cmd_experiment_run(static_cast<int>(opt.rounds), opt.solver_str, opt.out_dir,
                              opt.dialect, opt.carry_save, opt.timeout);
}

struct CampaignState {
    std::string campaign_id;
    std::string status{"IDLE"};
    int max_rounds{16};
    std::string solver{"cadical"};
    int timeout_sec{60};
    int highest_verified_round{0};
    int inconclusive_round{0};
    std::string start_time;
    std::string last_updated;
};

static const std::string CAMPAIGN_STATE_PATH = "evidence/campaign_state.json";

CampaignState load_campaign_state() {
    CampaignState s;
    std::ifstream f(CAMPAIGN_STATE_PATH);
    if (!f.is_open()) return s;

    std::string line;
    while (std::getline(f, line)) {
        auto get_val = [&](const std::string& key) -> std::string {
            size_t pos = line.find("\"" + key + "\"");
            if (pos == std::string::npos) return "";
            size_t colon = line.find(':', pos);
            if (colon == std::string::npos) return "";
            size_t start = line.find_first_not_of(" \t\"", colon + 1);
            size_t end = line.find_last_not_of(" \t\",\r\n");
            if (start != std::string::npos && end != std::string::npos && end >= start) {
                return line.substr(start, end - start + 1);
            }
            return "";
        };

        if (line.find("\"campaign_id\"") != std::string::npos) s.campaign_id = get_val("campaign_id");
        if (line.find("\"status\"") != std::string::npos) s.status = get_val("status");
        if (line.find("\"max_rounds\"") != std::string::npos) {
            std::string v = get_val("max_rounds");
            if (!v.empty()) s.max_rounds = std::stoi(v);
        }
        if (line.find("\"solver\"") != std::string::npos) s.solver = get_val("solver");
        if (line.find("\"highest_verified_round\"") != std::string::npos) {
            std::string v = get_val("highest_verified_round");
            if (!v.empty()) s.highest_verified_round = std::stoi(v);
        }
        if (line.find("\"inconclusive_round\"") != std::string::npos) {
            std::string v = get_val("inconclusive_round");
            if (!v.empty()) s.inconclusive_round = std::stoi(v);
        }
        if (line.find("\"start_time\"") != std::string::npos) s.start_time = get_val("start_time");
        if (line.find("\"last_updated\"") != std::string::npos) s.last_updated = get_val("last_updated");
    }
    return s;
}

void save_campaign_state(const CampaignState& s) {
    std::filesystem::create_directories("evidence");
    std::ofstream f(CAMPAIGN_STATE_PATH);
    if (!f.is_open()) return;

    f << "{\n"
      << "  \"campaign_id\": \"" << s.campaign_id << "\",\n"
      << "  \"status\": \"" << s.status << "\",\n"
      << "  \"max_rounds\": " << s.max_rounds << ",\n"
      << "  \"solver\": \"" << s.solver << "\",\n"
      << "  \"timeout_sec\": " << s.timeout_sec << ",\n"
      << "  \"highest_verified_round\": " << s.highest_verified_round << ",\n"
      << "  \"inconclusive_round\": " << s.inconclusive_round << ",\n"
      << "  \"start_time\": \"" << s.start_time << "\",\n"
      << "  \"last_updated\": \"" << s.last_updated << "\"\n"
      << "}\n";
}

int cmd_campaign_status() {
    CampaignState s = load_campaign_state();
    std::cout << "===============================================================\n"
              << "              AUTONOMOUS RESEARCH CAMPAIGN STATUS              \n"
              << "===============================================================\n";
    if (s.campaign_id.empty()) {
        std::cout << "  No active campaign state found.\n"
                  << "  To launch: sha-research campaign start [max_rounds] [solver]\n";
        return 0;
    }
    std::cout << "  Campaign ID:             " << s.campaign_id << "\n"
              << "  Status:                  " << s.status << "\n"
              << "  Target Max Rounds:       " << s.max_rounds << "\n"
              << "  Active Solver:           " << s.solver << "\n"
              << "  Highest Verified Round:  " << s.highest_verified_round << "\n"
              << "  Inconclusive Round:      " << (s.inconclusive_round > 0 ? std::to_string(s.inconclusive_round) : "None") << "\n"
              << "  Started:                 " << s.start_time << "\n"
              << "  Last Updated:            " << s.last_updated << "\n"
              << "===============================================================\n";
    return 0;
}

int cmd_campaign_pause() {
    CampaignState s = load_campaign_state();
    if (s.campaign_id.empty() || s.status != "IN_PROGRESS") {
        std::cout << "No in-progress campaign to pause.\n";
        return 0;
    }
    s.status = "PAUSED";
    save_campaign_state(s);
    std::cout << "Campaign " << s.campaign_id << " paused at round " << s.highest_verified_round << ".\n";
    return 0;
}

int cmd_campaign_start(int max_rounds, const std::string& solver_name, int start_from = 1,
                       EncodingDialect dialect = EncodingDialect::Tseitin,
                       bool carry_save = false) {
    auto utc_now = []() {
        auto now = std::chrono::system_clock::now();
        std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::tm bt{};
#if defined(_WIN32)
        gmtime_s(&bt, &tt);
#else
        gmtime_r(&tt, &bt);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &bt);
        return std::string(buf);
    };

    if (max_rounds < 1 || max_rounds > 64) {
        std::cerr << "Error: max_rounds must be between 1 and 64.\n";
        return 1;
    }

    CampaignState s = load_campaign_state();
    if (start_from == 1 || s.campaign_id.empty()) {
        s.campaign_id = ExperimentStorage::generate_experiment_id("campaign");
        s.start_time = utc_now();
        s.highest_verified_round = 0;
        s.inconclusive_round = 0;
    }
    s.status = "IN_PROGRESS";
    s.max_rounds = max_rounds;
    s.solver = solver_name;
    s.last_updated = utc_now();
    save_campaign_state(s);

    std::cout << "===============================================================\n"
              << "       STARTING AUTONOMOUS CAMPAIGN: " << s.campaign_id << "\n"
              << "       Target: Rounds " << start_from << ".." << max_rounds
              << " | Solver: " << solver_name
              << " | Encoding: " << dialect_name(dialect)
              << (carry_save ? " + carry-save" : "") << "\n"
              << "===============================================================\n";

    for (int r = start_from; r <= max_rounds; ++r) {
        std::cout << "\n[Campaign Step] Progressing to " << r << " rounds...\n";
        // Exit code 0 means the candidate was independently verified;
        // 1 means the solver produced none; 2 means it failed verification.
        int res = cmd_experiment_run(r, solver_name, "evidence", dialect, carry_save, 60);

        s.last_updated = utc_now();
        if (res == 0) {
            s.highest_verified_round = r;
            save_campaign_state(s);
            std::cout << "[Campaign Step] Round " << r << " completed & independently verified.\n";
        } else {
            s.inconclusive_round = r;
            s.status = "INCONCLUSIVE_AT_ROUND_" + std::to_string(r);
            save_campaign_state(s);
            std::cout << "[Campaign Step] Round " << r << " was inconclusive or timed out.\n"
                      << "Stopping campaign progression.\n"
                      << "Highest verified reduced-round preimage: " << s.highest_verified_round << " rounds.\n"
                      << "Scientific finding: No standard full SHA-256 collision or preimage demonstrated.\n";
            return 0;
        }
    }

    s.status = "COMPLETED";
    s.last_updated = utc_now();
    save_campaign_state(s);

    std::cout << "\n===============================================================\n"
              << "  CAMPAIGN " << s.campaign_id << " COMPLETED SUCCESSFULLY!\n"
              << "  Highest Verified Round: " << s.highest_verified_round << " / " << max_rounds << "\n"
              << "  Scientific finding: No standard full SHA-256 collision demonstrated.\n"
              << "===============================================================\n";
    return 0;
}

int cmd_campaign_resume() {
    CampaignState s = load_campaign_state();
    if (s.campaign_id.empty()) {
        std::cout << "No campaign state found to resume. Use 'campaign start'.\n";
        return 1;
    }
    int next_round = s.highest_verified_round + 1;
    if (next_round > s.max_rounds) {
        std::cout << "Campaign already completed up to max_rounds (" << s.max_rounds << ").\n";
        return 0;
    }
    std::cout << "Resuming campaign " << s.campaign_id << " from round " << next_round << "...\n";
    return cmd_campaign_start(s.max_rounds, s.solver, next_round);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        print_help();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "doctor") {
        return cmd_doctor();
    } else if (cmd == "bootstrap") {
        return cmd_bootstrap();
    } else if (cmd == "test") {
        return cmd_test();
    } else if (cmd == "benchmark") {
        return cmd_benchmark();
    } else if (cmd == "status") {
        return cmd_status();
    } else if (cmd == "verify") {
        return cmd_test();
    } else if (cmd == "hypothesis") {
        std::cout << "Active Hypotheses:\n"
                  << "  H1: SAT encoding of rounds 1..16 can find single-block preimages in < 5s.\n"
                  << "  H2: Differential trail with active W[1] MSB difference propagates through round 2.\n"
                  << "  H3: Vulkan compute throughput scales linearly with batch size up to workgroup limits.\n";
        return 0;
    } else if (cmd == "experiment") {
        if (argc >= 3 && std::string(argv[2]) == "run") {
            int rounds = 8;
            std::string solver = "cadical";
            std::string out_dir = "evidence";
            if (argc >= 4) rounds = std::stoi(argv[3]);
            if (argc >= 5) solver = argv[4];
            if (argc >= 6) out_dir = argv[5];
            return cmd_experiment_run(rounds, solver, out_dir,
                                       EncodingDialect::Tseitin, false, 60);
        } else {
            std::cout << "Usage: sha-research experiment run [rounds] [solver] [out_dir]\n"
                         "       sha-research preimage --rounds N [--solver S] "
                         "[--encoding xor|tseitin] [--carry-save] [--timeout T]\n";
            return 0;
        }
    } else if (cmd == "preimage") {
        std::vector<std::string> rest;
        for (int i = 2; i < argc; ++i) rest.emplace_back(argv[i]);
        return cmd_preimage(rest);
    } else if (cmd == "campaign") {
        if (argc >= 3) {
            std::string sub = argv[2];
            if (sub == "status") {
                return cmd_campaign_status();
            } else if (sub == "pause") {
                return cmd_campaign_pause();
            } else if (sub == "resume") {
                return cmd_campaign_resume();
            } else if (sub == "start") {
                int max_rounds = 12;
                std::string solver = "cadical";
                if (argc >= 4) max_rounds = std::stoi(argv[3]);
                if (argc >= 5) solver = argv[4];
                return cmd_campaign_start(max_rounds, solver);
            }
        }
        std::cout << "Usage: sha-research campaign <start|status|pause|resume> [max_rounds] [solver]\n";
        return 0;
    } else if (cmd == "train" || cmd == "analyze" || cmd == "report") {
        std::string py_cmd = "python tools/" + cmd + ".py";
        return std::system(py_cmd.c_str());
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        print_help();
        return 1;
    }

    return 0;
}
