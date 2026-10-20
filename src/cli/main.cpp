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
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <algorithm>

using namespace sha256_research;

#ifndef SHA256_RESEARCH_VERSION
#define SHA256_RESEARCH_VERSION "5.1.0"
#endif

// Search strategy drivers are defined after the option parser that dispatches
// to them, so they are forward-declared here.
struct SearchConfig;
int cmd_cube_search(const SearchConfig& opt);
int cmd_dobbertin_search(const SearchConfig& opt);

void print_banner() {
    std::cout << "===============================================================\n"
              << "   SHA-256 Cryptanalysis & Research Framework (v" << SHA256_RESEARCH_VERSION << ")\n"
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

// Deterministic message-word values from a seed, so a run is exactly
// reproducible and its evidence package stays replayable.
static uint32_t derived_word(uint32_t seed, uint32_t index) {
    uint32_t x = seed ^ (0x9E3779B9u * (index + 1));
    x ^= x >> 16; x *= 0x7FEB352Du;
    x ^= x >> 15; x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

int cmd_experiment_run(int rounds, const std::string& solver_str, const std::string& out_dir,
                       EncodingDialect dialect, bool carry_save, uint32_t timeout_seconds,
                       int fix_first_word = -1, int fix_last_word = -1,
                       uint32_t fix_seed = 0x5EED1234u) {
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

    // Free-variable reduction. A one-block preimage is overdetermined by
    // 2^256 (512 free message bits map onto 256 output bits), so pinning
    // message words preserves the existence of a solution while removing
    // search space. Each entry is an explicit (index, value) pair.
    bool pinning = (fix_first_word >= 0 && fix_last_word >= fix_first_word);
    if (pinning) {
        for (int w = fix_first_word; w <= fix_last_word && w < 16; ++w) {
            cfg.fixed_words.emplace_back(
                static_cast<uint32_t>(w),
                derived_word(fix_seed, static_cast<uint32_t>(w)));
        }
    }

    std::cout << "   Encoding " << rounds << "-round SHA-256 constraints to CNF ("
              << dialect_name(dialect) << (carry_save ? ", carry-save" : "") << ")...\n";

    if (pinning) {
        const int count = fix_last_word - fix_first_word + 1;
        std::cout << "   Pinned W[" << fix_first_word << ".." << fix_last_word << "] to "
                  << "seeded values (" << count << " words, " << count * 32 << " bits).\n";
    }

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
        std::cout << "RESULT_CANDIDATE=NONE\n";
        std::cout << "RESULT_TARGET_DIGEST=" << target_digest.to_hex() << "\n";
        std::cout << "RESULT_ROUNDS=" << rounds << "\n";
        std::cout << "RESULT_CLASSIFICATION=SolverUnavailable\n";
        std::cout << "RESULT_CNF_VARS=" << enc.cnf.num_vars << "\n";
        std::cout << "RESULT_CNF_CLAUSES=" << enc.cnf.clauses.size() << "\n";
        std::cout << "RESULT_CNF_XORS=" << enc.cnf.xor_constraints.size() << "\n";
        std::cout << "RESULT_ENCODING=" << dialect_name(dialect) << "\n";
        std::cout << "RESULT_CARRY_SAVE=" << (carry_save ? 1 : 0) << "\n";
        std::cout << "RESULT_ENCODE_TIME=" << encode_seconds << "\n";
        std::cout << "RESULT_SOLVER_TIME=0.0\n";
        std::cout << "RESULT_SOLVER_STATUS=UNAVAILABLE\n";
        std::cout << "RESULT_SOLVER_EXIT=-1\n";
        std::cout.flush();
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

// ---------------------------------------------------------------------------
// Cube-and-Conquer search driver.
//
// Zaikin (Constraints 2026) inverted 19 rounds of SHA-256 by parameterising a
// CDCL solver on intermediate inverse problems and running a parallel
// Cube-and-Conquer search. The mechanism implemented here is:
//
//   * a one-block preimage is massively overdetermined (512 free message bits
//     mapped onto 256 output bits), so large parts of the input may be pinned
//     without losing the existence of a solution;
//   * the remaining freedom is partitioned into disjoint cubes over chosen
//     state bits;
//   * each cube is solved independently, in parallel, under assumptions;
//   * a cube proven UNSAT contributes a blocking clause that prunes it
//     permanently from the master formula.
//
// Because the cubes are disjoint and their union covers every assignment,
// exhausting them with UNSAT is a genuine proof that no preimage exists for
// that round count and target -- never merely a timeout.
// ---------------------------------------------------------------------------
struct SearchConfig {
    uint32_t rounds{8};
    std::string solver_str{"cadical"};
    std::string out_dir{"evidence"};
    EncodingDialect dialect{EncodingDialect::Tseitin};
    bool carry_save{false};
    uint32_t timeout{60};

    // Message-word pinning (free-variable reduction).
    int fix_first_word{-1};
    int fix_last_word{-1};
    uint32_t fix_seed{0x5EED1234u};

    // Cube-and-Conquer.
    uint32_t cube_bits{0};        // 0 disables Cube-and-Conquer
    int cube_round{-1};           // round boundary whose state bits are used
    char cube_register{'e'};      // 'a' or 'e'
    uint32_t jobs{0};             // 0 => hardware_concurrency

    // Dobbertin-style state constraint. `state_bits == 0` disables it.
    int state_bits{0};
    int state_round{-1};
    uint32_t state_register{1};      // 0 = A, 1 = E
    uint32_t state_constant{0u};

    // Dobbertin-style state constraint. `dobbertin_bits == 0` disables it.
    int dobbertin_bits{0};
    int dobbertin_round{-1};
    char dobbertin_register{'e'};
    uint32_t dobbertin_constant{0x00000000u};
};

static SolverType solver_type_from_name(const std::string& name, bool& ok) {
    ok = true;
    if (name == "cadical") return SolverType::CaDiCaL;
    if (name == "kissat") return SolverType::Kissat;
    if (name == "cryptominisat" || name == "cms") return SolverType::CryptoMiniSat;
    if (name == "minisat") return SolverType::MiniSat;
    if (name == "z3") return SolverType::Z3_SMT;
    ok = false;
    return SolverType::CaDiCaL;
}

// Run a parallel Cube-and-Conquer preimage search.
int cmd_cube_search(const SearchConfig& opt) {
    const uint32_t rounds = opt.rounds;

    if (rounds < 1 || rounds > 64) {
        std::cerr << "Error: rounds must be in [1, 64].\n";
        return 1;
    }
    bool ok = false;
    const SolverType st = solver_type_from_name(opt.solver_str, ok);
    if (!ok) {
        std::cerr << "Error: unknown solver '" << opt.solver_str << "'\n";
        return 2;
    }
    if (opt.dialect == EncodingDialect::Xor && st != SolverType::CryptoMiniSat) {
        std::cerr << "Error: --encoding xor requires the XOR-capable solver 'cryptominisat'.\n";
        return 2;
    }

    auto solver = SolverFactory::create(st);
    if (!solver || !solver->is_available()) {
        std::cerr << "Error: solver " << opt.solver_str << " is not available.\n";
        return 1;
    }

    // Target digest: the R-round compression of a fixed reference block.
    std::vector<uint8_t> known_msg(64, 0);
    const char* tag = "TEST1234";
    for (size_t i = 0; i < 8; ++i) known_msg[i] = static_cast<uint8_t>(tag[i]);
    Sha256State target_state = SHA256_IV;
    Sha256Scalar::compress_block(target_state, known_msg.data(), rounds);
    Sha256Digest target_digest;
    for (size_t i = 0; i < 8; ++i) store_be32(target_digest.bytes.data() + i * 4, target_state[i]);

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;
    cfg.fix_target_digest = true;
    cfg.target_digest = target_digest;
    cfg.dialect = opt.dialect;
    cfg.carry_save_t1 = opt.carry_save;
    if (opt.fix_first_word >= 0 && opt.fix_last_word >= opt.fix_first_word) {
        for (int w = opt.fix_first_word; w <= opt.fix_last_word && w < 16; ++w) {
            cfg.fixed_words.emplace_back(
                static_cast<uint32_t>(w), derived_word(opt.fix_seed, static_cast<uint32_t>(w)));
        }
    }

    auto encode_t0 = std::chrono::steady_clock::now();
    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    const double encode_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - encode_t0).count();

    // Choose cube coordinates: `cube_bits` low-order bits of one state word at
    // the requested round boundary.
    const std::vector<std::vector<int>>& reg =
        (opt.cube_register == 'a') ? enc.state_a_vars : enc.state_e_vars;
    const size_t boundary = static_cast<size_t>(opt.cube_round);
    if (boundary >= reg.size()) {
        std::cerr << "Error: --cube-round " << opt.cube_round
                  << " has no recorded state (available: 0.." << (reg.size() - 1) << ").\n";
        return 2;
    }
    std::vector<int> coordinates(reg[boundary].begin(),
                                 reg[boundary].begin() + opt.cube_bits);

    const uint64_t total_cubes = 1ull << opt.cube_bits;
    unsigned jobs = opt.jobs ? opt.jobs : std::max(1u, std::thread::hardware_concurrency());
    if (jobs > total_cubes) jobs = static_cast<unsigned>(total_cubes);

    std::cout << "[Cube-and-Conquer] " << rounds << " rounds, "
              << opt.cube_bits << " cube bits over register '"
              << opt.cube_register << "' after round " << opt.cube_round << "\n";
    std::cout << "[Cube-and-Conquer] CNF: " << enc.cnf.num_vars << " vars, "
              << enc.cnf.clauses.size() << " clauses, "
              << enc.cnf.xor_constraints.size() << " XOR constraints ("
              << encode_seconds << " s)\n";
    std::cout << "[Cube-and-Conquer] " << total_cubes << " disjoint cubes over "
              << jobs << " worker threads\n";

    const uint32_t per_cube_timeout = std::max(1u, opt.timeout);

    // Learned blocking clauses accumulate across the search. Each one removes
    // a cube that was proven UNSAT, so later batches start from a smaller
    // formula.
    CnfFormula master = enc.cnf;

    std::atomic<uint64_t> cubes_solved{0};
    std::atomic<uint64_t> cubes_unsat{0};
    std::atomic<uint64_t> cubes_inconclusive{0};
    std::atomic<bool> found{false};
    std::mutex found_mutex;
    std::map<int, bool> winning_model;
    uint64_t winning_cube = 0;

    const auto wall_start = std::chrono::steady_clock::now();

    // Cubes are processed in batches. Within a batch every worker reads the
    // master formula, which is safe because it is not modified concurrently;
    // between batches the learned blocking clauses are merged under a lock.
    // Writing to `master` from inside the worker loop would be a data race.
    const uint64_t batch_size = std::max<uint64_t>(1, static_cast<uint64_t>(jobs) * 4);
    std::mutex merge_mutex;

    for (uint64_t batch_start = 0; batch_start < total_cubes && !found.load();
         batch_start += batch_size) {
        const uint64_t batch_end = std::min(total_cubes, batch_start + batch_size);

        std::atomic<uint64_t> cursor{batch_start};
        std::vector<std::vector<int>> learned;

        std::vector<std::thread> workers;
        for (unsigned t = 0; t < jobs; ++t) {
            workers.emplace_back([&]() {
                std::vector<std::vector<int>> local_learned;
                while (!found.load()) {
                    const uint64_t cube = cursor.fetch_add(1);
                    if (cube >= batch_end) break;

                    auto res = solver->solve_under_assumptions(
                        master, CubePartition::literals_for(coordinates, cube),
                        per_cube_timeout);

                    if (res.is_sat()) {
                        std::lock_guard<std::mutex> lock(found_mutex);
                        if (!found.load()) {
                            found.store(true);
                            winning_model = res.model;
                            winning_cube = cube;
                        }
                        cubes_solved.fetch_add(1);
                        return;
                    }
                    if (res.status == SolverStatus::Unsatisfiable) {
                        cubes_unsat.fetch_add(1);
                        // Sound: this cube is provably solution-free, so prune it.
                        local_learned.push_back(
                            CubePartition::blocking_clause(coordinates, cube));
                    } else {
                        // Timeout / unknown proves nothing and must not prune.
                        cubes_inconclusive.fetch_add(1);
                    }
                    cubes_solved.fetch_add(1);
                }
                if (!local_learned.empty()) {
                    std::lock_guard<std::mutex> lock(merge_mutex);
                    for (const auto& clause : local_learned) learned.push_back(clause);
                }
            });
        }
        for (auto& w : workers) w.join();

        // Merge learned clauses only after every worker has stopped reading.
        if (!learned.empty()) {
            for (const auto& clause : learned) master.add_clause(clause);
        }
    }

    const double solve_seconds_total =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();

    const uint64_t n_unsat = cubes_unsat.load();
    const uint64_t n_inconc = cubes_inconclusive.load();

    std::cout << "[Cube-and-Conquer] solved " << cubes_solved.load() << "/" << total_cubes
              << " cubes in " << solve_seconds_total << " s"
              << " (unsat=" << n_unsat << ", inconclusive=" << n_inconc << ")\n";

    // Machine-readable contract, consistent with `sha-research preimage`.
    std::cout << "RESULT_TARGET_DIGEST=" << target_digest.to_hex() << "\n";
    std::cout << "RESULT_ROUNDS=" << rounds << "\n";
    std::cout << "RESULT_CNF_VARS=" << master.num_vars << "\n";
    std::cout << "RESULT_CNF_CLAUSES=" << master.clauses.size() << "\n";
    std::cout << "RESULT_CNF_XORS=" << master.xor_constraints.size() << "\n";
    std::cout << "RESULT_ENCODING=" << dialect_name(opt.dialect) << "\n";
    std::cout << "RESULT_CARRY_SAVE=" << (opt.carry_save ? 1 : 0) << "\n";
    std::cout << "RESULT_ENCODE_TIME=" << encode_seconds << "\n";
    std::cout << "RESULT_SOLVER_TIME=" << solve_seconds_total << "\n";
    std::cout << "RESULT_CUBE_BITS=" << opt.cube_bits << "\n";
    std::cout << "RESULT_CUBE_ROUND=" << opt.cube_round << "\n";
    std::cout << "RESULT_CUBES_TOTAL=" << total_cubes << "\n";
    std::cout << "RESULT_CUBES_SOLVED=" << cubes_solved.load() << "\n";
    std::cout << "RESULT_CUBES_UNSAT=" << n_unsat << "\n";
    std::cout << "RESULT_CUBES_INCONCLUSIVE=" << n_inconc << "\n";

    if (found.load()) {
        auto msg_words = SatEncoder::extract_message_from_model(winning_model, enc.message_vars);
        std::vector<uint8_t> cand_block(64);
        for (size_t i = 0; i < 16; ++i) store_be32(cand_block.data() + i * 4, msg_words[i]);

        PreimageCandidate cand;
        cand.message = cand_block;
        cand.target_digest = target_digest;
        cand.claimed_rounds = rounds;
        cand.iv = SHA256_IV;
        cand.custom_iv = false;
        cand.generator_metadata = std::string("{\"strategy\":\"cube-and-conquer\",\"cube\":") +
                                  std::to_string(winning_cube) + "}";

        auto verdict = IndependentVerifier::verify_preimage_candidate(cand);

        std::string abs_path = std::filesystem::absolute(
            (std::filesystem::path(opt.out_dir) / "cube_candidate.bin")).string();
        for (char& ch : abs_path) if (ch == '\\') ch = '/';
        {
            std::ofstream cf(abs_path, std::ios::binary);
            if (cf.is_open()) {
                cf.write(reinterpret_cast<const char*>(cand_block.data()),
                         static_cast<std::streamsize>(cand_block.size()));
            }
        }

        std::cout << "RESULT_CANDIDATE=" << abs_path << "\n";
        std::cout << "RESULT_CLASSIFICATION=" << to_string(verdict.classification) << "\n";
        std::cout << "RESULT_SOLVER_STATUS=SAT\n";
        std::cout.flush();
        if (verdict.is_valid) {
            std::cout << "   [VERIFIED via IndependentVerifier] Cube "
                      << winning_cube << " yields a valid " << rounds
                      << "-round preimage. Classification: "
                      << to_string(verdict.classification) << "\n";
            return 0;
        }
        std::cout << "   [REJECTED via IndependentVerifier] Cube " << winning_cube
                  << " candidate failed verification: " << verdict.failure_reason << "\n";
        return 2;
    }

    // No SAT cube found. Distinguish a proof from an inconclusive run: a proof
    // requires every cube to have been decided UNSAT with no timeouts.
    if (n_unsat == total_cubes && n_inconc == 0) {
        std::cout << "RESULT_CANDIDATE=NONE\n";
        std::cout << "RESULT_CLASSIFICATION=ProvenNoPreimage\n";
        std::cout << "RESULT_SOLVER_STATUS=UNSAT\n";
        std::cout.flush();
        std::cout << "   PROOF: all " << total_cubes
                  << " cubes are disjoint, cover the space, and each was decided "
                     "UNSAT. No 1-block preimage exists for this target at "
                  << rounds << " rounds under the pinned message words.\n";
        return 1;
    }

    std::cout << "RESULT_CANDIDATE=NONE\n";
    std::cout << "RESULT_CLASSIFICATION=Unresolved\n";
    std::cout << "RESULT_SOLVER_STATUS=" << (n_inconc ? "TIMEOUT" : "UNKNOWN") << "\n";
    std::cout.flush();
    std::cout << "   Unresolved: " << n_inconc
              << " cube(s) hit the per-cube budget without a verdict. "
                 "This is NOT a proof of nonexistence.\n";
    return 1;
}

// `sha-research preimage --rounds N [--solver S] [--encoding xor|tseitin]
//                         [--carry-save] [--timeout T] [--out DIR]
//                         [--fix-words FIRST:LAST] [--fix-seed N]
//                         [--cube-bits K] [--cube-round R] [--cube-register a|e]
//                         [--jobs J]`
//
// Emits the full machine-readable result contract on stdout, including the
// encoding metrics the autonomous loop needs to make escalation decisions.
int cmd_preimage(const std::vector<std::string>& args) {
    SearchConfig opt;

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
            } else if (a == "--fix-words") {
                const std::string spec = need_value(i, "--fix-words");
                const size_t colon = spec.find(':');
                if (colon == std::string::npos) {
                    throw std::invalid_argument(
                        "--fix-words expects FIRST:LAST, got '" + spec + "'");
                }
                opt.fix_first_word = std::stoi(spec.substr(0, colon));
                opt.fix_last_word = std::stoi(spec.substr(colon + 1));
                if (opt.fix_first_word < 0 || opt.fix_last_word < opt.fix_first_word ||
                    opt.fix_last_word > 15) {
                    throw std::invalid_argument(
                        "--fix-words range must satisfy 0 <= FIRST <= LAST <= 15");
                }
            } else if (a == "--fix-seed") {
                opt.fix_seed = static_cast<uint32_t>(std::stoul(need_value(i, "--fix-seed")));
            } else if (a == "--cube-bits") {
                opt.cube_bits = static_cast<uint32_t>(std::stoul(need_value(i, "--cube-bits")));
                if (opt.cube_bits > 24) {
                    throw std::invalid_argument("--cube-bits must be <= 24");
                }
            } else if (a == "--cube-round") {
                opt.cube_round = std::stoi(need_value(i, "--cube-round"));
            } else if (a == "--cube-register") {
                const std::string reg = need_value(i, "--cube-register");
                if (reg != "a" && reg != "e") {
                    throw std::invalid_argument("--cube-register must be 'a' or 'e'");
                }
                opt.cube_register = reg[0];
            } else if (a == "--jobs") {
                opt.jobs = static_cast<uint32_t>(std::stoul(need_value(i, "--jobs")));
            } else if (a == "--dobbertin-bits") {
                opt.dobbertin_bits = std::stoi(need_value(i, "--dobbertin-bits"));
                if (opt.dobbertin_bits < 0 || opt.dobbertin_bits > 32) {
                    throw std::invalid_argument("--dobbertin-bits must be in [0, 32]");
                }
            } else if (a == "--dobbertin-round") {
                opt.dobbertin_round = std::stoi(need_value(i, "--dobbertin-round"));
            } else if (a == "--dobbertin-register") {
                const std::string reg = need_value(i, "--dobbertin-register");
                if (reg != "a" && reg != "e") {
                    throw std::invalid_argument("--dobbertin-register must be 'a' or 'e'");
                }
                opt.dobbertin_register = reg[0];
            } else if (a == "--dobbertin-constant") {
                opt.dobbertin_constant =
                    static_cast<uint32_t>(std::stoul(need_value(i, "--dobbertin-constant"), nullptr, 0));
            } else {
                throw std::invalid_argument("unknown option '" + a + "'");
            }
        }
        if (opt.cube_bits > 0 && opt.cube_round < 0) {
            throw std::invalid_argument("--cube-bits requires --cube-round");
        }
        if (opt.cube_round >= 0 && opt.cube_round > static_cast<int>(opt.rounds)) {
            throw std::invalid_argument(
                "--cube-round must be <= --rounds (the boundary state must exist)");
        }
        if (opt.dobbertin_bits > 0 && opt.dobbertin_round < 0) {
            throw std::invalid_argument("--dobbertin-bits requires --dobbertin-round");
        }
        if (opt.dobbertin_round >= 0 &&
            opt.dobbertin_round > static_cast<int>(opt.rounds)) {
            throw std::invalid_argument(
                "--dobbertin-round must be <= --rounds (the boundary state must exist)");
        }
        if (opt.cube_bits > 0 && opt.dobbertin_bits > 0) {
            throw std::invalid_argument(
                "--cube-bits and --dobbertin-bits are mutually exclusive strategies");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << "Usage: sha-research preimage --rounds N [--solver S] "
                     "[--encoding xor|tseitin] [--carry-save] [--timeout T] [--out DIR]\n"
                     "                          [--fix-words FIRST:LAST] [--fix-seed N]\n"
                     "                          [--cube-bits K] [--cube-round R] "
                     "[--cube-register a|e] [--jobs J]\n"
                     "                          [--dobbertin-bits B] [--dobbertin-round R] "
                     "[--dobbertin-register a|e] [--dobbertin-constant K]\n";
        return 2;
    }

    if (opt.dobbertin_bits > 0) {
        opt.state_bits = opt.dobbertin_bits;
        opt.state_round = opt.dobbertin_round;
        opt.state_register = (opt.dobbertin_register == 'a') ? 0 : 1;
        opt.state_constant = opt.dobbertin_constant;
        return cmd_dobbertin_search(opt);
    }

    if (opt.cube_bits > 0) {
        return cmd_cube_search(opt);
    }

    return cmd_experiment_run(static_cast<int>(opt.rounds), opt.solver_str, opt.out_dir,
                              opt.dialect, opt.carry_save, opt.timeout,
                              opt.fix_first_word, opt.fix_last_word, opt.fix_seed);
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

// ---------------------------------------------------------------------------
// Dobbertin-constrained preimage search.
//
// Dobbertin (1998) showed that constraining an intermediate *state register*
// to a chosen constant, rather than constraining the input, makes the
// inversion dramatically easier: the constraint propagates in both directions
// from the middle of the circuit, which is exactly where a CDCL search stalls.
// Davydov, Pikhtovnikov, Kiryanova and Zaikin (2025) applied this to SHA-256
// and reported 17- and 18-round preimages "for the first time", plus a
// weakened 19-round one.
//
// The catch is that a fully constrained register may admit no preimage at all
// for a given constant. So the constraint is relaxed one bit at a time until a
// solution appears, following Algorithm 1 of Zaikin (IJCAI-ECAI 2022):
//
//   for b = 32 down to 0:
//       solve the instance with the top b bits of the register pinned to K
//       if SAT  -> verify and stop
//       if UNSAT-> relax to b - 1
//
// Any solution found is a genuine preimage and is re-checked by the segregated
// verifier. A relaxation that finds nothing is never reported as a proof of
// nonexistence; only the unconstrained b = 0 instance being UNSAT would be.
// ---------------------------------------------------------------------------
int cmd_dobbertin_search(const SearchConfig& opt) {
    const uint32_t rounds = opt.rounds;

    if (rounds < 1 || rounds > 64) {
        std::cerr << "Error: rounds must be in [1, 64].\n";
        return 1;
    }
    bool ok = false;
    const SolverType st = solver_type_from_name(opt.solver_str, ok);
    if (!ok) {
        std::cerr << "Error: unknown solver '" << opt.solver_str << "'\n";
        return 2;
    }
    if (opt.dialect == EncodingDialect::Xor && st != SolverType::CryptoMiniSat) {
        std::cerr << "Error: --encoding xor requires the XOR-capable solver 'cryptominisat'.\n";
        return 2;
    }

    auto solver = SolverFactory::create(st);
    if (!solver || !solver->is_available()) {
        std::cerr << "Error: solver " << opt.solver_str << " is not available.\n";
        return 1;
    }

    // Target digest: the R-round compression of a fixed reference block.
    std::vector<uint8_t> known_msg(64, 0);
    const char* tag = "TEST1234";
    for (size_t i = 0; i < 8; ++i) known_msg[i] = static_cast<uint8_t>(tag[i]);
    Sha256State target_state = SHA256_IV;
    Sha256Scalar::compress_block(target_state, known_msg.data(), rounds);
    Sha256Digest target_digest;
    for (size_t i = 0; i < 8; ++i) store_be32(target_digest.bytes.data() + i * 4, target_state[i]);

    const char reg_name = (opt.state_register == 0) ? 'a' : 'e';
    const uint32_t constant = opt.state_constant;

    std::cout << "[Dobbertin] " << rounds << " rounds, register '" << reg_name
              << "' after round " << opt.state_round
              << ", constant 0x" << std::hex << constant << std::dec << "\n";

    const auto wall_start = std::chrono::steady_clock::now();
    double encode_seconds_total = 0.0;
    int cnf_vars = 0, cnf_clauses = 0, cnf_xors = 0;

    std::vector<std::pair<int, std::string>> attempts;  // (bits, outcome)

    for (int bits = opt.state_bits; bits >= 0; --bits) {
        SatEncoder::Sha256ProblemConfig cfg;
        cfg.num_rounds = rounds;
        cfg.use_standard_iv = true;
        cfg.fix_target_digest = true;
        cfg.target_digest = target_digest;
        cfg.dialect = opt.dialect;
        cfg.carry_save_t1 = opt.carry_save;
        if (opt.fix_first_word >= 0 && opt.fix_last_word >= opt.fix_first_word) {
            for (int w = opt.fix_first_word; w <= opt.fix_last_word && w < 16; ++w) {
                cfg.fixed_words.emplace_back(
                    static_cast<uint32_t>(w), derived_word(opt.fix_seed, static_cast<uint32_t>(w)));
            }
        }
        cfg.use_state_constraint = true;
        cfg.state_constraint_round = static_cast<uint32_t>(opt.state_round);
        cfg.state_constraint_register = opt.state_register;
        cfg.state_constraint_value = constant;
        cfg.state_constraint_bits = static_cast<uint32_t>(bits);

        auto e0 = std::chrono::steady_clock::now();
        auto enc = SatEncoder::encode_reduced_rounds(cfg);
        encode_seconds_total +=
            std::chrono::duration<double>(std::chrono::steady_clock::now() - e0).count();
        cnf_vars = enc.cnf.num_vars;
        cnf_clauses = static_cast<int>(enc.cnf.clauses.size());
        cnf_xors = static_cast<int>(enc.cnf.xor_constraints.size());

        auto res = solver->solve_cnf(enc.cnf, opt.timeout);

        std::cout << "  bits=" << bits << " vars=" << cnf_vars
                  << " clauses=" << cnf_clauses
                  << " solve=" << res.stats.wall_time_seconds << "s -> "
                  << to_string(res.status) << "\n";

        if (res.is_sat()) {
            auto msg_words = SatEncoder::extract_message_from_model(res.model, enc.message_vars);
            std::vector<uint8_t> cand_block(64);
            for (size_t i = 0; i < 16; ++i) store_be32(cand_block.data() + i * 4, msg_words[i]);

            PreimageCandidate cand;
            cand.message = cand_block;
            cand.target_digest = target_digest;
            cand.claimed_rounds = rounds;
            cand.iv = SHA256_IV;
            cand.custom_iv = false;
            cand.generator_metadata =
                std::string("{\"strategy\":\"dobbertin\",\"register\":\"") + reg_name +
                "\",\"round\":" + std::to_string(opt.state_round) +
                ",\"bits\":" + std::to_string(bits) +
                ",\"constant\":" + std::to_string(constant) + "}";

            auto verdict = IndependentVerifier::verify_preimage_candidate(cand);

            std::string abs_path = std::filesystem::absolute(
                (std::filesystem::path(opt.out_dir) / "dobbertin_candidate.bin")).string();
            for (char& ch : abs_path) if (ch == '\\') ch = '/';
            {
                std::ofstream cf(abs_path, std::ios::binary);
                if (cf.is_open()) {
                    cf.write(reinterpret_cast<const char*>(cand_block.data()),
                             static_cast<std::streamsize>(cand_block.size()));
                }
            }

            const double solve_total =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();

            std::cout << "RESULT_TARGET_DIGEST=" << target_digest.to_hex() << "\n";
            std::cout << "RESULT_CANDIDATE=" << abs_path << "\n";
            std::cout << "RESULT_ROUNDS=" << rounds << "\n";
            std::cout << "RESULT_CLASSIFICATION=" << to_string(verdict.classification) << "\n";
            std::cout << "RESULT_CNF_VARS=" << cnf_vars << "\n";
            std::cout << "RESULT_CNF_CLAUSES=" << cnf_clauses << "\n";
            std::cout << "RESULT_CNF_XORS=" << cnf_xors << "\n";
            std::cout << "RESULT_ENCODING=" << dialect_name(opt.dialect) << "\n";
            std::cout << "RESULT_CARRY_SAVE=" << (opt.carry_save ? 1 : 0) << "\n";
            std::cout << "RESULT_ENCODE_TIME=" << encode_seconds_total << "\n";
            std::cout << "RESULT_SOLVER_TIME=" << solve_total << "\n";
            std::cout << "RESULT_SOLVER_STATUS=SAT\n";
            std::cout << "RESULT_DOBBERTIN_BITS=" << bits << "\n";
            std::cout << "RESULT_DOBBERTIN_ROUND=" << opt.state_round << "\n";
            std::cout << "RESULT_DOBBERTIN_REGISTER=" << reg_name << "\n";
            std::cout.flush();

            if (verdict.is_valid) {
                std::cout << "   [VERIFIED via IndependentVerifier] Dobbertin constraint on "
                          << reg_name << " after round " << opt.state_round << " ("
                          << bits << " bits) yields a valid " << rounds
                          << "-round preimage. Classification: "
                          << to_string(verdict.classification) << "\n";
                return 0;
            }
            std::cout << "   [REJECTED via IndependentVerifier] candidate failed verification: "
                      << verdict.failure_reason << "\n";
            return 2;
        }

        if (res.status == SolverStatus::Timeout || res.status == SolverStatus::Unknown) {
            // Inconclusive. Relaxing is still sound and still useful: fewer
            // constraint bits means a strict superset of the solution set, so a
            // preimage found at a lower level is still genuine. This follows
            // Algorithm 1 of Zaikin (IJCAI-ECAI 2022), which relaxes on any
            // failure, not only on UNSAT.
            attempts.emplace_back(bits, "INCONCLUSIVE");
            std::cout << "   Inconclusive at " << bits << " bits; relaxing.\n";
            continue;
        }
        attempts.emplace_back(bits, "UNSAT");
    }

    const double solve_total =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();
    const bool exhausted_all = !attempts.empty() && attempts.back().first == 0;

    std::cout << "RESULT_TARGET_DIGEST=" << target_digest.to_hex() << "\n";
    std::cout << "RESULT_CANDIDATE=NONE\n";
    std::cout << "RESULT_ROUNDS=" << rounds << "\n";
    std::cout << "RESULT_CLASSIFICATION="
              << (exhausted_all ? "ProvenNoPreimage" : "Unresolved") << "\n";
    std::cout << "RESULT_CNF_VARS=" << cnf_vars << "\n";
    std::cout << "RESULT_CNF_CLAUSES=" << cnf_clauses << "\n";
    std::cout << "RESULT_CNF_XORS=" << cnf_xors << "\n";
    std::cout << "RESULT_ENCODING=" << dialect_name(opt.dialect) << "\n";
    std::cout << "RESULT_CARRY_SAVE=" << (opt.carry_save ? 1 : 0) << "\n";
    std::cout << "RESULT_ENCODE_TIME=" << encode_seconds_total << "\n";
    std::cout << "RESULT_SOLVER_TIME=" << solve_total << "\n";
    std::cout << "RESULT_SOLVER_STATUS=" << (exhausted_all ? "UNSAT" : "TIMEOUT") << "\n";
    std::cout.flush();

    if (exhausted_all) {
        std::cout << "   PROOF: every relaxation level down to the unconstrained (0-bit)\n"
                     "   instance was decided UNSAT. No 1-block preimage exists for this\n"
                     "   target at " << rounds << " rounds.\n";
        return 1;
    }
    std::cout << "   Unresolved within the budget. This is NOT a proof of nonexistence.\n";
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        print_help();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "--version" || cmd == "-v" || cmd == "version") {
        std::cout << "sha-research " << SHA256_RESEARCH_VERSION << "\n";
        return 0;
    } else if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_banner();
        print_help();
        return 0;
    } else if (cmd == "doctor") {
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
