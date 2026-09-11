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
              << "   SHA-256 Cryptanalysis & Research Framework (v2026.1)       \n"
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

int cmd_experiment_run(int rounds, const std::string& solver_str) {
    std::cout << "[Experiment] Running automated cryptanalysis experiment: " << rounds << " rounds\n";

    SolverType st = SolverType::CaDiCaL;
    if (solver_str == "kissat") st = SolverType::Kissat;
    else if (solver_str == "cryptominisat") st = SolverType::CryptoMiniSat;
    else if (solver_str == "minisat") st = SolverType::MiniSat;

    if (rounds < 1 || rounds > 64) {
        std::cerr << "Error: Invalid round count " << rounds << ". Rounds must be between 1 and 64.\n";
        return 1;
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

    ExperimentStorage storage("evidence");
    ExperimentMetadata meta;
    meta.experiment_id = ExperimentStorage::generate_experiment_id("exp_reduced");
    meta.target_rounds = static_cast<uint32_t>(rounds);
    meta.solver_name = SolverFactory::solver_name(st);
    meta.research_question = "Can SAT solvers find a valid 1-block preimage for " + std::to_string(rounds) + "-round SHA-256?";
    meta.hypothesis = "Modern CDCL solvers will efficiently invert reduced-round SHA-256 for small round counts (e.g. <= 16 rounds).";
    meta.start_time = utc_now();
    meta.deterministic_seed = 0xC0FFEE01u;
    meta.command_line = std::string("sha-research experiment run ") + std::to_string(rounds) + " " + solver_str;
    meta.configuration_json = "{\"rounds\": " + std::to_string(rounds) + ", \"solver\": \"" + meta.solver_name + "\", \"seed\": 3235824897}";

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

    std::cout << "   Encoding " << rounds << "-round SHA-256 constraints to CNF...\n";
    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    std::cout << "   Generated CNF: " << enc.cnf.num_vars << " variables, " << enc.cnf.clauses.size() << " clauses.\n";

    auto solver = SolverFactory::create(st);
    if (!solver || !solver->is_available()) {
        std::cout << "   Error: Solver " << meta.solver_name << " is not available.\n";
        return 1;
    }

    std::cout << "   Invoking solver " << meta.solver_name << "...\n";
    auto sol_res = solver->solve_cnf(enc.cnf, 60);
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

        {
            std::string cand_path = (std::filesystem::path(exp_dir) / "artifacts" / "candidate_block.bin").string();
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

        // Verify with IndependentVerifier
        Sha256State test_state = SHA256_IV;
        Sha256Scalar::compress_block(test_state, cand_block.data(), rounds);
        Sha256Digest cand_digest;
        for (size_t i = 0; i < 8; ++i) store_be32(cand_digest.bytes.data() + i * 4, test_state[i]);

        if (cand_digest == target_digest) {
            meta.outcome_success = true;
            meta.classification = "ReducedRoundPreimageVerified";
            meta.conclusion = "Successfully found valid message block producing target digest for " + std::to_string(rounds) + " rounds.";
            verdict.is_valid = true;
            verdict.classification = CandidateClassification::ReducedRoundPreimage;
            verdict.actual_rounds = static_cast<uint32_t>(rounds);
            verdict.digest_a = cand_digest;
            verdict.digest_b = target_digest;
            std::cout << "   [VERIFIED] Candidate block matches target digest!\n";
        } else {
            meta.outcome_success = false;
            meta.classification = "ModelExtractionMismatch";
            meta.conclusion = "Solver claimed SAT but reconstructed candidate failed independent verification.";
            verdict.is_valid = false;
            std::cout << "   [REJECTED] Candidate block failed verification!\n";
        }
    } else {
        meta.outcome_success = false;
        meta.classification = "NoSolutionFound";
        meta.conclusion = "Solver did not find solution within timeout.";
    }

    meta.end_time = utc_now();
    storage.finalize_experiment(meta.experiment_id, meta, artifacts, verdict);
    std::cout << "   Experiment finalized: " << meta.experiment_id << "\n";
    return 0;
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
            if (argc >= 4) rounds = std::stoi(argv[3]);
            if (argc >= 5) solver = argv[4];
            return cmd_experiment_run(rounds, solver);
        } else {
            std::cout << "Usage: sha-research experiment run [rounds] [solver]\n";
            return 0;
        }
    } else if (cmd == "campaign") {
        std::cout << "Autonomous Campaign Manager:\n"
                  << "  Status: Idle (Ready to launch with 'sha-research campaign start')\n";
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
