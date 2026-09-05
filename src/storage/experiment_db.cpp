#include "sha256_research/storage/experiment_db.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include <chrono>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <random>
#include <iomanip>

namespace sha256_research {

ExperimentStorage::ExperimentStorage(std::string base_dir)
    : base_dir_(std::move(base_dir)) {}

std::string ExperimentStorage::generate_experiment_id(const std::string& prefix) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    std::tm bt{};
#if defined(_WIN32)
    localtime_s(&bt, &in_time_t);
#else
    localtime_r(&in_time_t, &bt);
#endif
    ss << prefix << "_"
       << std::put_time(&bt, "%Y%m%d_%H%M%S")
       << "_" << std::setw(3) << std::setfill('0') << ms.count();

    // Append 4 random hex chars
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(0x1000, 0xFFFF);
    ss << "_" << std::hex << dist(rng);

    return ss.str();
}

std::string ExperimentStorage::hash_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";

    Sha256Scalar hasher;
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        hasher.update(buffer, sizeof(buffer));
    }
    if (file.gcount() > 0) {
        hasher.update(buffer, file.gcount());
    }

    Sha256Digest digest = hasher.finalize();
    return digest.to_hex();
}

std::string ExperimentStorage::create_experiment_run(const ExperimentMetadata& meta) {
    std::filesystem::path exp_dir = std::filesystem::path(base_dir_) / "experiments" / meta.experiment_id;
    std::filesystem::create_directories(exp_dir / "artifacts");
    std::filesystem::create_directories(exp_dir / "verification");

    // Write initial hypothesis and config
    std::ofstream hyp_file(exp_dir / "hypothesis.md");
    if (hyp_file.is_open()) {
        hyp_file << "# Experiment: " << meta.experiment_id << "\n\n";
        hyp_file << "## Research Question\n" << meta.research_question << "\n\n";
        hyp_file << "## Hypothesis\n" << meta.hypothesis << "\n\n";
        hyp_file << "## Target Rounds: " << meta.target_rounds << "\n";
        hyp_file << "## Solver: " << meta.solver_name << "\n";
    }

    std::ofstream cfg_file(exp_dir / "configuration.json");
    if (cfg_file.is_open()) {
        cfg_file << meta.configuration_json;
    }

    return exp_dir.string();
}

bool ExperimentStorage::finalize_experiment(
    const std::string& experiment_id,
    const ExperimentMetadata& meta,
    const std::vector<ArtifactRecord>& artifacts,
    const VerificationVerdict& verdict)
{
    std::filesystem::path exp_dir = std::filesystem::path(base_dir_) / "experiments" / experiment_id;
    if (!std::filesystem::exists(exp_dir)) return false;

    // Write conclusion
    std::ofstream conc_file(exp_dir / "conclusion.md");
    if (conc_file.is_open()) {
        conc_file << "# Conclusion for " << experiment_id << "\n\n";
        conc_file << "Outcome: " << (meta.outcome_success ? "CONFIRMED" : "REFUTED / INCONCLUSIVE") << "\n\n";
        conc_file << "Classification: " << meta.classification << "\n\n";
        conc_file << meta.conclusion << "\n";
    }

    // Write manifest JSON with file hashes
    std::ofstream manifest_file(exp_dir / "manifest.json");
    if (!manifest_file.is_open()) return false;

    manifest_file << "{\n";
    manifest_file << "  \"experiment_id\": \"" << experiment_id << "\",\n";
    manifest_file << "  \"parent_experiment\": \"" << meta.parent_experiment << "\",\n";
    manifest_file << "  \"start_time\": \"" << meta.start_time << "\",\n";
    manifest_file << "  \"end_time\": \"" << meta.end_time << "\",\n";
    manifest_file << "  \"outcome_success\": " << (meta.outcome_success ? "true" : "false") << ",\n";
    manifest_file << "  \"classification\": \"" << meta.classification << "\",\n";
    manifest_file << "  \"verification\": {\n";
    manifest_file << "    \"is_valid\": " << (verdict.is_valid ? "true" : "false") << ",\n";
    manifest_file << "    \"classification\": \"" << to_string(verdict.classification) << "\",\n";
    manifest_file << "    \"failure_reason\": \"" << verdict.failure_reason << "\",\n";
    manifest_file << "    \"actual_rounds\": " << verdict.actual_rounds << ",\n";
    manifest_file << "    \"digest_a\": \"" << verdict.digest_a.to_hex() << "\",\n";
    manifest_file << "    \"digest_b\": \"" << verdict.digest_b.to_hex() << "\"\n";
    manifest_file << "  },\n";
    manifest_file << "  \"artifacts\": [\n";

    for (size_t i = 0; i < artifacts.size(); ++i) {
        const auto& a = artifacts[i];
        manifest_file << "    {\n";
        manifest_file << "      \"path\": \"" << a.relative_path << "\",\n";
        manifest_file << "      \"sha256\": \"" << a.sha256_hash << "\",\n";
        manifest_file << "      \"size_bytes\": " << a.size_bytes << ",\n";
        manifest_file << "      \"description\": \"" << a.description << "\"\n";
        manifest_file << "    }" << (i + 1 < artifacts.size() ? "," : "") << "\n";
    }

    manifest_file << "  ]\n";
    manifest_file << "}\n";

    return true;
}

} // namespace sha256_research
