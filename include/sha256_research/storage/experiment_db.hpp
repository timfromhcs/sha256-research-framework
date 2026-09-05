#pragma once

#include "sha256_research/core/types.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace sha256_research {

struct ExperimentMetadata {
    std::string experiment_id;
    std::string hypothesis;
    std::string research_question;
    std::string parent_experiment;
    std::string start_time;
    std::string end_time;
    std::string configuration_json;
    std::string solver_name;
    uint32_t target_rounds{0};
    bool outcome_success{false};
    std::string classification;
    std::string conclusion;
};

struct ArtifactRecord {
    std::string relative_path;
    std::string sha256_hash;
    uint64_t size_bytes{0};
    std::string description;
};

class ExperimentStorage {
public:
    explicit ExperimentStorage(std::string base_dir = "evidence");

    // Generate unique immutable experiment ID
    static std::string generate_experiment_id(const std::string& prefix = "exp");

    // Hash file using SHA-256
    static std::string hash_file(const std::string& path);

    // Create experiment directory structure
    std::string create_experiment_run(const ExperimentMetadata& meta);

    // Write manifest JSON with file hashes
    bool finalize_experiment(
        const std::string& experiment_id,
        const ExperimentMetadata& meta,
        const std::vector<ArtifactRecord>& artifacts,
        const VerificationVerdict& verdict
    );

private:
    std::string base_dir_;
};

} // namespace sha256_research
