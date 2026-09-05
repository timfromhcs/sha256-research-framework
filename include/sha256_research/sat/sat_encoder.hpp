#pragma once

#include "sha256_research/core/types.hpp"
#include <vector>
#include <string>
#include <map>
#include <memory>

namespace sha256_research {

struct CnfFormula {
    int num_vars{0};
    std::vector<std::vector<int>> clauses;

    int new_var() noexcept { return ++num_vars; }
    std::vector<int> new_vars(size_t count) {
        std::vector<int> vars(count);
        for (size_t i = 0; i < count; ++i) vars[i] = ++num_vars;
        return vars;
    }

    void add_clause(const std::vector<int>& clause) {
        clauses.push_back(clause);
    }
    void add_unit(int lit) {
        clauses.push_back({lit});
    }

    std::string to_dimacs() const;
    bool write_dimacs_file(const std::string& path) const;
};

class SatEncoder {
public:
    SatEncoder() = default;

    // Bitwise gate encodings (Tseitin transformation)
    static void encode_not(CnfFormula& cnf, int in, int out);
    static void encode_and2(CnfFormula& cnf, int a, int b, int out);
    static void encode_or2(CnfFormula& cnf, int a, int b, int out);
    static void encode_xor2(CnfFormula& cnf, int a, int b, int out);
    static void encode_xor3(CnfFormula& cnf, int a, int b, int c, int out);
    static void encode_maj(CnfFormula& cnf, int a, int b, int c, int out);
    static void encode_ch(CnfFormula& cnf, int e, int f, int g, int out);

    // 32-bit word rotation and shift in variable arrays
    static std::vector<int> rotate_right(const std::vector<int>& in, uint32_t n);
    static std::vector<int> shift_right(CnfFormula& cnf, const std::vector<int>& in, uint32_t n);

    // 32-bit functions
    static std::vector<int> encode_sigma0(CnfFormula& cnf, const std::vector<int>& x);
    static std::vector<int> encode_sigma1(CnfFormula& cnf, const std::vector<int>& x);
    static std::vector<int> encode_gamma0(CnfFormula& cnf, const std::vector<int>& x);
    static std::vector<int> encode_gamma1(CnfFormula& cnf, const std::vector<int>& x);
    static std::vector<int> encode_ch32(CnfFormula& cnf, const std::vector<int>& e, const std::vector<int>& f, const std::vector<int>& g);
    static std::vector<int> encode_maj32(CnfFormula& cnf, const std::vector<int>& a, const std::vector<int>& b, const std::vector<int>& c);

    // 32-bit modular addition: out = (a + b) mod 2^32
    static std::vector<int> encode_add32(CnfFormula& cnf, const std::vector<int>& a, const std::vector<int>& b);
    static std::vector<int> encode_add32_const(CnfFormula& cnf, const std::vector<int>& a, uint32_t constant);

    // Encode constant 32-bit value
    static void fix_const32(CnfFormula& cnf, const std::vector<int>& vars, uint32_t val);

    // High-level SHA-256 SAT problem formulations
    struct Sha256ProblemConfig {
        uint32_t num_rounds{16};
        bool use_standard_iv{true};
        Sha256State custom_iv = SHA256_IV;
        bool fix_target_digest{false};
        Sha256Digest target_digest{};
        bool is_collision_problem{false};
        std::vector<uint32_t> fixed_message_words; // optional pre-fixed words
    };

    struct Sha256SatEncoding {
        CnfFormula cnf;
        std::vector<std::vector<int>> message_vars;       // W_0..W_{R-1} (32 vars each)
        std::vector<std::vector<int>> state_a_vars;       // A_0..A_R
        std::vector<std::vector<int>> state_e_vars;       // E_0..E_R
        std::vector<std::vector<int>> final_digest_vars;  // 8 words of output
        std::vector<std::vector<int>> message2_vars;      // For collision problem
    };

    static Sha256SatEncoding encode_reduced_rounds(const Sha256ProblemConfig& config);

    // Extract concrete 16 32-bit message words from a SAT model assignment
    static std::vector<uint32_t> extract_message_from_model(
        const std::map<int, bool>& model,
        const std::vector<std::vector<int>>& msg_vars
    );
};

} // namespace sha256_research
