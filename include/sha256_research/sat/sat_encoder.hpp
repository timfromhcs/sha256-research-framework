#pragma once

#include "sha256_research/core/types.hpp"
#include <algorithm>
#include <cstdlib>
#include <vector>
#include <string>
#include <map>
#include <memory>

namespace sha256_research {

// Encoding dialect for the emitted formula.
//
// The same SHA-256 circuit can be expressed several ways, and the choice
// dominates solver performance. Two dialects are supported:
//
//   Tseitin : pure CNF. Every gate becomes auxiliary variables plus clauses.
//              Universally supported, but XOR-heavy circuits balloon because
//              each XOR costs 4 clauses and one auxiliary variable.
//
//   Xor     : CryptoMiniSat's extended DIMACS. Pure XOR sub-circuits (the
//              sigma/gamma message-schedule and round functions, and adder sum
//              bits) are emitted as native XOR constraints, which lets the
//              solver apply Gaussian elimination over the GF(2) subsystem
//              instead of clause-level unit propagation.
//
// A dialect is recorded in the formula so callers can never mislabel one
// encoding as the other.
enum class EncodingDialect {
    Tseitin,   // pure CNF
    Xor        // CNF + native XOR constraints (requires XOR-capable solver)
};

struct CnfFormula {
    int num_vars{0};
    std::vector<std::vector<int>> clauses;
    // Native XOR constraints: parity of `lits` must equal `rhs`.
    // Populated only when the dialect is EncodingDialect::Xor.
    struct XorConstraint {
        std::vector<int> lits;
        bool rhs{true};
    };
    std::vector<XorConstraint> xor_constraints;
    EncodingDialect dialect{EncodingDialect::Tseitin};

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

    // Record a native XOR constraint: parity of `lits` must equal `rhs`.
    // Populated only when the dialect is EncodingDialect::Xor.
    //
    // Literal normalisation. A variable repeated `count` times with a total sign
    // sum S contributes:
    //   * the variable itself when count is odd (signed by the majority sign)
    //   * nothing when count is even
    //   * the constant ((count - |S|)/2) mod 2, which flips the parity
    // Both parts are folded away so the emitted clause set is minimal.
    void add_xor_constraint(std::vector<int> lits, bool rhs = true) {
        if (dialect != EncodingDialect::Xor || lits.empty()) return;

        std::map<int, std::pair<int, int>> occurrences; // var -> (count, sign_sum)
        for (int l : lits) {
            int var = std::abs(l);
            int sign = (l > 0) ? 1 : -1;
            auto& e = occurrences[var];
            e.first += 1;
            e.second += sign;
        }

        std::vector<int> cleaned;
        cleaned.reserve(occurrences.size());
        for (const auto& [var, info] : occurrences) {
            const int count = info.first;
            const int sign_sum = info.second;
            const int positives = (count + sign_sum) / 2;
            const int negatives = count - positives;

            // Opposite-sign pairs contribute the constant 1.
            const int constant_pairs = std::min(positives, negatives);
            if (constant_pairs % 2 == 1) rhs = !rhs;

            if (count % 2 == 1) {
                cleaned.push_back(positives > negatives ? var : -var);
            }
        }

        if (cleaned.empty()) {
            if (!rhs) cnf_conflict = true;  // reduces to false
            return;
        }

        if (!rhs) {
            // CryptoMiniSat XOR clauses carry no negated form. Introduce the
            // shared TRUE literal so parity(lits) == false becomes
            // parity(lits + TRUE) == true.
            cleaned.push_back(true_literal());
        }

        xor_constraints.push_back({std::move(cleaned), true});
    }

    // Shared TRUE literal (allocated at most once per formula).
    int true_literal() {
        if (true_var_ == 0) {
            true_var_ = new_var();
            add_unit(true_var_);
        }
        return true_var_;
    }

    // Shared FALSE literal. Literal 0 is the DIMACS clause terminator and is
    // never a usable literal, so carry chains and shift fills must use a real
    // variable constrained to false.
    int false_literal() {
        if (false_var_ == 0) {
            false_var_ = new_var();
            add_unit(-false_var_);
        }
        return false_var_;
    }

    // Set when normalisation proves the formula unsatisfiable.
    bool is_trivially_unsat() const noexcept { return cnf_conflict; }

    bool uses_xor() const noexcept {
        return dialect == EncodingDialect::Xor && !xor_constraints.empty();
    }

    // Total clause-like constraints, for fair size comparison across dialects.
    size_t constraint_count() const noexcept {
        return clauses.size() + xor_constraints.size();
    }

    std::string to_dimacs() const;
    bool write_dimacs_file(const std::string& path) const;

private:
    int true_var_{0};
    int false_var_{0};
    bool cnf_conflict{false};
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

    // Encode out = a XOR b. Under the Xor dialect this emits a single native
    // constraint with no auxiliary variable; under Tseitin it emits 4 clauses.
    // Returns the literal denoting `out`.
    static int encode_parity2(CnfFormula& cnf, int a, int b);
    static int encode_parity3(CnfFormula& cnf, int a, int b, int c);

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

    // Multi-operand addition with a single shared carry chain:
    //   out = (a0 + a1 + ... + a_{n-1}) mod 2^32
    // Reassociating SHA-256's T1 computation (h + S1 + Ch + W + K) into one
    // pass removes four serial ripple adders per round.
    static std::vector<int> encode_add32_multi(
        CnfFormula& cnf, const std::vector<const std::vector<int>*>& addends);

    // Full adder: returns sum bit, writes carry into `carry_out`.
    // Shared by the multi-operand path so every addend contributes to the same
    // carry chain instead of allocating one per addition.
    static int encode_full_adder(CnfFormula& cnf, int a, int b, int carry_in, int& carry_out);

    // Encode constant 32-bit value
    static void fix_const32(CnfFormula& cnf, const std::vector<int>& vars, uint32_t val);

    // Constant folding: bind a word to a literal constant without emitting
    // per-bit units, by propagating the constant through the adder network.
    // Returns true when the word was fully substituted away.
    static bool substitute_const32(CnfFormula& cnf, std::vector<int>& word, uint32_t val);

    // High-level SHA-256 SAT problem formulations
    struct Sha256ProblemConfig {
        uint32_t num_rounds{16};
        bool use_standard_iv{true};
        Sha256State custom_iv = SHA256_IV;
        bool fix_target_digest{false};
        Sha256Digest target_digest{};
        bool is_collision_problem{false};
        std::vector<uint32_t> fixed_message_words; // optional pre-fixed words
        EncodingDialect dialect{EncodingDialect::Tseitin};
        // Reassociate the round additions into a single shared carry chain.
        bool carry_save_t1{false};
    };

    struct Sha256SatEncoding {
        CnfFormula cnf;
        std::vector<std::vector<int>> message_vars;       // W_0..W_{R-1} (32 vars each)
        std::vector<std::vector<int>> state_a_vars;       // A_0..A_R
        std::vector<std::vector<int>> state_e_vars;       // E_0..E_R
        std::vector<std::vector<int>> final_digest_vars;  // 8 words of output
        std::vector<std::vector<int>> message2_vars;      // For collision problem
        EncodingDialect dialect{EncodingDialect::Tseitin};
    };

    static Sha256SatEncoding encode_reduced_rounds(const Sha256ProblemConfig& config);

    // Extract concrete 16 32-bit message words from a SAT model assignment
    static std::vector<uint32_t> extract_message_from_model(
        const std::map<int, bool>& model,
        const std::vector<std::vector<int>>& msg_vars
    );
};

} // namespace sha256_research
