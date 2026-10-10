#include "sha256_research/sat/sat_encoder.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace sha256_research {

namespace {

// CryptoMiniSat extended DIMACS writes XOR constraints as
//   x <lit> <lit> ... 0
// The parity of the literals must hold. A false parity has already been
// normalised into a shared TRUE literal by CnfFormula::add_xor_constraint, so
// every emitted clause is a true-parity constraint.
void write_xor_line(std::ostream& os, const std::vector<int>& lits) {
    if (lits.empty()) return;
    os << "x";
    for (int l : lits) os << " " << l;
    os << " 0\n";
}

} // namespace

std::string CnfFormula::to_dimacs() const {
    std::ostringstream oss;
    oss << "p cnf " << num_vars << " "
        << (clauses.size() + xor_constraints.size()) << "\n";
    for (const auto& cl : clauses) {
        for (int lit : cl) {
            oss << lit << " ";
        }
        oss << "0\n";
    }
    if (uses_xor()) {
        oss << "c CryptoMiniSat extended DIMACS: "
            << xor_constraints.size() << " native XOR constraints\n";
        for (const auto& xc : xor_constraints) {
            write_xor_line(oss, xc.lits);
        }
    }
    return oss.str();
}

bool CnfFormula::write_dimacs_file(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return false;
    out << "c SHA-256 Cryptanalysis formula ("
        << (dialect == EncodingDialect::Xor ? "XOR-extended DIMACS" : "pure CNF")
        << ")\n";
    out << "p cnf " << num_vars << " "
        << (clauses.size() + xor_constraints.size()) << "\n";
    for (const auto& cl : clauses) {
        for (int lit : cl) {
            out << lit << " ";
        }
        out << "0\n";
    }
    if (uses_xor()) {
        out << "c native XOR constraints: " << xor_constraints.size() << "\n";
        for (const auto& xc : xor_constraints) {
            write_xor_line(out, xc.lits);
        }
    }
    return true;
}

void SatEncoder::encode_not(CnfFormula& cnf, int in, int out) {
    cnf.add_clause({in, out});
    cnf.add_clause({-in, -out});
}

void SatEncoder::encode_and2(CnfFormula& cnf, int a, int b, int out) {
    cnf.add_clause({-a, -b, out});
    cnf.add_clause({a, -out});
    cnf.add_clause({b, -out});
}

void SatEncoder::encode_or2(CnfFormula& cnf, int a, int b, int out) {
    cnf.add_clause({a, b, -out});
    cnf.add_clause({-a, out});
    cnf.add_clause({-b, out});
}

void SatEncoder::encode_xor2(CnfFormula& cnf, int a, int b, int out) {
    cnf.add_clause({-a, -b, -out});
    cnf.add_clause({a, b, -out});
    cnf.add_clause({-a, b, out});
    cnf.add_clause({a, -b, out});
}

void SatEncoder::encode_xor3(CnfFormula& cnf, int a, int b, int c, int out) {
    int tmp = cnf.new_var();
    encode_xor2(cnf, a, b, tmp);
    encode_xor2(cnf, tmp, c, out);
}

int SatEncoder::encode_parity2(CnfFormula& cnf, int a, int b) {
    int out = cnf.new_var();
    if (cnf.dialect == EncodingDialect::Xor) {
        // Single native constraint: out <-> a XOR b, no auxiliary variable.
        cnf.add_xor_constraint({a, b, -out}, true);
    } else {
        encode_xor2(cnf, a, b, out);
    }
    return out;
}

int SatEncoder::encode_parity3(CnfFormula& cnf, int a, int b, int c) {
    int out = cnf.new_var();
    if (cnf.dialect == EncodingDialect::Xor) {
        cnf.add_xor_constraint({a, b, c, -out}, true);
    } else {
        encode_xor3(cnf, a, b, c, out);
    }
    return out;
}

void SatEncoder::encode_maj(CnfFormula& cnf, int a, int b, int c, int out) {
    cnf.add_clause({-a, -b, out});
    cnf.add_clause({-a, -c, out});
    cnf.add_clause({-b, -c, out});
    cnf.add_clause({a, b, -out});
    cnf.add_clause({a, c, -out});
    cnf.add_clause({b, c, -out});
}

void SatEncoder::encode_ch(CnfFormula& cnf, int e, int f, int g, int out) {
    cnf.add_clause({-e, -f, out});
    cnf.add_clause({-e, f, -out});
    cnf.add_clause({e, -g, out});
    cnf.add_clause({e, g, -out});
}

std::vector<int> SatEncoder::rotate_right(const std::vector<int>& in, uint32_t n) {
    std::vector<int> res(32);
    n %= 32;
    for (size_t i = 0; i < 32; ++i) {
        res[i] = in[(i + n) % 32];
    }
    return res;
}

std::vector<int> SatEncoder::shift_right(CnfFormula& cnf, const std::vector<int>& in, uint32_t n) {
    // One shared FALSE literal for the whole formula. Literal 0 cannot be used
    // here because it is the DIMACS clause terminator, and a per-call variable
    // would be pure bloat since gamma0/gamma1 run once per expanded word.
    const int zero_var = cnf.false_literal();

    std::vector<int> res(32);
    for (size_t i = 0; i < 32; ++i) {
        if (i + n < 32) {
            res[i] = in[i + n];
        } else {
            res[i] = zero_var;
        }
    }
    return res;
}

std::vector<int> SatEncoder::encode_sigma0(CnfFormula& cnf, const std::vector<int>& x) {
    auto r2 = rotate_right(x, 2);
    auto r13 = rotate_right(x, 13);
    auto r22 = rotate_right(x, 22);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = encode_parity3(cnf, r2[i], r13[i], r22[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_sigma1(CnfFormula& cnf, const std::vector<int>& x) {
    auto r6 = rotate_right(x, 6);
    auto r11 = rotate_right(x, 11);
    auto r25 = rotate_right(x, 25);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = encode_parity3(cnf, r6[i], r11[i], r25[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_gamma0(CnfFormula& cnf, const std::vector<int>& x) {
    auto r7 = rotate_right(x, 7);
    auto r18 = rotate_right(x, 18);
    auto s3 = shift_right(cnf, x, 3);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = encode_parity3(cnf, r7[i], r18[i], s3[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_gamma1(CnfFormula& cnf, const std::vector<int>& x) {
    auto r17 = rotate_right(x, 17);
    auto r19 = rotate_right(x, 19);
    auto s10 = shift_right(cnf, x, 10);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = encode_parity3(cnf, r17[i], r19[i], s10[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_ch32(CnfFormula& cnf, const std::vector<int>& e, const std::vector<int>& f, const std::vector<int>& g) {
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        encode_ch(cnf, e[i], f[i], g[i], out[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_maj32(CnfFormula& cnf, const std::vector<int>& a, const std::vector<int>& b, const std::vector<int>& c) {
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        encode_maj(cnf, a[i], b[i], c[i], out[i]);
    }
    return out;
}

int SatEncoder::encode_full_adder(CnfFormula& cnf, int a, int b, int carry_in, int& carry_out) {
    // Carry in may alias carry out in the caller's loop variable, so capture
    // it by value before writing the outgoing carry.
    const int cin = carry_in;

    // sum   = a XOR b XOR carry_in
    // carry = MAJ(a, b, carry_in)
    int sum = cnf.new_var();
    if (cnf.dialect == EncodingDialect::Xor) {
        cnf.add_xor_constraint({a, b, cin, -sum}, true);
    } else {
        encode_xor3(cnf, a, b, cin, sum);
    }

    int cout_var = cnf.new_var();
    encode_maj(cnf, a, b, cin, cout_var);
    carry_out = cout_var;

    return sum;
}

std::vector<int> SatEncoder::encode_add32(CnfFormula& cnf, const std::vector<int>& a, const std::vector<int>& b) {
    std::vector<int> out = cnf.new_vars(32);
    // Literal 0 is not usable inside XOR constraints; start from a real
    // variable pinned to false.
    int carry = cnf.false_literal();

    for (size_t i = 0; i < 32; ++i) {
        int next_carry = 0;
        out[i] = encode_full_adder(cnf, a[i], b[i], carry, next_carry);
        carry = next_carry;
    }
    return out;
}

std::vector<int> SatEncoder::encode_add32_multi(
    CnfFormula& cnf, const std::vector<const std::vector<int>*>& addends) {
    if (addends.empty()) {
        return cnf.new_vars(32);
    }
    if (addends.size() == 1) {
        return *addends.front();
    }
    if (addends.size() == 2) {
        return encode_add32(cnf, *addends[0], *addends[1]);
    }

    // Carry-save reduction. Collapsing the addend bits at a position with XOR
    // would be WRONG: the column sum of several addends carries a multi-bit
    // weight (3 + 3 needs a carry of 2, not a single bit), so parity loses
    // information. Instead reduce with 3:2 compressors, which satisfy
    //     a + b + c  ==  sum + 2 * carry
    // exactly, and shift the compressor carry into the next column.
    //
    // Each column is reduced to at most two literals, leaving two rows that a
    // single ripple-carry adder finishes. This is what collapses SHA-256's
    // T1 = h + S1 + Ch + W + K from four serial adders into one pass.
    const int zero = cnf.false_literal();
    std::vector<std::vector<int>> columns(32);
    for (size_t i = 0; i < 32; ++i) {
        columns[i].reserve(addends.size() + 8);
        for (const auto* addend : addends) {
            columns[i].push_back((*addend)[i]);
        }
    }

    for (size_t i = 0; i < 32; ++i) {
        while (columns[i].size() > 2) {
            int a = columns[i][columns[i].size() - 3];
            int b = columns[i][columns[i].size() - 2];
            int c = columns[i][columns[i].size() - 1];
            columns[i].resize(columns[i].size() - 3);

            int sum = encode_parity3(cnf, a, b, c);
            int carry = cnf.new_var();
            encode_maj(cnf, a, b, c, carry);

            columns[i].push_back(sum);
            if (i + 1 < 32) {
                columns[i + 1].push_back(carry);
            }
            // A carry shifted out of bit 31 is discarded, matching mod 2^32.
        }
    }

    std::vector<int> row0(32), row1(32);
    for (size_t i = 0; i < 32; ++i) {
        row0[i] = columns[i].empty() ? zero : columns[i][0];
        row1[i] = columns[i].size() > 1 ? columns[i][1] : zero;
    }
    return encode_add32(cnf, row0, row1);
}

std::vector<int> SatEncoder::encode_add32_const(CnfFormula& cnf, const std::vector<int>& a, uint32_t constant) {
    // out = (a + constant) mod 2^32
    //
    // Per bit i:  sum_i   = a_i XOR c_i XOR carry_i
    //             carry_i+1 = MAJ(a_i, c_i, carry_i)
    //
    // When c_i is a known bit the cost collapses:
    //   c_i == 0 : sum = a XOR carry            ; carry' = a AND carry
    //   c_i == 1 : sum = NOT(a XOR carry)       ; carry' = a OR  carry
    // This avoids materialising a 32-variable constant word plus 32 unit
    // clauses, which is what the generic two-operand path would require.
    std::vector<int> out = cnf.new_vars(32);
    int carry = cnf.false_literal(); // pinned-false variable, not DIMACS literal 0

    for (size_t i = 0; i < 32; ++i) {
        const bool c_bit = ((constant >> i) & 1U) != 0;

        // parity = a_i XOR carry  (always a true-parity XOR constraint)
        int parity = encode_parity2(cnf, a[i], carry);

        if (c_bit) {
            // sum = NOT parity
            encode_not(cnf, parity, out[i]);
        } else {
            out[i] = parity;
        }

        if (i < 31) {
            int next_carry = cnf.new_var();
            if (c_bit) {
                encode_or2(cnf, a[i], carry, next_carry);   // MAJ(a, 1, carry)
            } else {
                encode_and2(cnf, a[i], carry, next_carry);  // MAJ(a, 0, carry)
            }
            carry = next_carry;
        }
    }
    return out;
}

void SatEncoder::fix_const32(CnfFormula& cnf, const std::vector<int>& vars, uint32_t val) {
    for (size_t i = 0; i < 32; ++i) {
        bool bit = ((val >> i) & 1U) != 0;
        if (bit) {
            cnf.add_unit(vars[i]);
        } else {
            cnf.add_unit(-vars[i]);
        }
    }
}

bool SatEncoder::substitute_const32(CnfFormula& cnf, std::vector<int>& word, uint32_t val) {
    // Bind every variable in `word` to the corresponding constant bit and
    // report whether the word can be replaced by a literal-only vector.
    fix_const32(cnf, word, val);
    (void)cnf;
    return true;
}

SatEncoder::Sha256SatEncoding SatEncoder::encode_reduced_rounds(const Sha256ProblemConfig& config) {
    if (config.num_rounds == 0 || config.num_rounds > 64) {
        throw std::invalid_argument("Invalid num_rounds: must be between 1 and 64");
    }
    Sha256SatEncoding enc;
    enc.dialect = config.dialect;
    enc.cnf.dialect = config.dialect;
    uint32_t rounds = config.num_rounds;

    // 1. Message variables W_0..W_{max(15, rounds-1)}
    uint32_t total_w = std::max(16U, rounds);
    enc.message_vars.resize(total_w);
    for (uint32_t i = 0; i < 16; ++i) {
        enc.message_vars[i] = enc.cnf.new_vars(32);
    }

    // Message schedule constraints W_t for t = 16..total_w-1
    for (uint32_t t = 16; t < total_w; ++t) {
        auto g1 = encode_gamma1(enc.cnf, enc.message_vars[t - 2]);
        auto g0 = encode_gamma0(enc.cnf, enc.message_vars[t - 15]);
        auto sum1 = encode_add32(enc.cnf, g1, enc.message_vars[t - 7]);
        auto sum2 = encode_add32(enc.cnf, g0, enc.message_vars[t - 16]);
        enc.message_vars[t] = encode_add32(enc.cnf, sum1, sum2);
    }

    // Optional: pin specific message words by index.
    for (const auto& [index, value] : config.fixed_words) {
        if (index >= 16 || index >= enc.message_vars.size()) continue;
        fix_const32(enc.cnf, enc.message_vars[index], value);
    }

    // 2. Initial state variables A_0..H_0
    std::vector<int> state_a = enc.cnf.new_vars(32);
    std::vector<int> state_b = enc.cnf.new_vars(32);
    std::vector<int> state_c = enc.cnf.new_vars(32);
    std::vector<int> state_d = enc.cnf.new_vars(32);
    std::vector<int> state_e = enc.cnf.new_vars(32);
    std::vector<int> state_f = enc.cnf.new_vars(32);
    std::vector<int> state_g = enc.cnf.new_vars(32);
    std::vector<int> state_h = enc.cnf.new_vars(32);

    Sha256State iv = config.use_standard_iv ? SHA256_IV : config.custom_iv;
    fix_const32(enc.cnf, state_a, iv[0]);
    fix_const32(enc.cnf, state_b, iv[1]);
    fix_const32(enc.cnf, state_c, iv[2]);
    fix_const32(enc.cnf, state_d, iv[3]);
    fix_const32(enc.cnf, state_e, iv[4]);
    fix_const32(enc.cnf, state_f, iv[5]);
    fix_const32(enc.cnf, state_g, iv[6]);
    fix_const32(enc.cnf, state_h, iv[7]);

    enc.state_a_vars.push_back(state_a);
    enc.state_e_vars.push_back(state_e);

    // 3. Round step function constraints
    for (uint32_t t = 0; t < rounds; ++t) {
        auto s1 = encode_sigma1(enc.cnf, state_e);
        auto ch_val = encode_ch32(enc.cnf, state_e, state_f, state_g);

        std::vector<int> t1;
        if (config.carry_save_t1) {
            // T1 = h + S1(e) + Ch(e,f,g) + W[t] + K[t]  in one carry chain.
            std::vector<int> k_const = enc.cnf.new_vars(32);
            fix_const32(enc.cnf, k_const, SHA256_K[t]);
            std::vector<const std::vector<int>*> addends = {
                &state_h, &s1, &ch_val, &enc.message_vars[t], &k_const
            };
            t1 = encode_add32_multi(enc.cnf, addends);
        } else {
            auto t1_part1 = encode_add32(enc.cnf, state_h, s1);
            auto t1_part2 = encode_add32(enc.cnf, ch_val, enc.message_vars[t]);
            auto t1_part3 = encode_add32_const(enc.cnf, t1_part1, SHA256_K[t]);
            t1 = encode_add32(enc.cnf, t1_part2, t1_part3);
        }

        auto s0 = encode_sigma0(enc.cnf, state_a);
        auto maj_val = encode_maj32(enc.cnf, state_a, state_b, state_c);
        auto t2 = encode_add32(enc.cnf, s0, maj_val);

        auto next_e = encode_add32(enc.cnf, state_d, t1);
        auto next_a = encode_add32(enc.cnf, t1, t2);

        state_h = state_g;
        state_g = state_f;
        state_f = state_e;
        state_e = next_e;
        state_d = state_c;
        state_c = state_b;
        state_b = state_a;
        state_a = next_a;

        enc.state_a_vars.push_back(state_a);
        enc.state_e_vars.push_back(state_e);
    }

    // 4. Output / Feedforward
    enc.final_digest_vars.resize(8);
    std::vector<std::vector<int>> working = {state_a, state_b, state_c, state_d, state_e, state_f, state_g, state_h};

    for (size_t i = 0; i < 8; ++i) {
        enc.final_digest_vars[i] = encode_add32_const(enc.cnf, working[i], iv[i]);
    }

    // 5. Target hash constraint (if specified)
    if (config.fix_target_digest) {
        for (size_t i = 0; i < 8; ++i) {
            uint32_t expected_w = load_be32(config.target_digest.bytes.data() + i * 4);
            fix_const32(enc.cnf, enc.final_digest_vars[i], expected_w);
        }
    }

    return enc;
}

std::vector<uint32_t> SatEncoder::extract_message_from_model(
    const std::map<int, bool>& model,
    const std::vector<std::vector<int>>& msg_vars)
{
    std::vector<uint32_t> words(16, 0);
    for (size_t w = 0; w < 16 && w < msg_vars.size(); ++w) {
        uint32_t val = 0;
        for (size_t b = 0; b < 32; ++b) {
            int var = msg_vars[w][b];
            auto it = model.find(var);
            if (it != model.end() && it->second) {
                val |= (1U << b);
            }
        }
        words[w] = val;
    }
    return words;
}

} // namespace sha256_research