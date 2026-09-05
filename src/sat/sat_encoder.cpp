#include "sha256_research/sat/sat_encoder.hpp"
#include <fstream>
#include <sstream>

namespace sha256_research {

std::string CnfFormula::to_dimacs() const {
    std::ostringstream oss;
    oss << "p cnf " << num_vars << " " << clauses.size() << "\n";
    for (const auto& cl : clauses) {
        for (int lit : cl) {
            oss << lit << " ";
        }
        oss << "0\n";
    }
    return oss.str();
}

bool CnfFormula::write_dimacs_file(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return false;
    out << "c SHA-256 Cryptanalysis CNF formula\n";
    out << "p cnf " << num_vars << " " << clauses.size() << "\n";
    for (const auto& cl : clauses) {
        for (int lit : cl) {
            out << lit << " ";
        }
        out << "0\n";
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
    std::vector<int> res(32);
    // Constant 0 literal
    int zero_var = cnf.new_var();
    cnf.add_clause({-zero_var}); // fixed to false

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
        encode_xor3(cnf, r2[i], r13[i], r22[i], out[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_sigma1(CnfFormula& cnf, const std::vector<int>& x) {
    auto r6 = rotate_right(x, 6);
    auto r11 = rotate_right(x, 11);
    auto r25 = rotate_right(x, 25);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        encode_xor3(cnf, r6[i], r11[i], r25[i], out[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_gamma0(CnfFormula& cnf, const std::vector<int>& x) {
    auto r7 = rotate_right(x, 7);
    auto r18 = rotate_right(x, 18);
    auto s3 = shift_right(cnf, x, 3);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        encode_xor3(cnf, r7[i], r18[i], s3[i], out[i]);
    }
    return out;
}

std::vector<int> SatEncoder::encode_gamma1(CnfFormula& cnf, const std::vector<int>& x) {
    auto r17 = rotate_right(x, 17);
    auto r19 = rotate_right(x, 19);
    auto s10 = shift_right(cnf, x, 10);
    std::vector<int> out = cnf.new_vars(32);
    for (size_t i = 0; i < 32; ++i) {
        encode_xor3(cnf, r17[i], r19[i], s10[i], out[i]);
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

std::vector<int> SatEncoder::encode_add32(CnfFormula& cnf, const std::vector<int>& a, const std::vector<int>& b) {
    std::vector<int> sum = cnf.new_vars(32);
    int carry = 0;

    for (size_t i = 0; i < 32; ++i) {
        if (i == 0) {
            // First bit has carry_in = 0
            encode_xor2(cnf, a[0], b[0], sum[0]);
            carry = cnf.new_var();
            encode_and2(cnf, a[0], b[0], carry);
        } else {
            encode_xor3(cnf, a[i], b[i], carry, sum[i]);
            if (i < 31) {
                int next_carry = cnf.new_var();
                encode_maj(cnf, a[i], b[i], carry, next_carry);
                carry = next_carry;
            }
        }
    }
    return sum;
}

std::vector<int> SatEncoder::encode_add32_const(CnfFormula& cnf, const std::vector<int>& a, uint32_t constant) {
    std::vector<int> b = cnf.new_vars(32);
    fix_const32(cnf, b, constant);
    return encode_add32(cnf, a, b);
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

SatEncoder::Sha256SatEncoding SatEncoder::encode_reduced_rounds(const Sha256ProblemConfig& config) {
    Sha256SatEncoding enc;
    uint32_t rounds = std::min(config.num_rounds, 64U);

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

    // Optional: fix specific message words
    for (size_t i = 0; i < config.fixed_message_words.size() && i < 16; ++i) {
        fix_const32(enc.cnf, enc.message_vars[i], config.fixed_message_words[i]);
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
        auto t1_part1 = encode_add32(enc.cnf, state_h, s1);
        auto t1_part2 = encode_add32(enc.cnf, ch_val, enc.message_vars[t]);
        auto t1_part3 = encode_add32_const(enc.cnf, t1_part1, SHA256_K[t]);
        auto t1 = encode_add32(enc.cnf, t1_part2, t1_part3);

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
    auto initial_iv_vars = {iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]};
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
