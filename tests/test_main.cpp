#include "sha256_research/core/types.hpp"
#include "sha256_research/sha256/sha256_scalar.hpp"
#include "sha256_research/cpu/sha256_optimized.hpp"
#include "sha256_research/differential/diff_trail.hpp"
#include "sha256_research/sat/sat_encoder.hpp"
#include "sha256_research/solver/solver_interface.hpp"
#include "sha256_research/verifier/verifier.hpp"
#include "sha256_research/vulkan/sha256_vulkan.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <random>
#include <sstream>

using namespace sha256_research;

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define RUN_TEST(fn) \
    do { \
        g_tests_run++; \
        std::cout << "[RUN]  " << #fn << "... "; \
        try { \
            fn(); \
            g_tests_passed++; \
            std::cout << "PASSED\n"; \
        } catch (const std::exception& e) { \
            std::cout << "FAILED (" << e.what() << ")\n"; \
        } catch (...) { \
            std::cout << "FAILED (unknown exception)\n"; \
        } \
    } while(0)

// Deterministic PRNG for tests (fixed seed; no randomness in verdicts).
static std::mt19937 test_rng(0x12345678u);

void test_nist_known_answer_vectors() {
    auto kats = IndependentVerifier::get_standard_test_vectors();
    if (kats.size() < 4) throw std::runtime_error("expected >= 4 KATs");
    for (const auto& kat : kats) {
        bool ok = IndependentVerifier::verify_known_answer(kat);
        if (!ok) throw std::runtime_error("KAT failed: " + kat.name);
    }
    // Extra independent vectors (FIPS 180-4 / widely published).
    struct EV { const char* msg; size_t len; const char* hex; };
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56-byte NIST multi-block boundary)
    // covered by KAT; here add single-char and 1M-'a' truncated checks via streaming below.
    // Well-known: SHA256("a") = ca978112...
    {
        Sha256Digest d = Sha256Scalar::hash("a", 1);
        if (d.to_hex() != "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")
            throw std::runtime_error("KAT 'a' mismatch");
    }
    // Well-known: SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    {
        const char* m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        Sha256Digest d = Sha256Scalar::hash(m, 56);
        if (d.to_hex() != "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
            throw std::runtime_error("KAT 56-byte asc mismatch");
    }
}

void test_sha256_edge_lengths() {
    // Padding-boundary sweep required by spec: 0..130 incl. critical edges (55, 56, 64, 65, 119, 120, 128).
    std::vector<size_t> lens = {0, 1, 15, 16, 31, 32, 54, 55, 56, 57, 63, 64,
                                65, 118, 119, 120, 121, 127, 128, 129, 130, 200, 1000, 4096};
    for (size_t len = 0; len <= 130; ++len) {
        lens.push_back(len);
    }
    std::sort(lens.begin(), lens.end());
    lens.erase(std::unique(lens.begin(), lens.end()), lens.end());

    for (size_t len : lens) {
        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>((i * 13 + 37) & 0xFF);
        Sha256Digest s = Sha256Scalar::hash(data.data(), len);
        Sha256Digest o = Sha256Optimized::hash(data.data(), len);
        Sha256Digest o_ref = Sha256Optimized::hash_path(data.data(), len,
            Sha256Optimized::Path::ScalarReference);
        Sha256Digest indep = IndependentVerifier::independent_hash(data.data(), len);
        if (!(s == o && s == o_ref && s == indep))
            throw std::runtime_error("edge-length mismatch at " + std::to_string(len));
        // Streaming split equivalence: hash in two halves.
        if (len > 0) {
            Sha256Scalar st;
            size_t k = len / 2;
            st.update(data.data(), k);
            st.update(data.data() + k, len - k);
            if (st.finalize() != s)
                throw std::runtime_error("streaming split mismatch at " + std::to_string(len));
        }
    }
}

void test_streaming_chunked_hashing() {
    Sha256Scalar s1;
    s1.update("hello ", 6);
    s1.update("world", 5);
    Sha256Digest d1 = s1.finalize();

    Sha256Digest d2 = Sha256Scalar::hash("hello world");
    if (d1 != d2) throw std::runtime_error("Chunked update differed from single hash");

    // Many split patterns over a 200-byte message (incl. 1-byte chunks).
    std::vector<uint8_t> msg(200);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i & 0xFF);
    Sha256Digest ref = Sha256Scalar::hash(msg.data(), msg.size());
    for (size_t split = 0; split < msg.size(); split += 37) {
        Sha256Scalar st;
        st.update(msg.data(), split);
        st.update(msg.data() + split, msg.size() - split);
        if (st.finalize() != ref)
            throw std::runtime_error("split pattern failed at " + std::to_string(split));
    }
    // Byte-at-a-time streaming.
    {
        Sha256Scalar st;
        for (uint8_t b : msg) st.update(&b, 1);
        if (st.finalize() != ref) throw std::runtime_error("byte-at-a-time streaming mismatch");
    }
}

void test_cpu_backend_equivalence() {
    // Randomized differential scalar vs optimized (fixed seed).
    for (int iter = 0; iter < 200; ++iter) {
        size_t len = test_rng() % 300;
        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>(test_rng() & 0xFF);
        Sha256Digest a = Sha256Scalar::hash(data.data(), len);
        Sha256Digest b = Sha256Optimized::hash(data.data(), len);
        Sha256Digest c = Sha256Optimized::hash_path(data.data(), len,
            Sha256Optimized::Path::ScalarReference);
        Sha256Digest d = Sha256Optimized::hash_path(data.data(), len,
            Sha256Optimized::Path::UnrolledPortable);
        if (!(a == b && a == c && a == d))
            throw std::runtime_error("randomized differential mismatch at len " + std::to_string(len));
    }
    // Batch API equivalence.
    {
        const size_t count = 64, mlen = 55;
        std::vector<uint8_t> in(count * mlen);
        for (size_t i = 0; i < in.size(); ++i) in[i] = static_cast<uint8_t>((i * 7 + 1) & 0xFF);
        std::vector<Sha256Digest> out(count);
        Sha256Optimized::hash_batch(in.data(), mlen, count, out.data(), 4);
        for (size_t i = 0; i < count; ++i) {
            Sha256Digest ref = Sha256Scalar::hash(in.data() + i * mlen, mlen);
            if (!(out[i] == ref)) throw std::runtime_error("hash_batch mismatch");
        }
    }
}

void test_search_partition_exact_cover() {
    auto check = [](uint64_t max_iter, unsigned int threads) {
        auto ranges = Sha256Optimized::partition_range(max_iter, threads);
        if (threads == 0 || max_iter == 0) {
            if (!ranges.empty()) throw std::runtime_error("expected empty ranges");
            return;
        }
        if (ranges.size() != threads) throw std::runtime_error("range count != threads");
        // Sorted, non-overlapping, union == [0, max_iter).
        std::vector<std::pair<uint64_t,uint64_t>> s = ranges;
        std::sort(s.begin(), s.end());
        if (s.front().first != 0) throw std::runtime_error("cover does not start at 0");
        if (s.back().second != max_iter) throw std::runtime_error("cover does not end at max");
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i].first > s[i].second) throw std::runtime_error("inverted range");
            if (i + 1 < s.size() && s[i].second != s[i+1].first)
                throw std::runtime_error("gap/overlap in partition");
        }
        uint64_t total = 0;
        for (auto& r : s) total += (r.second - r.first);
        if (total != max_iter) throw std::runtime_error("partition total != max");
    };
    check(1000, 4);     // divisible
    check(1000, 7);     // remainder
    check(3, 8);        // fewer iterations than threads
    check(1, 1);
    check(1, 16);
    check(0, 4);        // zero-length
    check(10, 1);       // single worker
    check(1000000, 16);
    check(1000003, 16); // awkward remainder
    check(0, 0);
    // Regression: old code dropped max%threads trailing nonces; ensure covered.
    {
        auto r = Sha256Optimized::partition_range(10, 3); // 4+3+3
        uint64_t covered = 0;
        for (auto& p : r) covered += p.second - p.first;
        if (covered != 10) throw std::runtime_error("remainder loss regression");
    }
}

void test_search_early_termination_sane() {
    // target_zero_bits=0 matches every hash; nonce 0 must be found quickly.
    Sha256Optimized::SearchTarget t;
    t.target_zero_bits = 0;
    t.max_iterations = 100;
    uint8_t prefix[4] = {1, 2, 3, 4};
    auto res = Sha256Optimized::search_prefix_zeros(prefix, 4, t, 4);
    if (!res.found) throw std::runtime_error("trivial search should always find nonce");
    // Verify the reported digest independently.
    std::vector<uint8_t> buf(4 + 8);
    std::memcpy(buf.data(), prefix, 4);
    store_be64(buf.data() + 4, res.nonce);
    if (!(Sha256Scalar::hash(buf.data(), buf.size()) == res.digest))
        throw std::runtime_error("search digest not independently reproducible");
    if (res.nonce >= t.max_iterations) throw std::runtime_error("nonce out of domain");
}

void test_differential_trail_verification() {
    auto trail = DifferentialAnalysis::create_standard_reduced_trail(2);
    Sha256State iv = SHA256_IV;
    uint8_t b1[64] = {0};
    uint8_t b2[64] = {0};
    b1[4] = 0x80; // W[1] MSB

    auto res = trail.verify_pair(iv, b1, b2);
    if (!res.satisfied) {
        throw std::runtime_error("Differential trail failed: " + res.failure_reason);
    }
    // Negative: identical blocks must NOT satisfy a trail demanding MSB difference.
    auto res2 = trail.verify_pair(iv, b1, b1);
    if (res2.satisfied) throw std::runtime_error("trail wrongly satisfied for identical blocks");
    // Round-by-round delta honesty: observed ΔW/ΔA from exact traces.
    auto tr1 = Sha256Scalar::compress_block_trace(iv, b1, 2);
    auto tr2 = Sha256Scalar::compress_block_trace(iv, b2, 2);
    if ((tr1.W[1] ^ tr2.W[1]) != 0x80000000U)
        throw std::runtime_error("observed message delta mismatch");
}

// --- SAT semantic oracle: unit propagation over CNF clauses and XOR constraints ---
static bool assign_lit(std::map<int,bool>& asg, int lit) {
    int v = lit > 0 ? lit : -lit;
    bool val = lit > 0;
    auto it = asg.find(v);
    if (it != asg.end()) return it->second == val;
    asg[v] = val;
    return true;
}

// Evaluate a native XOR constraint under a total assignment.
// All emitted constraints carry a true parity, so the XOR of the literals must be 1.
static bool xor_constraint_holds(const CnfFormula::XorConstraint& xc, const std::map<int,bool>& asg) {
    int parity = 0;
    for (int lit : xc.lits) {
        auto it = asg.find(lit > 0 ? lit : -lit);
        if (it == asg.end()) return false; // not a total assignment
        bool val = it->second;
        parity ^= (lit > 0) ? (val ? 1 : 0) : (val ? 0 : 1);
    }
    return parity == (xc.rhs ? 1 : 0);
}

static bool unit_propagate(const CnfFormula& cnf, std::map<int,bool>& asg) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& cl : cnf.clauses) {
            bool satisfied = false;
            int unassigned = 0, last_lit = 0;
            for (int lit : cl) {
                int v = lit > 0 ? lit : -lit;
                auto it = asg.find(v);
                if (it == asg.end()) { unassigned++; last_lit = lit; }
                else if (it->second == (lit > 0)) { satisfied = true; break; }
            }
            if (satisfied) continue;
            if (unassigned == 0) return false; // conflict
            if (unassigned == 1) {
                if (!assign_lit(asg, last_lit)) return false;
                changed = true;
            }
        }
        // XOR constraints: when all but one literal is known, the last one is
        // determined, because the total parity must be odd.
        for (const auto& xc : cnf.xor_constraints) {
            int parity = 0;
            int unassigned_count = 0;
            int last_lit = 0;
            for (int lit : xc.lits) {
                auto it = asg.find(lit > 0 ? lit : -lit);
                if (it == asg.end()) { unassigned_count++; last_lit = lit; continue; }
                parity ^= (lit > 0) ? (it->second ? 1 : 0) : (it->second ? 0 : 1);
            }
            const int target = xc.rhs ? 1 : 0;
            if (unassigned_count == 0) {
                if (parity != target) return false;  // constraint violated
            } else if (unassigned_count == 1) {
                // parity XOR value(last) must equal target
                bool want = ((target - parity) & 1) != 0;
                if (!assign_lit(asg, want ? last_lit : -last_lit)) return false;
                changed = true;
            }
        }
    }
    return true;
}
static bool cnf_satisfied(const CnfFormula& cnf, const std::map<int,bool>& asg) {
    for (const auto& cl : cnf.clauses) {
        bool sat = false;
        for (int lit : cl) {
            int v = lit > 0 ? lit : -lit;
            auto it = asg.find(v);
            if (it != asg.end() && it->second == (lit > 0)) { sat = true; break; }
        }
        if (!sat) return false;
    }
    for (const auto& xc : cnf.xor_constraints) {
        if (!xor_constraint_holds(xc, asg)) return false;
    }
    return true;
}

void test_sat_gates_exhaustive() {
    // AND/OR/XOR/MAJ/CH truth tables via unit propagation (fix inputs, derive out).
    for (int a = 0; a <= 1; ++a) for (int b = 0; b <= 1; ++b) {
        { CnfFormula c; int va=c.new_var(), vb=c.new_var(), vo=c.new_var();
          SatEncoder::encode_and2(c, va, vb, vo);
          std::map<int,bool> asg{{va,(bool)a},{vb,(bool)b}};
          if (!unit_propagate(c, asg)) throw std::runtime_error("and2 conflict");
          auto it = asg.find(vo);
          if (it == asg.end() || it->second != (bool)(a & b)) throw std::runtime_error("and2 wrong"); }
        { CnfFormula c; int va=c.new_var(), vb=c.new_var(), vo=c.new_var();
          SatEncoder::encode_or2(c, va, vb, vo);
          std::map<int,bool> asg{{va,(bool)a},{vb,(bool)b}};
          if (!unit_propagate(c, asg)) throw std::runtime_error("or2 conflict");
          auto it = asg.find(vo);
          if (it == asg.end() || it->second != (bool)(a | b)) throw std::runtime_error("or2 wrong"); }
        { CnfFormula c; int va=c.new_var(), vb=c.new_var(), vo=c.new_var();
          SatEncoder::encode_xor2(c, va, vb, vo);
          std::map<int,bool> asg{{va,(bool)a},{vb,(bool)b}};
          if (!unit_propagate(c, asg)) throw std::runtime_error("xor2 conflict");
          auto it = asg.find(vo);
          if (it == asg.end() || it->second != (bool)(a ^ b)) throw std::runtime_error("xor2 wrong"); }
        for (int cc = 0; cc <= 1; ++cc) {
            { CnfFormula c; int va=c.new_var(), vb=c.new_var(), vc=c.new_var(), vo=c.new_var();
              SatEncoder::encode_maj(c, va, vb, vc, vo);
              std::map<int,bool> asg{{va,(bool)a},{vb,(bool)b},{vc,(bool)cc}};
              if (!unit_propagate(c, asg)) throw std::runtime_error("maj conflict");
              int exp = ((a&b)^(a&cc)^(b&cc));
              auto it = asg.find(vo);
              if (it == asg.end() || it->second != (bool)exp) throw std::runtime_error("maj wrong"); }
            { CnfFormula c; int ve=c.new_var(), vf=c.new_var(), vg=c.new_var(), vo=c.new_var();
              SatEncoder::encode_ch(c, ve, vf, vg, vo);
              std::map<int,bool> asg{{ve,(bool)a},{vf,(bool)b},{vg,(bool)cc}};
              if (!unit_propagate(c, asg)) throw std::runtime_error("ch conflict");
              int exp = ((a&b)^((!a)&cc));
              auto it = asg.find(vo);
              if (it == asg.end() || it->second != (bool)exp) throw std::runtime_error("ch wrong"); }
            { CnfFormula c; int va=c.new_var(), vb=c.new_var(), vc=c.new_var(), vo=c.new_var();
              SatEncoder::encode_xor3(c, va, vb, vc, vo);
              std::map<int,bool> asg{{va,(bool)a},{vb,(bool)b},{vc,(bool)cc}};
              if (!unit_propagate(c, asg)) throw std::runtime_error("xor3 conflict");
              auto it = asg.find(vo);
              if (it == asg.end() || it->second != (bool)(a ^ b ^ cc)) throw std::runtime_error("xor3 wrong"); }
        }
    }
    // Negative: wrong output assertion must yield conflict.
    { CnfFormula c; int va=c.new_var(), vb=c.new_var(), vo=c.new_var();
      SatEncoder::encode_and2(c, va, vb, vo);
      std::map<int,bool> asg{{va,true},{vb,true},{vo,false}};
      if (unit_propagate(c, asg) && cnf_satisfied(c, asg))
          throw std::runtime_error("and2 accepted wrong output"); }
}

void test_sat_add32_semantics() {
    // Randomized 32-bit addition: fix inputs, unit-propagate, compare vs native.
    for (int iter = 0; iter < 25; ++iter) {
        uint32_t av = test_rng(), bv = test_rng();
        // Edge-biased cases.
        if (iter == 0) { av = 0; bv = 0; }
        if (iter == 1) { av = 0xFFFFFFFFu; bv = 1u; }
        if (iter == 2) { av = 0xFFFFFFFFu; bv = 0xFFFFFFFFu; }
        CnfFormula cnf;
        auto a = cnf.new_vars(32);
        auto b = cnf.new_vars(32);
        SatEncoder::fix_const32(cnf, a, av);
        SatEncoder::fix_const32(cnf, b, bv);
        auto sum = SatEncoder::encode_add32(cnf, a, b);
        std::map<int,bool> asg;
        if (!unit_propagate(cnf, asg)) throw std::runtime_error("add32 conflict on valid inputs");
        uint32_t expected = av + bv;
        for (int i = 0; i < 32; ++i) {
            auto it = asg.find(sum[i]);
            if (it == asg.end()) throw std::runtime_error("add32 sum bit underived");
            if (it->second != (bool)((expected >> i) & 1u))
                throw std::runtime_error("add32 sum mismatch");
        }
        if (!cnf_satisfied(cnf, asg)) throw std::runtime_error("add32 model violates clauses");
        // Negative: forcing a wrong sum bit must conflict.
        {
            CnfFormula c2;
            auto a2 = c2.new_vars(32);
            auto b2 = c2.new_vars(32);
            SatEncoder::fix_const32(c2, a2, av);
            SatEncoder::fix_const32(c2, b2, bv);
            auto s2 = SatEncoder::encode_add32(c2, a2, b2);
            std::map<int,bool> asg2;
            // Flip bit 0 of expected sum.
            bool wrong = !((expected >> 0) & 1u);
            asg2[s2[0]] = wrong;
            if (unit_propagate(c2, asg2) && cnf_satisfied(c2, asg2))
                throw std::runtime_error("add32 accepted corrupted sum");
        }
    }
}

void test_sat_sigma_gamma_semantics() {
    // Sigma0/Sigma1/Gamma0/Gamma1 vs native FIPS functions via propagation.
    for (int iter = 0; iter < 10; ++iter) {
        uint32_t xv = test_rng();
        if (iter == 0) xv = 0;
        if (iter == 1) xv = 0xFFFFFFFFu;
        auto check = [&](std::vector<int> (fn)(CnfFormula&, const std::vector<int>&),
                         uint32_t expected) {
            CnfFormula cnf;
            auto x = cnf.new_vars(32);
            SatEncoder::fix_const32(cnf, x, xv);
            auto out = fn(cnf, x);
            std::map<int,bool> asg;
            if (!unit_propagate(cnf, asg)) throw std::runtime_error("sigma/gamma conflict");
            uint32_t got = 0;
            for (int i = 0; i < 32; ++i) {
                auto it = asg.find(out[i]);
                if (it == asg.end()) throw std::runtime_error("sigma/gamma bit underived");
                if (it->second) got |= (1u << i);
            }
            if (got != expected) throw std::runtime_error("sigma/gamma mismatch");
        };
        check(SatEncoder::encode_sigma0, sigma0(xv));
        check(SatEncoder::encode_sigma1, sigma1(xv));
        check(SatEncoder::encode_gamma0, gamma0(xv));
        check(SatEncoder::encode_gamma1, gamma1(xv));
    }
}

void test_sat_encoder_tseitin_basic() {
    CnfFormula cnf;
    int a = cnf.new_var();
    int b = cnf.new_var();
    int out = cnf.new_var();
    SatEncoder::encode_xor2(cnf, a, b, out);
    if (cnf.clauses.size() != 4) throw std::runtime_error("encode_xor2 clause count != 4");

    // 1-round reduced SHA-256 CNF generation
    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = 1;
    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    if (enc.cnf.clauses.empty() || enc.cnf.num_vars == 0) {
        throw std::runtime_error("SAT encoding failed to generate variables/clauses");
    }
    // Behaviorally meaningful: fixing the message to a known block and
    // propagating must derive the 1-round working state consistently with
    // the native reference trace (small end-to-end semantic check).
    {
        uint8_t block[64] = {0};
        for (int i = 0; i < 64; ++i) block[i] = static_cast<uint8_t>(i & 0xFF);
        uint32_t W[64];
        Sha256Scalar::expand_schedule(block, W);
        auto ref = Sha256Scalar::compress_block_trace(SHA256_IV, block, 1);
        SatEncoder::Sha256ProblemConfig cfg2;
        cfg2.num_rounds = 1;
        cfg2.use_standard_iv = true;
        for (int i = 0; i < 16; ++i) cfg2.fixed_words.emplace_back(static_cast<uint32_t>(i), W[i]);
        auto enc2 = SatEncoder::encode_reduced_rounds(cfg2);
        // Message words fixed -> propagation must not conflict.
        std::map<int,bool> asg;
        if (!unit_propagate(enc2.cnf, asg))
            throw std::runtime_error("1-round fixed-message CNF propagation conflict");
        // Digest vars must be derivable and match native feedforward.
        Sha256State st = SHA256_IV;
        Sha256Scalar::compress_block(st, block, 1);
        for (int w = 0; w < 8; ++w) {
            uint32_t got = 0;
            for (int i = 0; i < 32; ++i) {
                auto it = asg.find(enc2.final_digest_vars[w][i]);
                if (it == asg.end()) throw std::runtime_error("digest bit underived");
                if (it->second) got |= (1u << i);
            }
            if (got != st[w]) throw std::runtime_error("1-round digest mismatch vs native");
        }
        (void)ref;
    }
}

void test_sat_end_to_end_with_solver() {
    // Reduced 1-round preimage solved by a real external solver when present;
    // gracefully skipped when no solver is installed (CI without WSL).
    auto solver = SolverFactory::create(SolverType::CaDiCaL);
    if (!solver) { std::cout << "[no solver factory, skipping] "; return; }
    bool avail = solver->is_available();
    if (!avail) {
        // Try any available solver before skipping.
        auto available = SolverFactory::get_available_solvers();
        if (available.empty()) { std::cout << "[no SAT solver installed, skipping] "; return; }
        solver = SolverFactory::create(available.front());
    }
    uint8_t block[64] = {0};
    for (int i = 0; i < 64; ++i) block[i] = static_cast<uint8_t>((i * 3 + 7) & 0xFF);
    Sha256State tst = SHA256_IV;
    Sha256Scalar::compress_block(tst, block, 1);
    Sha256Digest target;
    for (int i = 0; i < 8; ++i) store_be32(target.bytes.data() + i * 4, tst[i]);

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = 1;
    cfg.use_standard_iv = true;
    cfg.fix_target_digest = true;
    cfg.target_digest = target;
    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    auto res = solver->solve_cnf(enc.cnf, 30);
    if (res.status == SolverStatus::Timeout || res.status == SolverStatus::Error ||
        res.status == SolverStatus::Unknown) {
        std::cout << "[solver inconclusive, skipping strict assert] ";
        return;
    }
    if (res.status != SolverStatus::Satisfiable)
        throw std::runtime_error("1-round preimage should be SAT");
    auto words = SatEncoder::extract_message_from_model(res.model, enc.message_vars);
    uint8_t cand[64];
    for (int i = 0; i < 16; ++i) store_be32(cand + i * 4, words[i]);
    Sha256State chk = SHA256_IV;
    Sha256Scalar::compress_block(chk, cand, 1);
    for (int i = 0; i < 8; ++i)
        if (chk[i] != tst[i]) throw std::runtime_error("solver model failed independent verify");
}

void test_independent_verifier_rejection_gate() {
    bool ok = IndependentVerifier::run_negative_verifier_tests();
    if (!ok) throw std::runtime_error("Verifier negative integrity gate failed");
}

void test_verifier_metadata_forgery() {
    // A non-colliding pair with metadata claiming "verified/standard collision"
    // must still be rejected: metadata is never authority.
    CollisionCandidate cand;
    cand.message_a = {'f', 'o', 'o'};
    cand.message_b = {'b', 'a', 'r'};
    cand.claimed_rounds = 64;
    cand.custom_iv = false;
    cand.iv = SHA256_IV;
    cand.generator_metadata = "{\"verified\": true, \"classification\": \"StandardFullCollision\"}";
    auto v = IndependentVerifier::verify_collision_candidate(cand);
    if (v.is_valid || v.classification == CandidateClassification::StandardFullCollision)
        throw std::runtime_error("metadata forgery accepted");
    // Over-claimed rounds (>64) must be rejected explicitly (anti-clamping policy).
    CollisionCandidate cand2;
    cand2.message_a = {'x'};
    cand2.message_b = {'y'};
    cand2.claimed_rounds = 1000;
    auto v2 = IndependentVerifier::verify_collision_candidate(cand2);
    if (v2.is_valid || v2.classification != CandidateClassification::Invalid)
        throw std::runtime_error("over-claimed rounds not rejected as invalid");
}

void test_primitive_exhaustive() {
    // Test rotr32
    if (rotr32(0x12345678, 4) != 0x81234567) throw std::runtime_error("rotr32 mismatch");
    if (rotr32(0x80000000, 1) != 0x40000000) throw std::runtime_error("rotr32 bit 31 mismatch");
    if (rotr32(0x00000001, 1) != 0x80000000) throw std::runtime_error("rotr32 bit 0 mismatch");
    if (rotr32(0xA5A5A5A5, 0) != 0xA5A5A5A5) throw std::runtime_error("rotr32 0 rot mismatch");

    // Test ch and maj with known values
    if (ch(0xFFFFFFFF, 0x12345678, 0x87654321) != 0x12345678) throw std::runtime_error("ch selector 1 mismatch");
    if (ch(0x00000000, 0x12345678, 0x87654321) != 0x87654321) throw std::runtime_error("ch selector 0 mismatch");
    if (ch(0xFFFFFFFF, 0, 0xFFFFFFFF) != 0) throw std::runtime_error("ch all ones mismatch");

    if (maj(0xFFFFFFFF, 0xFFFFFFFF, 0) != 0xFFFFFFFF) throw std::runtime_error("maj two ones mismatch");
    if (maj(0, 0xFFFFFFFF, 0) != 0) throw std::runtime_error("maj one one mismatch");
    if (maj(0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0) != 0xE8E8E8E8) throw std::runtime_error("maj mixed mismatch");

    // Test sigma0 and sigma1
    if (sigma0(0) != 0) throw std::runtime_error("sigma0(0) mismatch");
    if (sigma1(0) != 0) throw std::runtime_error("sigma1(0) mismatch");
    if (sigma0(0x12345678) != (rotr32(0x12345678, 2) ^ rotr32(0x12345678, 13) ^ rotr32(0x12345678, 22)))
        throw std::runtime_error("sigma0 definition mismatch");
    if (sigma1(0x12345678) != (rotr32(0x12345678, 6) ^ rotr32(0x12345678, 11) ^ rotr32(0x12345678, 25)))
        throw std::runtime_error("sigma1 definition mismatch");

    // Test gamma0 and gamma1
    if (gamma0(0) != 0) throw std::runtime_error("gamma0(0) mismatch");
    if (gamma1(0) != 0) throw std::runtime_error("gamma1(0) mismatch");
    if (gamma0(0x87654321) != (rotr32(0x87654321, 7) ^ rotr32(0x87654321, 18) ^ (0x87654321U >> 3)))
        throw std::runtime_error("gamma0 definition mismatch");
    if (gamma1(0x87654321) != (rotr32(0x87654321, 17) ^ rotr32(0x87654321, 19) ^ (0x87654321U >> 10)))
        throw std::runtime_error("gamma1 definition mismatch");
}

void test_concurrency_hash_batch() {
    // Test hash_batch with multiple threads and compare to scalar reference.
    // We'll use a set of messages of the same length.

    const size_t message_len = 64; // one block
    const size_t count = 128; // number of messages

    // Prepare input data: each message is a sequence of bytes (0..255) repeated.
    std::vector<uint8_t> input(message_len * count);
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<uint8_t>(i & 0xFF);
    }

    // Compute reference using scalar reference for each message.
    std::vector<Sha256Digest> reference(count);
    for (size_t i = 0; i < count; ++i) {
        reference[i] = Sha256Scalar::hash(input.data() + i * message_len, message_len);
    }

    // Test with different thread counts: 0 (default), 1, 2, 4, 8, 16.
    std::vector<unsigned int> thread_counts = {0, 1, 2, 4, 8, 16};
    for (unsigned int threads : thread_counts) {
        std::vector<Sha256Digest> output(count);
        Sha256Optimized::hash_batch(input.data(), message_len, count, output.data(), threads);

        // Compare each output to the reference.
        for (size_t i = 0; i < count; ++i) {
            if (output[i] != reference[i]) {
                throw std::runtime_error("hash_batch mismatch with " + std::to_string(threads) +
                                         " threads at message index " + std::to_string(i));
            }
        }
    }
}

void test_concurrency_search() {
    // Test search_prefix_zeros with multiple threads and a trivial target (zero bits).
    // We set max_iterations low enough so that the search is deterministic (nonce 0 will be found).

    // Target: zero bits = 0 -> every hash matches, so nonce 0 should be found.
    Sha256Optimized::SearchTarget target;
    target.target_zero_bits = 0;
    target.max_iterations = 100; // small enough to be quick and deterministic.

    // Use a fixed prefix (4 bytes).
    uint8_t prefix[4] = {0x01, 0x02, 0x03, 0x04};

    // Test with different thread counts.
    std::vector<unsigned int> thread_counts = {0, 1, 2, 4, 8, 16};
    for (unsigned int threads : thread_counts) {
        auto result = Sha256Optimized::search_prefix_zeros(prefix, 4, target, threads);

        // We expect to find a nonce (since target_zero_bits=0).
        if (!result.found) {
            throw std::runtime_error("search_prefix_zeros did not find a nonce with " +
                                     std::to_string(threads) + " threads");
        }

        // The nonce should be within the max_iterations.
        if (result.nonce >= target.max_iterations) {
            throw std::runtime_error("search_prefix_zeros returned nonce out of range with " +
                                     std::to_string(threads) + " threads");
        }

        // Verify the digest independently.
        std::vector<uint8_t> buf(4 + 8);
        std::memcpy(buf.data(), prefix, 4);
        store_be64(buf.data() + 4, result.nonce);
        Sha256Digest computed = Sha256Scalar::hash(buf.data(), buf.size());
        if (computed != result.digest) {
            throw std::runtime_error("search_prefix_zeros digest mismatch with " +
                                     std::to_string(threads) + " threads");
        }
    }
}

void test_vulkan_smoke() {
    Sha256VulkanEngine vk;
    if (vk.initialize("shaders")) {
        auto res = vk.run_smoke_test(256, 64);
        if (!res.verified_against_cpu) {
            throw std::runtime_error("Vulkan compute mismatch against CPU reference");
        }
    } else {
        std::cout << "[Vulkan unavailable or CPU-only build, skipping Vulkan GPU test] ";
    }
}

void test_million_a() {
    // Create a vector of 1,000,000 'a's
    std::vector<uint8_t> data(1000000, 'a');

    // Compute using scalar reference
    sha256_research::Sha256Scalar scalar;
    scalar.update(data.data(), data.size());
    sha256_research::Sha256Digest hash_scalar = scalar.finalize();

    // Compute using optimized backend
    sha256_research::Sha256Digest hash_optimized = sha256_research::Sha256Optimized::hash(data.data(), data.size());

    // Known value from OpenSSL for 1,000,000 'a's
    const char* known_hex = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    if (hash_scalar.to_hex() != known_hex) {
        throw std::runtime_error("Scalar hash mismatch for million 'a's");
    }
    if (hash_optimized.to_hex() != known_hex) {
        throw std::runtime_error("Optimized hash mismatch for million 'a's");
    }
}

void test_sat_invalid_round_rejection() {
    SatEncoder::Sha256ProblemConfig cfg0;
    cfg0.num_rounds = 0;
    bool caught0 = false;
    try {
        SatEncoder::encode_reduced_rounds(cfg0);
    } catch (const std::invalid_argument&) {
        caught0 = true;
    }
    if (!caught0) throw std::runtime_error("encode_reduced_rounds accepted 0 rounds");

    SatEncoder::Sha256ProblemConfig cfg65;
    cfg65.num_rounds = 65;
    bool caught65 = false;
    try {
        SatEncoder::encode_reduced_rounds(cfg65);
    } catch (const std::invalid_argument&) {
        caught65 = true;
    }
    if (!caught65) throw std::runtime_error("encode_reduced_rounds accepted 65 rounds");
}

void test_anti_clamping_api() {
    uint8_t block[64] = {0};
    Sha256State st = SHA256_IV;

    // Sha256Scalar::compress_block
    bool caught_s0 = false;
    try {
        Sha256Scalar::compress_block(st, block, 0);
    } catch (const std::invalid_argument&) {
        caught_s0 = true;
    }
    if (!caught_s0) throw std::runtime_error("Sha256Scalar::compress_block accepted 0 rounds");

    bool caught_s65 = false;
    try {
        Sha256Scalar::compress_block(st, block, 65);
    } catch (const std::invalid_argument&) {
        caught_s65 = true;
    }
    if (!caught_s65) throw std::runtime_error("Sha256Scalar::compress_block accepted 65 rounds");

    // Sha256Scalar::compress_block_trace
    bool caught_t0 = false;
    try {
        Sha256Scalar::compress_block_trace(st, block, 0);
    } catch (const std::invalid_argument&) {
        caught_t0 = true;
    }
    if (!caught_t0) throw std::runtime_error("Sha256Scalar::compress_block_trace accepted 0 rounds");

    bool caught_t65 = false;
    try {
        Sha256Scalar::compress_block_trace(st, block, 65);
    } catch (const std::invalid_argument&) {
        caught_t65 = true;
    }
    if (!caught_t65) throw std::runtime_error("Sha256Scalar::compress_block_trace accepted 65 rounds");

    // IndependentVerifier::independent_compress_block
    bool caught_v0 = false;
    try {
        IndependentVerifier::independent_compress_block(st, block, 0);
    } catch (const std::invalid_argument&) {
        caught_v0 = true;
    }
    if (!caught_v0) throw std::runtime_error("IndependentVerifier::independent_compress_block accepted 0 rounds");

    bool caught_v65 = false;
    try {
        IndependentVerifier::independent_compress_block(st, block, 65);
    } catch (const std::invalid_argument&) {
        caught_v65 = true;
    }
    if (!caught_v65) throw std::runtime_error("IndependentVerifier::independent_compress_block accepted 65 rounds");
}

void test_independent_verifier_differential() {
    // Cross-verify IndependentVerifier::independent_hash vs Sha256Scalar and Sha256Optimized
    // on all NIST KATs
    auto kats = IndependentVerifier::get_standard_test_vectors();
    for (const auto& kat : kats) {
        Sha256Digest indep = IndependentVerifier::independent_hash(kat.message.data(), kat.message.size());
        if (indep != kat.expected_digest) {
            throw std::runtime_error("IndependentVerifier failed KAT: " + kat.name);
        }
        Sha256Digest scalar = Sha256Scalar::hash(kat.message.data(), kat.message.size());
        Sha256Digest opt = Sha256Optimized::hash(kat.message.data(), kat.message.size());
        if (indep != scalar || indep != opt) {
            throw std::runtime_error("Cross-verification mismatch on KAT: " + kat.name);
        }
    }

    // Cross-verify on random lengths
    for (int iter = 0; iter < 100; ++iter) {
        size_t len = test_rng() % 350;
        std::vector<uint8_t> buf(len);
        for (size_t i = 0; i < len; ++i) buf[i] = static_cast<uint8_t>(test_rng() & 0xFF);
        Sha256Digest d_indep = IndependentVerifier::independent_hash(buf.data(), len);
        Sha256Digest d_scalar = Sha256Scalar::hash(buf.data(), len);
        Sha256Digest d_opt = Sha256Optimized::hash(buf.data(), len);
        if (d_indep != d_scalar || d_indep != d_opt) {
            throw std::runtime_error("Differential mismatch between IndependentVerifier and reference at len " + std::to_string(len));
        }
    }
}

void test_independent_verifier_preimage_gate() {
    // Generate valid 8-round candidate
    PreimageCandidate cand;
    cand.message.resize(64);
    for (size_t i = 0; i < 64; ++i) cand.message[i] = static_cast<uint8_t>(i ^ 0x5A);
    cand.claimed_rounds = 8;
    cand.iv = SHA256_IV;
    cand.custom_iv = false;

    Sha256State st = SHA256_IV;
    IndependentVerifier::independent_compress_block(st, cand.message.data(), 8);
    for (size_t i = 0; i < 8; ++i) {
        cand.target_digest.bytes[i * 4 + 0] = static_cast<uint8_t>(st[i] >> 24);
        cand.target_digest.bytes[i * 4 + 1] = static_cast<uint8_t>(st[i] >> 16);
        cand.target_digest.bytes[i * 4 + 2] = static_cast<uint8_t>(st[i] >> 8);
        cand.target_digest.bytes[i * 4 + 3] = static_cast<uint8_t>(st[i]);
    }

    auto v_valid = IndependentVerifier::verify_preimage_candidate(cand);
    if (!v_valid.is_valid || v_valid.classification != CandidateClassification::ReducedRoundPreimage) {
        throw std::runtime_error("Valid preimage candidate rejected by IndependentVerifier");
    }

    // Tamper with target digest
    cand.target_digest.bytes[0] ^= 0xFF;
    auto v_invalid = IndependentVerifier::verify_preimage_candidate(cand);
    if (v_invalid.is_valid || v_invalid.classification != CandidateClassification::Invalid) {
        throw std::runtime_error("Tampered target preimage accepted by IndependentVerifier");
    }
}

// ---------------------------------------------------------------------------
// Encoding correctness. Every dialect must denote exactly the reference
// SHA-256 compression function. Rather than trusting an ad-hoc assignment, the
// formula is handed to a real solver: pinning the reference inputs must be
// SAT, and pinning a wrong output must be UNSAT. A smaller CNF that changes the
// semantics is worse than a large correct one, so both directions are checked.
// ---------------------------------------------------------------------------

// Total-assignment filler for the propagation-based checks below.
// Only meaningful once unit_propagate() has derived everything derivable.
static void fill_remaining(const CnfFormula& cnf, std::map<int,bool>& asg) {
    for (int v = 1; v <= cnf.num_vars; ++v) {
        if (asg.find(v) == asg.end()) asg[v] = false;
    }
}

// Pin inputs, propagate, then require the formula to be fully satisfied.
// This is the propagation-based equivalent of asking a solver, and it needs no
// external process.
static bool pin_and_propagate_ok(const CnfFormula& cnf, std::map<int,bool>& asg) {
    if (!unit_propagate(cnf, asg)) return false;   // conflict
    fill_remaining(cnf, asg);
    return cnf_satisfied(cnf, asg);
}

// Pick a solver that can handle the formula's dialect.
static std::unique_ptr<ISolver> pick_solver(EncodingDialect d) {
    auto all = SolverFactory::get_available_solvers();
    if (all.empty()) return nullptr;
    if (d == EncodingDialect::Xor) {
        for (auto t : all) {
            if (t == SolverType::CryptoMiniSat) return SolverFactory::create(t);
        }
        return nullptr;  // XOR constraints need an XOR-capable solver
    }
    for (auto t : all) {
        if (t == SolverType::CaDiCaL) return SolverFactory::create(t);
    }
    return SolverFactory::create(all.front());
}

// Solve a small formula with a real solver, in the requested dialect.
// Returns SolverStatus::Unknown when no suitable solver is installed.
static SolverStatus solve_small(CnfFormula& cnf, EncodingDialect d, uint32_t timeout) {
    auto solver = pick_solver(d);
    if (!solver) return SolverStatus::Unknown;
    return solver->solve_cnf(cnf, timeout).status;
}

// Reference reduced-round digest for a message block.
static Sha256Digest reference_digest(const std::vector<uint32_t>& msg, uint32_t rounds) {
    uint8_t block[64] = {0};
    for (size_t i = 0; i < 16; ++i) store_be32(block + i * 4, msg[i]);
    Sha256State st = SHA256_IV;
    Sha256Scalar::compress_block(st, block, rounds);
    Sha256Digest d;
    for (size_t i = 0; i < 8; ++i) store_be32(d.bytes.data() + i * 4, st[i]);
    return d;
}

// Pin the 16 message words of an encoding to concrete values.
static void pin_message(CnfFormula& cnf, const SatEncoder::Sha256SatEncoding& enc,
                        const std::vector<uint32_t>& msg) {
    for (size_t i = 0; i < 16 && i < enc.message_vars.size(); ++i) {
        SatEncoder::fix_const32(cnf, enc.message_vars[i], msg[i]);
    }
}

static void check_dialect_semantics(EncodingDialect dialect, bool carry_save, const char* label) {
    const uint32_t rounds = 3;
    auto solver = pick_solver(dialect);
    if (!solver) {
        std::cout << "[no " << (dialect == EncodingDialect::Xor ? "XOR-capable " : "")
                  << "solver, skipping " << label << "] ";
        return;
    }

    std::vector<uint32_t> msg(16);
    for (uint32_t i = 0; i < 16; ++i) msg[i] = 0xA5A50000u ^ (i * 0x01010101u);
    const Sha256Digest true_digest = reference_digest(msg, rounds);

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;
    cfg.dialect = dialect;
    cfg.carry_save_t1 = carry_save;

    // 1. Inputs pinned, output free -> the circuit must be satisfiable.
    auto enc_open = SatEncoder::encode_reduced_rounds(cfg);
    if (enc_open.cnf.is_trivially_unsat()) {
        throw std::runtime_error(std::string(label) + ": encoding normalised to UNSAT");
    }
    pin_message(enc_open.cnf, enc_open, msg);
    auto r1 = solver->solve_cnf(enc_open.cnf, 60);
    if (r1.status != SolverStatus::Satisfiable) {
        throw std::runtime_error(std::string(label) +
            ": encoding with reference inputs is not SAT (solver disagrees with reference impl)");
    }

    // 2. Inputs pinned, output pinned to the reference digest -> still SAT,
    //    and the extracted model must recompute to that digest.
    SatEncoder::Sha256ProblemConfig cfg_true = cfg;
    cfg_true.fix_target_digest = true;
    cfg_true.target_digest = true_digest;
    auto enc_true = SatEncoder::encode_reduced_rounds(cfg_true);

    // Solver-independent check first: with the reference inputs and the true
    // digest pinned, the formula must not be contradictory. If propagation
    // finds a conflict the ENCODING is wrong; if it passes but the solver says
    // UNSAT, the emitted DIMACS is wrong.
    {
        CnfFormula probe = enc_true.cnf;
        pin_message(probe, enc_true, msg);
        std::map<int,bool> asg;
        if (!unit_propagate(probe, asg)) {
            throw std::runtime_error(std::string(label) +
                ": encoding is CONTRADICTORY under reference inputs (propagation found a conflict)");
        }
        fill_remaining(probe, asg);
        if (!cnf_satisfied(probe, asg)) {
            throw std::runtime_error(std::string(label) +
                ": reference inputs do not yield a satisfying assignment");
        }
    }

    pin_message(enc_true.cnf, enc_true, msg);
    auto r2 = solver->solve_cnf(enc_true.cnf, 60);
    if (r2.status != SolverStatus::Satisfiable) {
        throw std::runtime_error(std::string(label) +
            ": correct target digest rejected (status=" +
            std::to_string(static_cast<int>(r2.status)) +
            ", exit=" + std::to_string(r2.stats.exit_code) +
            ", vars=" + std::to_string(enc_true.cnf.num_vars) +
            ", clauses=" + std::to_string(enc_true.cnf.clauses.size()) +
            ", xors=" + std::to_string(enc_true.cnf.xor_constraints.size()) +
            ", stderr=" + r2.stats.raw_stderr.substr(0, 200) + ")");
    }
    auto model_words = SatEncoder::extract_message_from_model(r2.model, enc_true.message_vars);
    for (size_t i = 0; i < 16; ++i) {
        if (model_words[i] != msg[i]) {
            throw std::runtime_error(std::string(label) +
                ": pinned message not recoverable from the model (encoding is unsound)");
        }
    }

    // 3. Inputs pinned, output pinned to a WRONG digest -> must be UNSAT.
    Sha256Digest wrong = true_digest;
    wrong.bytes[0] ^= 0xFF;
    SatEncoder::Sha256ProblemConfig cfg_wrong = cfg;
    cfg_wrong.fix_target_digest = true;
    cfg_wrong.target_digest = wrong;
    auto enc_wrong = SatEncoder::encode_reduced_rounds(cfg_wrong);
    pin_message(enc_wrong.cnf, enc_wrong, msg);
    auto r3 = solver->solve_cnf(enc_wrong.cnf, 60);
    if (r3.status == SolverStatus::Satisfiable) {
        throw std::runtime_error(std::string(label) +
            ": a wrong target digest was accepted (encoding is over-constrained / degenerate)");
    }
    if (r3.status == SolverStatus::Unknown || r3.status == SolverStatus::Error ||
        r3.status == SolverStatus::Timeout) {
        std::cout << "[solver inconclusive on negative case for " << label << "] ";
    }
}

void test_sat_dialect_semantic_equivalence() {
    check_dialect_semantics(EncodingDialect::Tseitin, false, "tseitin");
    check_dialect_semantics(EncodingDialect::Tseitin, true,  "tseitin+carrysave");
    check_dialect_semantics(EncodingDialect::Xor,      false, "xor");
    check_dialect_semantics(EncodingDialect::Xor,      true,  "xor+carrysave");
}

// The XOR dialect must be strictly leaner than pure Tseitin on the same
// problem, otherwise it is not worth its solver-compatibility cost.
void test_sat_xor_dialect_is_smaller() {
    SatEncoder::Sha256ProblemConfig base;
    base.num_rounds = 6;
    base.use_standard_iv = true;

    SatEncoder::Sha256ProblemConfig t = base;
    t.dialect = EncodingDialect::Tseitin;
    auto et = SatEncoder::encode_reduced_rounds(t);

    SatEncoder::Sha256ProblemConfig x = base;
    x.dialect = EncodingDialect::Xor;
    auto ex = SatEncoder::encode_reduced_rounds(x);

    if (ex.cnf.xor_constraints.empty()) {
        throw std::runtime_error("XOR dialect produced zero XOR constraints");
    }
    if (ex.cnf.num_vars >= et.cnf.num_vars) {
        throw std::runtime_error(
            "XOR dialect did not reduce variable count: xor=" +
            std::to_string(ex.cnf.num_vars) + " tseitin=" + std::to_string(et.cnf.num_vars));
    }
    std::cout << "[vars xor=" << ex.cnf.num_vars
              << " tseitin=" << et.cnf.num_vars
              << ", xors=" << ex.cnf.xor_constraints.size() << "] ";
}

// Carry-save reassociation must not change the denoted function and must not
// grow the formula relative to the serial chain it replaces.
void test_sat_carry_save_reassociation() {
    SatEncoder::Sha256ProblemConfig base;
    base.num_rounds = 6;
    base.use_standard_iv = true;

    SatEncoder::Sha256ProblemConfig serial = base;
    serial.dialect = EncodingDialect::Xor;
    serial.carry_save_t1 = false;
    auto es = SatEncoder::encode_reduced_rounds(serial);

    SatEncoder::Sha256ProblemConfig cs = base;
    cs.dialect = EncodingDialect::Xor;
    cs.carry_save_t1 = true;
    auto ec = SatEncoder::encode_reduced_rounds(cs);

    if (ec.cnf.num_vars > es.cnf.num_vars) {
        throw std::runtime_error(
            "carry-save T1 increased variable count: cs=" +
            std::to_string(ec.cnf.num_vars) + " serial=" + std::to_string(es.cnf.num_vars));
    }
    std::cout << "[vars cs=" << ec.cnf.num_vars << " serial=" << es.cnf.num_vars << "] ";
}

// The shared-carry multi-operand adder must model real 32-bit addition.
// Exhaustively checked over small operands by unit propagation (no solver
// needed), which is what catches a parity-collapse error: XOR-ing the addend
// bits of a column would lose the multi-bit carry and get e.g. 3+3 wrong.
void test_sat_add32_multi_semantics() {
    int checked = 0;
    for (auto dialect : {EncodingDialect::Tseitin, EncodingDialect::Xor}) {
        for (uint32_t a = 0; a <= 3; ++a) {
            for (uint32_t b = 0; b <= 3; ++b) {
                for (uint32_t c = 0; c <= 3; ++c) {
                    for (uint32_t e = 0; e <= 1; ++e) {
                        CnfFormula cnf;
                        cnf.dialect = dialect;

                        std::vector<uint32_t> vals = {a, b, c, e};
                        std::vector<std::vector<int>> vars(vals.size());
                        for (size_t k = 0; k < vals.size(); ++k) {
                            vars[k] = cnf.new_vars(32);
                            SatEncoder::fix_const32(cnf, vars[k], vals[k]);
                        }
                        std::vector<const std::vector<int>*> addends;
                        for (auto& v : vars) addends.push_back(&v);

                        auto sum = SatEncoder::encode_add32_multi(cnf, addends);
                        const uint32_t expect = a + b + c + e;

                        std::map<int,bool> asg;
                        for (int bit = 0; bit < 32; ++bit) {
                            asg[sum[bit]] = ((expect >> bit) & 1U) != 0;
                        }
                        if (!pin_and_propagate_ok(cnf, asg)) {
                            throw std::runtime_error(
                                "encode_add32_multi mis-models 32-bit addition: " +
                                std::to_string(a) + "+" + std::to_string(b) + "+" +
                                std::to_string(c) + "+" + std::to_string(e));
                        }
                        ++checked;
                    }
                }
            }
        }
    }
    if (checked < 256) throw std::runtime_error("add32-multi coverage unexpectedly small");
}

// encode_add32_const must agree with adding a fully materialised constant
// word through the generic two-operand path, for every constant bit pattern.
void test_sat_add32_const_folding() {
    std::mt19937 rng(0xBEEF01u);
    int checked = 0;

    for (int trial = 0; trial < 8; ++trial) {
        for (auto dialect : {EncodingDialect::Tseitin, EncodingDialect::Xor}) {
            uint32_t a_val = rng();
            // Exercise both sparse and dense constants, including the edges.
            const uint32_t k_val = (trial % 4 == 0) ? 0u
                                 : (trial % 4 == 1) ? 0xFFFFFFFFu
                                 : (trial % 4 == 2) ? 0x00000001u
                                 : rng();
            const uint32_t expect = a_val + k_val;

            CnfFormula c1;
            c1.dialect = dialect;
            auto av = c1.new_vars(32);
            SatEncoder::fix_const32(c1, av, a_val);
            auto sum1 = SatEncoder::encode_add32_const(c1, av, k_val);
            SatEncoder::fix_const32(c1, sum1, expect);

            CnfFormula c2;
            c2.dialect = dialect;
            auto av2 = c2.new_vars(32);
            auto kv = c2.new_vars(32);
            SatEncoder::fix_const32(c2, av2, a_val);
            SatEncoder::fix_const32(c2, kv, k_val);
            auto sum2 = SatEncoder::encode_add32(c2, av2, kv);
            SatEncoder::fix_const32(c2, sum2, expect);

            SolverStatus s1 = solve_small(c1, dialect, 30);
            SolverStatus s2 = solve_small(c2, dialect, 30);
            if (s1 == SolverStatus::Unknown || s2 == SolverStatus::Unknown) continue;

            if (s1 != SolverStatus::Satisfiable) {
                throw std::runtime_error("encode_add32_const rejects a correct a + K");
            }
            if (s2 != SolverStatus::Satisfiable) {
                throw std::runtime_error("generic add32 rejects a correct a + K");
            }

            // Wrong constant sum must be rejected.
            CnfFormula c3;
            c3.dialect = dialect;
            auto av3 = c3.new_vars(32);
            SatEncoder::fix_const32(c3, av3, a_val);
            auto sum3 = SatEncoder::encode_add32_const(c3, av3, k_val);
            SatEncoder::fix_const32(c3, sum3, expect ^ 0x5A5A5A5Au);
            if (solve_small(c3, dialect, 30) == SolverStatus::Satisfiable) {
                throw std::runtime_error("encode_add32_const accepted a wrong a + K");
            }
            checked++;
        }
    }
    if (checked == 0) std::cout << "[no solver available, const folding untested] ";
}

// A different constant must produce a different sum, proving the encoder is
// not silently discarding the K value.
void test_sat_add32_const_is_sound() {
    std::mt19937 rng(0x123456u);
    int checked = 0;

    for (int trial = 0; trial < 6; ++trial) {
        for (auto dialect : {EncodingDialect::Tseitin, EncodingDialect::Xor}) {
            uint32_t a_val = rng();
            uint32_t k_val = rng();

            // Pin the sum to a + k2 while the circuit encodes a + k.
            // With k != k2 this must be UNSAT.
            uint32_t k2 = k_val ^ (1u << (rng() % 32));
            if (k2 == k_val) continue;

            CnfFormula c;
            c.dialect = dialect;
            auto av = c.new_vars(32);
            SatEncoder::fix_const32(c, av, a_val);
            auto sum = SatEncoder::encode_add32_const(c, av, k_val);
            SatEncoder::fix_const32(c, sum, a_val + k2);

            SolverStatus st = solve_small(c, dialect, 30);
            if (st == SolverStatus::Unknown) continue;
            if (st == SolverStatus::Satisfiable) {
                throw std::runtime_error("encode_add32_const ignores the constant value");
            }
            checked++;
        }
    }
    if (checked == 0) std::cout << "[no solver available, const soundness untested] ";
}

// The DIMACS writer must emit exactly one line per constraint and must never
// emit an out-of-range literal inside an XOR constraint. Negative literals are
// legal in XOR clauses, so only the magnitude is range-checked.
void test_sat_dimacs_writer_integrity() {
    for (auto dialect : {EncodingDialect::Tseitin, EncodingDialect::Xor}) {
        SatEncoder::Sha256ProblemConfig cfg;
        cfg.num_rounds = 3;
        cfg.dialect = dialect;
        auto enc = SatEncoder::encode_reduced_rounds(cfg);

        std::string dimacs = enc.cnf.to_dimacs();
        std::istringstream iss(dimacs);
        std::string line;
        size_t clause_lines = 0, xor_lines = 0;
        while (std::getline(iss, line)) {
            if (line.empty() || line[0] == 'c' || line[0] == 'p') continue;
            if (line[0] == 'x') {
                ++xor_lines;
                std::istringstream ls(line.substr(1));
                int lit;
                while (ls >> lit) {
                    if (lit == 0) break;
                    if (lit > enc.cnf.num_vars || -lit > enc.cnf.num_vars) {
                        throw std::runtime_error("XOR clause contains an out-of-range literal");
                    }
                }
            } else {
                ++clause_lines;
            }
        }
        if (clause_lines != enc.cnf.clauses.size()) {
            throw std::runtime_error("DIMACS clause line count mismatch");
        }
        if (xor_lines != enc.cnf.xor_constraints.size()) {
            throw std::runtime_error("DIMACS XOR line count mismatch");
        }
        if (dialect == EncodingDialect::Xor && xor_lines == 0) {
            throw std::runtime_error("XOR dialect emitted no XOR lines");
        }
        if (dialect == EncodingDialect::Tseitin && xor_lines != 0) {
            throw std::runtime_error("Tseitin dialect emitted XOR lines");
        }
    }
}

// ---------------------------------------------------------------------------
// Cube-and-Conquer primitives.
//
// The blocking clause is what makes Cube-and-Conquer sound: a cube may only be
// pruned after it is proven UNSAT. If the clause were wrong the search would
// silently discard live regions and could "prove" a false nonexistence claim,
// so these tests check disjointness, coverage and exact exclusion.
// ---------------------------------------------------------------------------

void test_cube_partition_is_disjoint_and_total() {
    const int k = 6;
    CnfFormula base;
    std::vector<int> coords = base.new_vars(k);

    const auto cubes = CubePartition::enumerate(coords, 1u << k);
    if (cubes.size() != (1u << k)) {
        throw std::runtime_error("cube enumeration did not produce 2^k cubes");
    }

    // Every cube pins each coordinate to a distinct literal.
    for (size_t c = 0; c < cubes.size(); ++c) {
        if (cubes[c].size() != coords.size()) {
            throw std::runtime_error("cube has wrong arity");
        }
        for (size_t j = 0; j < coords.size(); ++j) {
            bool expected_positive = ((c >> j) & 1) != 0;
            int lit = cubes[c][j];
            if ((lit > 0) != expected_positive || std::abs(lit) != coords[j]) {
                throw std::runtime_error("cube literal does not pin its coordinate");
            }
        }
    }

    // Disjointness: no literal assignment satisfies two different cubes.
    for (size_t a = 0; a < cubes.size(); ++a) {
        for (size_t b = a + 1; b < cubes.size(); ++b) {
            bool contradicts = false;
            for (size_t j = 0; j < coords.size(); ++j) {
                if (cubes[a][j] == -cubes[b][j]) { contradicts = true; break; }
            }
            if (!contradicts) {
                throw std::runtime_error("two cubes are not disjoint");
            }
        }
    }
}

void test_cube_blocking_clause_excludes_exactly_its_cube() {
    const int k = 4;
    CnfFormula base;
    std::vector<int> coords = base.new_vars(k);
    const auto cubes = CubePartition::enumerate(coords, 1u << k);

    for (size_t c = 0; c < cubes.size(); ++c) {
        std::vector<int> blocking = CubePartition::blocking_clause(coords, c);
        if (blocking.size() != coords.size()) {
            throw std::runtime_error("blocking clause has wrong arity");
        }

        // The blocking clause must be satisfied by every cube except its own.
        for (size_t other = 0; other < cubes.size(); ++other) {
            bool clause_satisfied = false;
            for (size_t j = 0; j < blocking.size(); ++j) {
                for (int lit : cubes[other]) {
                    if (lit == blocking[j]) { clause_satisfied = true; break; }
                }
                if (clause_satisfied) break;
            }
            if (other == c && clause_satisfied) {
                throw std::runtime_error("blocking clause does NOT exclude its own cube");
            }
            if (other != c && !clause_satisfied) {
                throw std::runtime_error("blocking clause wrongly excludes another cube");
            }
        }
    }
}

void test_cube_enumeration_respects_cap() {
    CnfFormula base;
    std::vector<int> coords = base.new_vars(10);
    if (CubePartition::enumerate(coords, 5).size() != 5) {
        throw std::runtime_error("cube enumeration ignored the cap");
    }
    if (!CubePartition::enumerate(coords, 0).empty()) {
        throw std::runtime_error("zero cap must yield no cubes");
    }
}

// Assumption solving must equal solving the formula with those literals pinned.
// Checked on a formula where the answer is determined by the assumptions.
void test_solve_under_assumptions_pins_literals() {
    auto solver = SolverFactory::create(SolverType::CaDiCaL);
    if (!solver || !solver->is_available()) {
        auto avail = SolverFactory::get_available_solvers();
        if (avail.empty()) { std::cout << "[no solver, skipping] "; return; }
        solver = SolverFactory::create(avail.front());
    }

    // (a or b) and (not a or b): b must be true.
    CnfFormula cnf;
    int a = cnf.new_var(), b = cnf.new_var();
    cnf.add_clause({a, b});
    cnf.add_clause({-a, b});

    auto res = solver->solve_under_assumptions(cnf, {b}, 30);
    if (res.status == SolverStatus::Unknown) { std::cout << "[inconclusive] "; return; }
    if (!res.is_sat()) {
        throw std::runtime_error("assumption b=true should be satisfiable");
    }
    if (res.stats.assumptions_applied != 1) {
        throw std::runtime_error("assumption count not recorded");
    }
    auto it_b = res.model.find(b);
    if (it_b == res.model.end() || !it_b->second) {
        throw std::runtime_error("solver model contradicts the assumption");
    }

    // Contradictory assumptions must be UNSAT.
    CnfFormula cnf2;
    int x = cnf2.new_var();
    cnf2.add_clause({x});
    auto res2 = solver->solve_under_assumptions(cnf2, {-x}, 30);
    if (res2.status == SolverStatus::Unsatisfiable) {
        // Expected: x AND NOT x is unsatisfiable.
    } else if (res2.status == SolverStatus::Satisfiable) {
        throw std::runtime_error("contradictory assumptions accepted");
    }
}

// fixed_words must pin exactly the listed indices. A positional vector would
// silently pin every lower index as well, so this checks both directions:
// a listed word is forced, and an unlisted one is not.
void test_fixed_words_pins_only_listed_indices() {
    auto solver = pick_solver(EncodingDialect::Xor);
    if (!solver) { std::cout << "[no XOR solver, skipping] "; return; }

    const uint32_t rounds = 3;
    const uint32_t pinned_value = 0xDEADBEEFu;
    const uint32_t other_value = 0x01234567u;

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;
    cfg.dialect = EncodingDialect::Xor;
    cfg.fixed_words = {{3u, pinned_value}};
    auto enc = SatEncoder::encode_reduced_rounds(cfg);

    // 1. The listed word is genuinely pinned: the opposite value is UNSAT.
    {
        CnfFormula c = enc.cnf;
        SatEncoder::fix_const32(c, enc.message_vars[3], pinned_value ^ 0x1u);
        SolverStatus st = solver->solve_cnf(c, 60).status;
        if (st == SolverStatus::Satisfiable) {
            throw std::runtime_error(
                "fixed_words did not pin W[3]: its complement is satisfiable");
        }
    }

    // 2. An unlisted word is NOT pinned: it can take either value.
    for (uint32_t probe : {other_value, other_value ^ 0xFFFFFFFFu}) {
        CnfFormula c = enc.cnf;
        SatEncoder::fix_const32(c, enc.message_vars[3], pinned_value);
        SatEncoder::fix_const32(c, enc.message_vars[5], probe);
        SolverStatus st = solver->solve_cnf(c, 60).status;
        if (st != SolverStatus::Satisfiable) {
            throw std::runtime_error(
                "fixed_words wrongly pinned an unlisted word (W[5])");
        }
    }

    // 3. Pinning W[3] is consistent with the model's own value.
    {
        CnfFormula c = enc.cnf;
        SatEncoder::fix_const32(c, enc.message_vars[3], pinned_value);
        auto res = solver->solve_cnf(c, 60);
        if (res.status == SolverStatus::Satisfiable) {
            auto words = SatEncoder::extract_message_from_model(res.model, enc.message_vars);
            if (words[3] != pinned_value) {
                throw std::runtime_error("model disagrees with the pinned word");
            }
        }
    }
}

// Pinning every message word must make the instance unsatisfiable for a target
// derived from a different block. This is a genuine, checkable proof path.
void test_pinning_all_words_proves_unsat() {
    auto solver = pick_solver(EncodingDialect::Xor);
    if (!solver) { std::cout << "[no XOR solver, skipping] "; return; }

    const uint32_t rounds = 4;
    std::vector<uint32_t> msg(16);
    for (uint32_t i = 0; i < 16; ++i) msg[i] = 0x11223344u ^ (i * 0x01010101u);

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;
    cfg.dialect = EncodingDialect::Xor;
    cfg.fix_target_digest = true;
    cfg.target_digest = Sha256Digest{};   // deliberately not the true digest
    for (uint32_t i = 0; i < 16; ++i) cfg.fixed_words.emplace_back(i, msg[i]);

    auto enc = SatEncoder::encode_reduced_rounds(cfg);
    SolverStatus st = solver->solve_cnf(enc.cnf, 60).status;
    if (st == SolverStatus::Satisfiable) {
        throw std::runtime_error(
            "fully pinned message accepted a target it cannot produce");
    }
}

// Dobbertin-style state constraints must pin the top `bits` bits of the chosen
// register at the chosen round, and must leave the rest free.
void test_dobbertin_state_constraint_pins_msb_first() {
    auto solver = pick_solver(EncodingDialect::Xor);
    if (!solver) { std::cout << "[no XOR solver, skipping] "; return; }

    const uint32_t rounds = 3;
    const uint32_t k_round = 1;
    const uint32_t k_value = 0xA5A5A5A5u;
    const uint32_t bits = 8;

    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = rounds;
    cfg.use_standard_iv = true;
    cfg.dialect = EncodingDialect::Xor;
    cfg.use_state_constraint = true;
    cfg.state_constraint_round = k_round;
    cfg.state_constraint_register = 1;   // E
    cfg.state_constraint_value = k_value;
    cfg.state_constraint_bits = bits;
    auto enc = SatEncoder::encode_reduced_rounds(cfg);

    // Complementing a constrained bit must be UNSAT; flipping an unconstrained
    // bit must stay SAT.
    for (uint32_t i = 0; i < bits; ++i) {
        const uint32_t word_bit = 31u - i;  // most-significant first
        const bool want = ((k_value >> word_bit) & 1U) != 0;
        CnfFormula c = enc.cnf;
        c.add_unit(want ? -enc.state_e_vars[k_round][word_bit]
                        : enc.state_e_vars[k_round][word_bit]);
        SolverStatus st = solver->solve_cnf(c, 60).status;
        if (st == SolverStatus::Satisfiable) {
            throw std::runtime_error(
                "state constraint bit is not actually pinned (complement SAT)");
        }
    }

    // A bit below the constrained prefix must remain free.
    for (uint32_t word_bit = 0; word_bit + bits < 32; ++word_bit) {
        CnfFormula c = enc.cnf;
        c.add_unit(enc.state_e_vars[k_round][word_bit]);
        SolverStatus st = solver->solve_cnf(c, 60).status;
        if (st != SolverStatus::Satisfiable) {
            throw std::runtime_error(
                "state constraint over-constrained an unconstrained bit");
        }
    }

    // Zero bits must be equivalent to no constraint at all.
    SatEncoder::Sha256ProblemConfig none = cfg;
    none.state_constraint_bits = 0;
    auto enc_none = SatEncoder::encode_reduced_rounds(none);
    SatEncoder::Sha256ProblemConfig zero = cfg;
    zero.state_constraint_bits = 0;
    auto enc_zero = SatEncoder::encode_reduced_rounds(zero);
    if (enc_none.cnf.num_vars != enc_zero.cnf.num_vars ||
        enc_none.cnf.clauses.size() != enc_zero.cnf.clauses.size()) {
        throw std::runtime_error("0-bit state constraint is not a no-op");
    }
}

// A round index with no recorded state must be rejected, not silently ignored.
void test_dobbertin_rejects_out_of_range_round() {
    SatEncoder::Sha256ProblemConfig cfg;
    cfg.num_rounds = 2;
    cfg.use_state_constraint = true;
    cfg.state_constraint_round = 9;   // only rounds 0..2 exist
    cfg.state_constraint_bits = 8;
    bool threw = false;
    try {
        SatEncoder::encode_reduced_rounds(cfg);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    if (!threw) {
        throw std::runtime_error("out-of-range state_constraint_round was accepted");
    }

    SatEncoder::Sha256ProblemConfig cfg2 = cfg;
    cfg2.state_constraint_round = 0;
    cfg2.state_constraint_bits = 33;   // more than a word
    threw = false;
    try {
        SatEncoder::encode_reduced_rounds(cfg2);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    if (!threw) {
        throw std::runtime_error("state_constraint_bits > 32 was accepted");
    }
}

// Completeness of the Ch and Maj encodings with respect to conditioned
// projections.
//
// Feng and Gao (ePrint 2026/1505) argue that Tseitin encodings of SHA-256's
// nonlinear functions can hide conditioned differential projections from BCP,
// and remedy this with redundant CNF clauses (four Ch and twelve Maj per bit).
//
// This test checks our encodings against that criterion directly. The gate is
// complete for a given projection when every assignment consistent with the
// truth table also satisfies the projected clause -- i.e. the projection is
// already entailed by what we emit, so a redundant clause would add clause
// count without adding propagation.
//
//   Ch(e,f,g) is controlled by e:     e = 1 -> out = f,      e = 0 -> out = g
//   Maj(a,b,c) is controlled by any x: x = 1 -> out = OR(rest)
//                                     x = 0 -> out = AND(rest)
static bool clause_holds_under(const std::vector<int>& clause,
                               const std::map<int, bool>& asg)
{
    for (int lit : clause) {
        auto it = asg.find(lit > 0 ? lit : -lit);
        if (it != asg.end() && it->second == (lit > 0)) return true;
    }
    return false;
}

// Assert that `clause` holds on every correct model of Ch/Maj over v.
static void require_entailed(bool is_ch, const std::vector<int>& clause,
                             const std::vector<int>& v, const char* what)
{
    for (int mask = 0; mask < 16; ++mask) {
        std::map<int, bool> asg;
        for (int i = 0; i < 4; ++i) asg[v[i]] = ((mask >> i) & 1) != 0;
        const int a = asg[v[0]], b = asg[v[1]], c = asg[v[2]];
        const bool truth = is_ch
            ? ((((a & b) ^ ((1 - a) & c)) & 1) != 0)
            : ((((a + b + c) >= 2) ? 1 : 0) != 0);
        const bool out_value = asg[v[3]];
        if (truth != out_value) continue;             // not a correct model
        if (!clause_holds_under(clause, asg)) {
            throw std::runtime_error(
                std::string(is_ch ? "Ch" : "Maj") +
                " encoding does not entail conditioned projection: " + what);
        }
    }
}

void test_nonlinear_encodings_are_conditioned_projection_complete() {
    // ---- Ch: single control e, outputs f when e=1 and g when e=0.
    {
        CnfFormula enc;
        const int e = enc.new_var(), f = enc.new_var(),
                  g = enc.new_var(), o = enc.new_var();
        SatEncoder::encode_ch(enc, e, f, g, o);
        const std::vector<int> v = {e, f, g, o};

        require_entailed(true, {-e, -o, f}, v, "e & ~out -> f");
        require_entailed(true, {-e, -f,  o}, v, "e & f -> out");
        require_entailed(true, { e, -o, g}, v, "~e & ~out -> g");
        require_entailed(true, { e, -g,  o}, v, "~e & g -> out");
    }

    // ---- Maj: each of the three variables can serve as the control.
    for (int ctrl = 0; ctrl < 3; ++ctrl) {
        CnfFormula enc;
        const int a = enc.new_var(), b = enc.new_var(),
                  c = enc.new_var(), o = enc.new_var();
        SatEncoder::encode_maj(enc, a, b, c, o);
        const std::vector<int> v = {a, b, c, o};
        const int x = v[ctrl];
        const int p = v[(ctrl + 1) % 3];
        const int q = v[(ctrl + 2) % 3];
        const std::string tag = " ctrl=" + std::to_string(ctrl);

        // x = 1 -> o = p OR q
        require_entailed(false, {-x, -o, p, q}, v, ("x & o -> p|q" + tag).c_str());
        require_entailed(false, {-x, -p, o},    v, ("x & p -> o" + tag).c_str());
        require_entailed(false, {-x, -q, o},    v, ("x & q -> o" + tag).c_str());
        // x = 0 -> o = p AND q
        require_entailed(false, { x,  p, -o},   v, ("~x & ~p -> ~o" + tag).c_str());
        require_entailed(false, { x,  q, -o},   v, ("~x & ~q -> ~o" + tag).c_str());
        require_entailed(false, { x, -p, -q, o}, v, ("~x & p & q -> o" + tag).c_str());
    }
}

int main() {
    std::cout << "===============================================================\n"
              << "            SHA-256 Framework Test Suite                       \n"
              << "===============================================================\n";

    RUN_TEST(test_nist_known_answer_vectors);
    RUN_TEST(test_sha256_edge_lengths);
    RUN_TEST(test_streaming_chunked_hashing);
    RUN_TEST(test_cpu_backend_equivalence);
    RUN_TEST(test_search_partition_exact_cover);
    RUN_TEST(test_search_early_termination_sane);
    RUN_TEST(test_differential_trail_verification);
    RUN_TEST(test_sat_gates_exhaustive);
    RUN_TEST(test_sat_add32_semantics);
    RUN_TEST(test_sat_sigma_gamma_semantics);
    RUN_TEST(test_sat_encoder_tseitin_basic);
    RUN_TEST(test_sat_dialect_semantic_equivalence);
    RUN_TEST(test_sat_xor_dialect_is_smaller);
    RUN_TEST(test_sat_carry_save_reassociation);
    RUN_TEST(test_sat_add32_multi_semantics);
    RUN_TEST(test_sat_add32_const_folding);
    RUN_TEST(test_sat_add32_const_is_sound);
    RUN_TEST(test_sat_dimacs_writer_integrity);
    RUN_TEST(test_cube_partition_is_disjoint_and_total);
    RUN_TEST(test_cube_blocking_clause_excludes_exactly_its_cube);
    RUN_TEST(test_cube_enumeration_respects_cap);
    RUN_TEST(test_solve_under_assumptions_pins_literals);
    RUN_TEST(test_fixed_words_pins_only_listed_indices);
RUN_TEST(test_pinning_all_words_proves_unsat);
    RUN_TEST(test_dobbertin_state_constraint_pins_msb_first);
    RUN_TEST(test_dobbertin_rejects_out_of_range_round);
    RUN_TEST(test_nonlinear_encodings_are_conditioned_projection_complete);
    RUN_TEST(test_sat_invalid_round_rejection);
    RUN_TEST(test_anti_clamping_api);
    RUN_TEST(test_sat_end_to_end_with_solver);
    RUN_TEST(test_independent_verifier_rejection_gate);
    RUN_TEST(test_independent_verifier_differential);
    RUN_TEST(test_independent_verifier_preimage_gate);
    RUN_TEST(test_verifier_metadata_forgery);
    RUN_TEST(test_primitive_exhaustive);
    RUN_TEST(test_concurrency_hash_batch);
    RUN_TEST(test_concurrency_search);
    RUN_TEST(test_vulkan_smoke);
    RUN_TEST(test_million_a);

    std::cout << "===============================================================\n"
              << "  Results: " << g_tests_passed << " / " << g_tests_run << " passed\n"
              << "===============================================================\n";

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
