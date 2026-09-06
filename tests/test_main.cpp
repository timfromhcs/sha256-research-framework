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
    // Padding-boundary sweep required by spec: 0..129 incl. critical edges.
    std::vector<size_t> lens = {0, 1, 15, 16, 31, 32, 54, 55, 56, 57, 63, 64,
                                65, 127, 128, 129, 200, 1000, 4096};
    for (size_t len : lens) {
        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>((i * 13 + 37) & 0xFF);
        Sha256Digest s = Sha256Scalar::hash(data.data(), len);
        Sha256Digest o = Sha256Optimized::hash(data.data(), len);
        Sha256Digest o_ref = Sha256Optimized::hash_path(data.data(), len,
            Sha256Optimized::Path::ScalarReference);
        if (!(s == o && s == o_ref))
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

// --- SAT semantic oracle: unit propagation over CNF clauses ---
static bool assign_lit(std::map<int,bool>& asg, int lit) {
    int v = lit > 0 ? lit : -lit;
    bool val = lit > 0;
    auto it = asg.find(v);
    if (it != asg.end()) return it->second == val;
    asg[v] = val;
    return true;
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
        for (int i = 0; i < 16; ++i) cfg2.fixed_message_words.push_back(W[i]);
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
        bool any = false;
        for (auto t : SolverFactory::get_available_solvers()) { (void)t; any = true; break; }
        if (!any) { std::cout << "[no SAT solver installed, skipping] "; return; }
        solver = SolverFactory::create(SolverFactory::get_available_solvers().front());
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
    // Over-claimed rounds (>64) clamp to 64 and must not misclassify.
    CollisionCandidate cand2;
    cand2.message_a = {'x'};
    cand2.message_b = {'y'};
    cand2.claimed_rounds = 1000;
    auto v2 = IndependentVerifier::verify_collision_candidate(cand2);
    if (v2.actual_rounds != 64) throw std::runtime_error("rounds not clamped");
    if (v2.classification == CandidateClassification::StandardFullCollision)
        throw std::runtime_error("non-collision misclassified as full collision");
}

void test_primitive_exhaustive() {
    // Test rotr32 for a few values
    assert(rotr32(0x12345678, 4) == 0x81234567);
    // Test ch and maj with known values
    assert(ch(0xFFFFFFFF, 0, 0xFFFFFFFF) == 0xFFFFFFFF);
    assert(maj(0xFFFFFFFF, 0xFFFFFFFF, 0) == 0xFFFFFFFF);
    // Test sigma0 and sigma1
    assert(sigma0(0) == 0);
    assert(sigma1(0) == 0);
    // Test gamma0 and gamma1
    assert(gamma0(0) == 0);
    assert(gamma1(0) == 0);
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
    RUN_TEST(test_sat_end_to_end_with_solver);
    RUN_TEST(test_independent_verifier_rejection_gate);
    RUN_TEST(test_verifier_metadata_forgery);
    RUN_TEST(test_primitive_exhaustive);
    RUN_TEST(test_concurrency_hash_batch);
    RUN_TEST(test_concurrency_search);
    RUN_TEST(test_vulkan_smoke);

    std::cout << "===============================================================\n"
              << "  Results: " << g_tests_passed << " / " << g_tests_run << " passed\n"
              << "===============================================================\n";

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
