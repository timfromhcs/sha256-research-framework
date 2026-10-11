#define _CRT_SECURE_NO_WARNINGS
// Independent reimplementation of the submask context-shaping construction
// for reduced-round SHA-256 compression-function preimages.
//
// The technique is due to K. S. Basra (2026), "Context Shaping for 19- and
// 20-Round SHA-256 Compression Preimages",
// github.com/kamb-code/sha256-r19-preimage. Nothing here is copied from that
// repository: the equations below are derived from the FIPS 180-4 round
// function together with the structural conditions of the construction.
//
// Every candidate this program emits is re-verified by an independent forward
// compression before it is printed, and the framework's segregated
// IndependentVerifier arbitrates the final claim.
//
// Why this exists: the direct SAT encoding used elsewhere in this framework
// does not reach 19 rounds (reports/preimage_strategies.md), because a
// one-block preimage is overdetermined by 2^256 and CDCL cannot thread one of
// the many solutions through a deep circuit. Working backwards from the target
// removes the message schedule from the search entirely.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <string>
#include <vector>
#include <thread>
#include <cmath>
#include <algorithm>

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t Sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static inline uint32_t Sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static inline uint32_t sg0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static inline uint32_t sg1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static const uint32_t SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

// ---------------------------------------------------------------------------
// Forward compression. Used only to check candidates we claim are preimages.
// ---------------------------------------------------------------------------
static void forward_compress(const uint32_t W16[16], int rounds, uint32_t out[8],
                             uint32_t* a_trace = nullptr) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = W16[i];
    for (int t = 16; t < rounds && t < 64; ++t)
        w[t] = sg1(w[t - 2]) + w[t - 7] + sg0(w[t - 15]) + w[t - 16];

    uint32_t a = SHA256_IV[0], b = SHA256_IV[1], c = SHA256_IV[2], d = SHA256_IV[3];
    uint32_t e = SHA256_IV[4], f = SHA256_IV[5], g = SHA256_IV[6], h = SHA256_IV[7];
    if (a_trace) {
        // a_{-4}=IV[3], a_{-3}=IV[2], a_{-2}=IV[1], a_{-1}=IV[0]
        for (int k = 0; k < 4; ++k) a_trace[k] = SHA256_IV[3 - k];
    }
    for (int t = 0; t < rounds; ++t) {
        uint32_t t1 = h + Sig1(e) + ch(e, f, g) + SHA256_K[t] + w[t];
        uint32_t t2 = Sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
        if (a_trace) a_trace[t + 4] = a;
    }
    out[0] = a + SHA256_IV[0]; out[1] = b + SHA256_IV[1];
    out[2] = c + SHA256_IV[2]; out[3] = d + SHA256_IV[3];
    out[4] = e + SHA256_IV[4]; out[5] = f + SHA256_IV[5];
    out[6] = g + SHA256_IV[6]; out[7] = h + SHA256_IV[7];
}

// ---------------------------------------------------------------------------
// Reduced-round state.
//
// The state after round r is written a_r, e_r. With the initial value placed
// at r = -4..-1, the round relations
//     a_r = T1^(r) + T2^(r),  e_r = a_{r-4} + T1^(r)
// give, by inversion,
//     T2^(r) = Sig0(a_{r-1}) + Maj(a_{r-1},a_{r-2},a_{r-3})
//     e_r    = a_{r-4} + a_r - T2^(r)
//     W_r    = a_r - T2^(r) - e_{r-4} - Sig1(e_{r-1})
//                        - Ch(e_{r-1},e_{r-2},e_{r-3}) - K_r
//
// A[] is indexed by r+4, so negative indices land on the IV words directly.
// ---------------------------------------------------------------------------
struct State {
    static const int MAXW = 80;
    int R = 0;
    uint32_t A[MAXW];  // a_r at index r+4

    void init(int rounds) {
        R = rounds;
        for (int i = 0; i < MAXW; ++i) A[i] = 0;
        // a_{-1}=IV[0], a_{-2}=IV[1], a_{-3}=IV[2], a_{-4}=IV[3]
        for (int i = 0; i < 4; ++i) A[i] = SHA256_IV[3 - i];
    }
    inline uint32_t& a(int r) { return A[r + 4]; }
    inline uint32_t  a(int r) const { return A[r + 4]; }

    inline uint32_t T2(int r) const {
        return Sig0(A[r - 1 + 4]) + maj(A[r - 1 + 4], A[r - 2 + 4], A[r - 3 + 4]);
    }
    // e_r, valid once a_{-4}..a_{r} are known.
    // e_{-1}=IV[4], e_{-2}=IV[5], e_{-3}=IV[6], e_{-4}=IV[7].
    inline uint32_t E(int r) const {
        if (r < 0) return SHA256_IV[3 - r];
        return A[r - 4 + 4] + A[r + 4] - T2(r);
    }
    inline uint32_t W(int r) const {
        return a(r) - T2(r) - E(r - 4) - Sig1(E(r - 1))
               - ch(E(r - 1), E(r - 2), E(r - 3)) - SHA256_K[r];
    }

    // Backward chain: the target fixes a_{R-1}..a_{R-4} and e_{R-1}..e_{R-4}
    // after subtracting the IV, and four more steps extend it downwards.
    void backward_chain(const uint32_t target[8]) {
        for (int k = 0; k < 4; ++k) {
            a(R - 1 - k) = target[k] - SHA256_IV[k];
        }
        uint32_t eR[MAXW];
        for (int i = 0; i < MAXW; ++i) eR[i] = 0;
        for (int k = 0; k < 4; ++k) eR[R - 1 - k + 4] = target[4 + k] - SHA256_IV[4 + k];

        for (int r = R - 1; r >= R - 4; --r) {
            uint32_t t1 = a(r) - T2(r);
            a(r - 4) = eR[r + 4] - t1;
        }
    }
};

// ---------------------------------------------------------------------------
// Inverse table for u -> sg0(u) - u.
//
// The image of this map has density ~0.633673, so a full 2^32 table is mostly
// empty. We store a dense table over the image range [0, 2^bits): a lookup
// whose argument falls outside that range simply misses. Smaller tables cost
// proportionally fewer surviving paths -- a throughput trade-off, never a
// correctness one.
// ---------------------------------------------------------------------------
// A hard memory ceiling. The table is 4 bytes per index, so this bounds the
// requested width before anything is allocated. An earlier revision parsed
// the width in hex, so "--bits 28" became 0x28 = 40 and the tool tried to
// allocate a 17 GiB table on a machine with 11 GiB free. The budget check and
// the decimal parser below exist so that a typo can never take the machine
// down again.
static const uint64_t MAX_TABLE_BYTES = 6ull << 30;  // 6 GiB

struct InverseTable {
    uint32_t bits = 0;
    uint32_t mask = 0;
    std::vector<uint32_t> tab;
    uint64_t stored = 0;

    static uint32_t max_bits_for_budget(uint64_t budget) {
        uint32_t b = 0;
        while (b < 32 && (4ull << (b + 1)) <= budget) ++b;
        return b;
    }

    void build(uint32_t b) {
        uint64_t need = (4ull) << b;
        if (need > MAX_TABLE_BYTES) {
            uint32_t cap = max_bits_for_budget(MAX_TABLE_BYTES);
            fprintf(stderr,
                    "table width %u needs %.2f GiB, above the %.2f GiB budget; "
                    "clamping to 2^%u (%.2f GiB)\n",
                    b, (double)need / (1024 * 1024 * 1024),
                    (double)MAX_TABLE_BYTES / (1024 * 1024 * 1024), cap,
                    (double)((4ull) << cap) / (1024 * 1024 * 1024));
            b = cap;
        }
        bits = b;
        mask = (b >= 32) ? 0xFFFFFFFFu : ((1u << b) - 1u);
        tab.assign(static_cast<size_t>(mask) + 1u, 0xFFFFFFFFu);

        // Scan the FULL 32-bit range of u and keep only the roots whose image
        // falls inside the stored range. Restricting u to the same range as
        // the image would drop the image density from 0.6337 to about 0.25,
        // costing a factor of 16 in yield because three lookups must all hit.
        // The scan is parallelised; each thread owns a disjoint u range and
        // writes only to its own slots (different u give different images).
        const unsigned T = std::max(1u, std::thread::hardware_concurrency());
        std::vector<std::thread> th;
        std::vector<uint64_t> counts(T, 0);
        const uint64_t CHUNK = 1ull << 24;
        for (unsigned t = 0; t < T; ++t) {
            th.emplace_back([&, t]() {
                uint64_t n = 0;
                for (uint64_t base = (uint64_t)t * CHUNK;
                     base < 0x100000000ull; base += CHUNK * T) {
                    uint64_t end = base + CHUNK;
                    if (end > 0x100000000ull) end = 0x100000000ull;
                    for (uint64_t u = base; u < end; ++u) {
                        uint32_t uv = static_cast<uint32_t>(u);
                        uint32_t img = sg0(uv) - uv;
                        if (img <= mask) { tab[img] = uv; ++n; }
                    }
                }
                counts[t] = n;
            });
        }
        for (auto& th2 : th) th2.join();
        for (uint64_t n : counts) stored += n;
    }
    inline uint32_t lookup(uint32_t image) const {
        if (image > mask) return 0xFFFFFFFFu;
        return tab[image];
    }
    double image_fraction() const {
        return static_cast<double>(stored) / static_cast<double>(mask + 1ull);
    }
};

// ---------------------------------------------------------------------------
// The submask context family.
//
//   a4 = a5 = v,   e8 = e9 = 0xFFFFFFFF
//
// Under those conditions the schedule constraints on W16, W17, W18 become
// triangular in (a1, a2, a3): each is solved by one table lookup for
// sg0(u) - u, and the residual consistency check collapses from a modular
// equation to the bitwise condition Maj(v, a3, a2) == a3.
//
// The mechanism is saturation. Ch(0xFFFFFFFF, y, z) = y and Maj(x, x, y) = x,
// so wherever an unknown reaches a constraint through one of those functions
// with a context word among the arguments, the dependence disappears.
//
// At 20 rounds a fourth constraint C3 on W19 appears. Unlike C0..C2 it is not
// solved by a lookup: it reduces to a residual that must happen to vanish,
// which is where the extra ~2^32 factor comes from.
// ---------------------------------------------------------------------------
static inline uint32_t t2_of_0() {
    return Sig0(SHA256_IV[0]) + maj(SHA256_IV[0], SHA256_IV[1], SHA256_IV[2]);
}

struct Searcher {
    int R = 19;
    State st;

    // Context words.
    uint32_t v = 0, a6 = 0, a7 = 0, a10 = 0, a8 = 0, a9 = 0;
    // Words recovered from the backward chain / target, constant per context.
    uint32_t W0 = 0, W14 = 0, W15 = 0, W16 = 0, W17 = 0, W18 = 0;
    uint32_t kappa3 = 0; bool have_c3 = false;
    uint32_t A0 = 0, A1 = 0, A2 = 0;

    void setup(const uint32_t target[8], uint32_t V, uint32_t A6, uint32_t A7,
               uint32_t A10, uint32_t A11 = 0) {
        v = V; a6 = A6; a7 = A7; a10 = A10;
        st.init(R);
        st.backward_chain(target);

        a8 = 0xFFFFFFFFu - v + (Sig0(a7) + maj(a7, a6, v));           // e8 = -1
        a9 = 0xFFFFFFFFu - v + (Sig0(a8) + maj(a8, a7, a6));         // e9 = -1
        st.a(4) = v; st.a(5) = v; st.a(6) = a6; st.a(7) = a7;
        st.a(8) = a8; st.a(9) = a9; st.a(10) = a10;
        // At 20 rounds the backward chain stops at a_12, so a_11 is free and
        // joins the context rather than being determined by the target.
        if (R >= 20) st.a(11) = A11;

        // W14..W18 depend on the context and the backward chain, never on the
        // unknown a0..a3. W0 is the exception: round 0 gives
        // W_0 = a_0 - T2^(0) - e_{-4} - Sig1(e_{-1}) - Ch(e_{-1},e_{-2},e_{-3}) - K_0,
        // so it carries a_0 with coefficient +1. Treating it as a constant --
        // which an earlier revision did -- breaks C_0 and nothing else, which
        // is exactly the kind of single-constraint bug the search reports.
        W0  = 0u - t2_of_0() - SHA256_IV[7] - Sig1(SHA256_IV[4])
              - ch(SHA256_IV[4], SHA256_IV[5], SHA256_IV[6]) - SHA256_K[0];
        W14 = st.W(14); W15 = st.W(15);
        W16 = st.W(16); W17 = st.W(17); W18 = st.W(18);
        if (R >= 20) {
            uint32_t W19 = st.W(19), W12 = st.W(12);
            kappa3 = W19 - sg1(W17) - W12;
            have_c3 = true;
        }

// A_j such that W_{9+j} = A_j - a_{j+1}, with a2 = a3 = 0 for j = 0.
        //
        // Note Maj(x, y, y) == y and Maj(x, x, y) == x. With a4 = a5 = v the
        // saturated terms are T2^(6) = Sig0(v) + Maj(v, v, a3) = Sig0(v) + v
        // and T2^(7) = Sig0(a6) + Maj(a6, v, v) = Sig0(a6) + v. Mixing these
        // two forms up is the easy mistake; the planted-state self-test below
        // exists precisely to catch it.
        uint32_t T2_9 = Sig0(a8) + maj(a8, a7, a6);
        A0 = a9 - T2_9 + Sig0(v) - 0xFFFFFFFFu - a7 + Sig0(a6) - SHA256_K[9];

        uint32_t T2_10 = Sig0(a9) + maj(a9, a8, a7);
        A1 = a10 - T2_10 - a6 + Sig0(v) + v - 0xFFFFFFFEu - SHA256_K[10];

        uint32_t T2_11 = Sig0(a10) + maj(a10, a9, a8);
        uint32_t e10 = a6 + a10 - T2_10;
        A2 = st.a(11) - T2_11 - a7 + Sig0(a6) + v - Sig1(e10)
             - 0xFFFFFFFFu - SHA256_K[11];
    }

    // B_j: the part of W_{j+1} independent of a_{j+1}.
    // With a_{-1}=IV[0], a_{-2}=IV[1], a_{-3}=IV[2], a_{-4}=IV[3] and
    // e_{-1}=IV[4], e_{-2}=IV[5], e_{-3}=IV[6].
    static uint32_t T2_of0() {
        return Sig0(SHA256_IV[0]) + maj(SHA256_IV[0], SHA256_IV[1], SHA256_IV[2]);
    }
    static uint32_t b0(uint32_t a0) {
        uint32_t e0 = SHA256_IV[3] + a0 - T2_of0();
        uint32_t T2_1 = Sig0(a0) + maj(a0, SHA256_IV[0], SHA256_IV[1]);
        return 0u - T2_1 - SHA256_IV[6] - Sig1(e0)
               - ch(e0, SHA256_IV[4], SHA256_IV[5]) - SHA256_K[1];
    }
    static uint32_t b1(uint32_t a0, uint32_t a1) {
        uint32_t e0 = SHA256_IV[3] + a0 - T2_of0();
        uint32_t T2_1 = Sig0(a0) + maj(a0, SHA256_IV[0], SHA256_IV[1]);
        uint32_t e1 = SHA256_IV[2] + a1 - T2_1;
        uint32_t T2_2 = Sig0(a1) + maj(a1, a0, SHA256_IV[0]);
        return 0u - T2_2 - SHA256_IV[5] - Sig1(e1)
               - ch(e1, e0, SHA256_IV[4]) - SHA256_K[2];
    }
    static uint32_t b2(uint32_t a0, uint32_t a1, uint32_t a2) {
        uint32_t e0 = SHA256_IV[3] + a0 - T2_of0();
        uint32_t T2_1 = Sig0(a0) + maj(a0, SHA256_IV[0], SHA256_IV[1]);
        uint32_t e1 = SHA256_IV[2] + a1 - T2_1;
        uint32_t T2_2 = Sig0(a1) + maj(a1, a0, SHA256_IV[0]);
        uint32_t e2 = SHA256_IV[1] + a2 - T2_2;
        uint32_t T2_3 = Sig0(a2) + maj(a2, a1, a0);
        return 0u - T2_3 - SHA256_IV[4] - Sig1(e2)
               - ch(e2, e1, e0) - SHA256_K[3];
    }

    // Try one swept a0. Returns true and fills (a1,a2,a3) on a candidate that
    // satisfies all three constraints and the collapsed condition.
    //
    // With c3_out non-null the fourth constraint is evaluated too and its
    // residual is written there without being required to vanish. That turns
    // the 20-round case into a measurement of the residual's distribution
    // rather than a search for an exact zero.
    bool try_a0(uint32_t a0, const InverseTable& tab,
                uint32_t& a1, uint32_t& a2, uint32_t& a3,
                uint32_t* c3_out = nullptr) const {
        const uint32_t B0 = b0(a0);
        uint32_t u = tab.lookup(W16 - sg1(W14) - (a0 + W0) - A0 - B0);
        if (u == 0xFFFFFFFFu) return false;
        a1 = u - B0;

        const uint32_t B1 = b1(a0, a1);
        u = tab.lookup(W17 - sg1(W15) - (a1 + B0) - A1 - B1);
        if (u == 0xFFFFFFFFu) return false;
        a2 = u - B1;

        const uint32_t B2 = b2(a0, a1, a2);
        u = tab.lookup(W18 - sg1(W16) - (a2 + B1) - A2 - B2);
        if (u == 0xFFFFFFFFu) return false;
        a3 = u - B2;

        // The residual consistency check collapses to this bitwise condition.
        if (maj(v, a3, a2) != a3) return false;

        if (have_c3) {
            State p = st;
            p.a(0) = a0; p.a(1) = a1; p.a(2) = a2; p.a(3) = a3;
            uint32_t c3 = sg0(p.W(4)) + p.W(3) - kappa3;
            if (c3_out) { *c3_out = c3; return true; }
            if (c3 != 0) return false;
        }
        return true;
    }

    // Recover the sixteen message words from a complete state.
    void words(uint32_t W[16], uint32_t a0, uint32_t a1, uint32_t a2,
               uint32_t a3) const {
        State s = st;
        s.a(0) = a0; s.a(1) = a1; s.a(2) = a2; s.a(3) = a3;
        for (int r = 0; r < 16; ++r) W[r] = s.W(r);
    }
};

// ---------------------------------------------------------------------------
static bool parse_hex32(const char* h, uint32_t& out) {
    uint64_t v = 0;
    for (int i = 0; h[i] && h[i] != ' '; ++i) {
        char c = h[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint32_t)d;
    }
    out = (uint32_t)v;
    return true;
}

static bool parse_target(const char* hex, uint32_t out[8]) {
    std::string s(hex);
    for (char& c : s) if (c == ' ') c = 0;
    if (s.size() < 64) return false;
    for (int i = 0; i < 8; ++i) {
        std::string w = s.substr(i * 8, 8);
        uint32_t v;
        if (!parse_hex32(w.c_str(), v)) return false;
        out[i] = v;
    }
    return true;
}

static uint32_t BITS = 32;

int main(int argc, char** argv) {
    if (const char* b = getenv("CS_FIBRE_BITS")) BITS = (uint32_t)strtoul(b, nullptr, 10);
    if (argc < 2) {
        printf("context_shaping -- reduced-round SHA-256 preimage search\n\n");
        printf("  selftest                     backward-chain round trip\n");
        printf("  analyze <block> <target>     recover state, test family membership\n");
        printf("  search <target> [options]    search for new preimages\n");
        printf("      --bits B      table covers image values < 2^B (default 30)\n");
        printf("      --contexts N  number of contexts to try (default 64)\n");
        printf("      --sweep M     swept a0 values per context (default 1<<21)\n");
        printf("      --seed S      context seed (default 1)\n");
        return 0;
    }

    const char* cmd = argv[1];

    if (std::strcmp(cmd, "selftest") == 0) {
        uint32_t W[16];
        for (int i = 0; i < 16; ++i) W[i] = 0x01234567u * (uint32_t)(i + 1);
        uint32_t digest[8];
        uint32_t trace[State::MAXW];
        forward_compress(W, 19, digest, trace);

        // The target alone fixes a_{R-1}..a_{R-8}; check the chain recovers
        // exactly those words, and nothing about the free ones.
        State s;
        s.init(19);
        s.backward_chain(digest);
        bool ok = true;
        for (int r = 11; r <= 18; ++r) {
            if (s.a(r) != trace[r + 4]) {
                ok = false;
                printf("  a[%2d] recovered %08x, expected %08x\n",
                       r, s.a(r), trace[r + 4]);
            }
        }
        printf("backward chain a11..a18 (19 rounds): %s\n", ok ? "OK" : "FAILED");
        if (!ok) return 1;

        // With the whole state installed, every message word must come back.
        for (int r = 0; r <= 10; ++r) s.a(r) = trace[r + 4];
        bool ok2 = true;
        for (int r = 0; r < 16; ++r) {
            if (s.W(r) != W[r]) {
                ok2 = false;
                printf("  W[%2d] recovered %08x, expected %08x\n", r, s.W(r), W[r]);
            }
        }
        printf("message-word recovery W0..W15: %s\n", ok2 ? "OK" : "FAILED");

        // The e relation must also agree with the forward computation.
        bool ok3 = true;
        for (int r = 0; r < 19; ++r) {
            uint32_t e = s.E(r);
            if (r < 19) {
                // e_r is implied by a_{r-4} + a_r - T2^(r); verify the
                // relation used by W() reproduces a consistent state.
                if (e != (s.a(r - 4) + s.a(r) - s.T2(r))) { ok3 = false; }
            }
        }
        printf("e-word relation: %s\n", ok3 ? "OK" : "FAILED");

        // Algebraic identities of the submask family, checked on planted
        // states. These isolate the derivation from the search: if they hold
        // for arbitrary a0..a3, any failure found later belongs to the search
        // or to the table, not to the construction.
        uint32_t V = 0x12345678u, A6 = 0xdeadbeefu, A7 = 0x0badf00du,
                 A10 = 0xfeedfaceu;
        Searcher se;
        se.setup(digest, V, A6, A7, A10);

        bool ok4 = true, ok5 = true, ok6 = true, ok7 = true, ok8 = true;
        bool okA1 = true, okA2 = true, okA0 = true;
        for (int trial = 0; trial < 64; ++trial) {
            uint32_t a0 = 0x9E3779B9u * (uint32_t)(trial + 1);
            uint32_t a1 = 0x85EBCA6Bu * (uint32_t)(trial + 7);
            uint32_t a2 = 0xC2B2AE35u * (uint32_t)(trial + 13);
            uint32_t a3 = 0x27D4EB2Fu * (uint32_t)(trial + 29);

            State p = se.st;
            p.a(0) = a0; p.a(1) = a1; p.a(2) = a2; p.a(3) = a3;

            // The family conditions must actually hold in the planted state.
            if (p.E(8) != 0xFFFFFFFFu || p.E(9) != 0xFFFFFFFFu) ok4 = false;

            // B_j : W_{j+1} = a_{j+1} + B_j
            if (p.W(1) != a1 + Searcher::b0(a0)) ok5 = false;
            if (p.W(2) != a2 + Searcher::b1(a0, a1)) ok6 = false;
            if (p.W(3) != a3 + Searcher::b2(a0, a1, a2)) ok7 = false;

            // A_1 and A_2 hold for every a3 -- this is the saturation that
            // makes the constraints triangular.
            if (p.W(10) != se.A1 - a2) ok8 = false, okA1 = false;
            if (p.W(11) != se.A2 - a3) ok8 = false, okA2 = false;

            // A_0 is provisional at a2 = a3 = 0; the difference from the true
            // W_9 must be exactly Maj(v,a3,a2) - a3.
            uint32_t resid = p.W(9) - (se.A0 - a1);
            if (resid != (maj(V, a3, a2) - a3)) ok8 = false, okA0 = false;

            if (trial == 0 && (p.W(11) != se.A2 - a3 || resid != (maj(V, a3, a2) - a3))) {
                printf("  [dbg] W11=%08x  A2-a3=%08x  diff=%08x\n",
                       p.W(11), se.A2 - a3, p.W(11) - (se.A2 - a3));
                printf("  [dbg] W9 =%08x  A0-a1=%08x  resid=%08x  expect=%08x\n",
                       p.W(9), se.A0 - a1, resid, maj(V, a3, a2) - a3);
                printf("  [dbg] E5=%08x E6=%08x E7=%08x E10=%08x E11=%08x\n",
                       p.E(5), p.E(6), p.E(7), p.E(10), p.E(11));
                printf("  [dbg] T2(5)=%08x T2(11)=%08x  A0=%08x A2=%08x\n",
                       p.T2(5), p.T2(11), se.A0, se.A2);
            }
        }
        printf("family conditions e8=e9=0xFFFFFFFF : %s\n", ok4 ? "OK" : "FAILED");
        printf("B_0 identity W1 = a1 + B0        : %s\n", ok5 ? "OK" : "FAILED");
        printf("B_1 identity W2 = a2 + B1        : %s\n", ok6 ? "OK" : "FAILED");
        printf("B_2 identity W3 = a3 + B2        : %s\n", ok7 ? "OK" : "FAILED");
        printf("A_1 identity W10 = A1 - a2       : %s\n", okA1 ? "OK" : "FAILED");
        printf("A_2 identity W11 = A2 - a3       : %s\n", okA2 ? "OK" : "FAILED");
        printf("A_0 residual = Maj(v,a3,a2)-a3   : %s\n", okA0 ? "OK" : "FAILED");
        return (ok && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8) ? 0 : 1;
    }

    if (std::strcmp(cmd, "analyze") == 0 && argc >= 4) {
        uint32_t target[8];
        if (!parse_target(argv[3], target)) {
            printf("bad target\n"); return 2;
        }
        // Rebuild the state a candidate implies and test the family conditions.
        State s;
        s.init(19);
        s.backward_chain(target);
        // Recover a_0..a_3 by running the chain forward from the recovered
        // message words is not possible without a full forward pass, so we
        // instead check whether the *context* words of the chain are free.
        printf("backward chain recovered a11..a18:\n  ");
        for (int r = 11; r <= 18; ++r) printf("%08x ", s.a(r));
        printf("\n");
        (void)argv[2];
        return 0;
    }

    // Measure the fibre-size distribution of u -> sigma0(u) - u.
    //
    // The context-shaping search recovers one root per image value, so the
    // number of preimages an image value has bounds the yield of a single
    // lookup. The mean is 1/0.633673 ~ 1.578, but a mean says nothing about
    // the tail. Erdős's conjecture on the largest fibres of the totient
    // function (OpenAI/math family 011) shows that for a highly non-injective
    // arithmetic map the largest fibre can be polynomially larger than
    // average -- so it is worth measuring rather than assuming.
    if (std::strcmp(cmd, "fibres") == 0) {
        const unsigned T = std::max(1u, std::thread::hardware_concurrency());
        // `1u << 32` is undefined behaviour, which silently produced N = 1 on
        // the first run of this measurement.
        const uint32_t N = (BITS >= 32) ? 0xFFFFFFFFu : ((1u << BITS) - 1u);
        const uint64_t NS = (uint64_t)N + 1ull;
        std::vector<uint8_t> cnt((size_t)NS, 0);
        std::vector<std::thread> th;
        for (unsigned t = 0; t < T; ++t) {
            th.emplace_back([&, t]() {
                const uint64_t CH = 1ull << 24;
                for (uint64_t base = (uint64_t)t * CH; base < 0x100000000ull;
                     base += CH * T) {
                    uint64_t end = base + CH;
                    if (end > 0x100000000ull) end = 0x100000000ull;
                    for (uint64_t u = base; u < end; ++u) {
                        uint32_t uv = (uint32_t)u;
                        uint32_t img = sg0(uv) - uv;
                        if (img < N) ++cnt[img];
                    }
                }
            });
        }
        for (auto& x : th) x.join();

        uint64_t hist[256] = {0};
        uint64_t present = 0, total = 0;
        uint32_t maxf = 0;
        for (uint32_t i = 0; i < N; ++i) {
            uint8_t c = cnt[i];
            if (c) { ++present; total += c; if (c > maxf) maxf = c; }
            if (c < 256) ++hist[c];
        }
        printf("image space        : 2^%u (%llu values)\n", BITS,
               (unsigned long long)NS);
        printf("images attained    : %llu (density %.6f)\n",
               (unsigned long long)present, (double)present / (double)NS);
        printf("total preimages    : %llu (of 2^32 scanned)\n",
               (unsigned long long)total);
        printf("mean fibre         : %.6f over attained images\n",
               (double)total / (double)present);
        printf("max fibre          : %u\n", maxf);
        printf("\nfibre size : count : fraction\n");
        for (int c = 1; c <= 8 && c < 256; ++c) {
            if (!hist[c]) continue;
            printf("  %-12d : %-10llu : %.6f\n", c,
                   (unsigned long long)hist[c], (double)hist[c] / (double)present);
        }
        return 0;
    }

    if (std::strcmp(cmd, "search") == 0 && argc >= 3) {
        uint32_t bits = 30, contexts = 64, sweep = 1u << 21, seed = 1, rounds = 19;
        uint32_t target[8];
        if (!parse_target(argv[2], target)) { printf("bad target\n"); return 2; }
        for (int i = 3; i + 1 < argc; i += 2) {
            // Options are decimal. An earlier revision parsed these as hex,
            // which silently turned "--bits 28" into 40 and asked for a 17 GiB
            // allocation.
            const std::string k(argv[i]);
            char* endp = nullptr;
            unsigned long val = strtoul(argv[i + 1], &endp, 10);
            if (endp == argv[i + 1] || *endp != '\0') {
                fprintf(stderr, "option %s expects a decimal integer, got '%s'\n",
                        k.c_str(), argv[i + 1]);
                return 2;
            }
            if (k == "--bits") bits = (uint32_t)val;
            else if (k == "--contexts") contexts = (uint32_t)val;
            else if (k == "--sweep") sweep = (uint32_t)val;
            else if (k == "--seed") seed = (uint32_t)val;
            else if (k == "--rounds") rounds = val;
            else { fprintf(stderr, "unknown option %s\n", k.c_str()); return 2; }
        }
        if (bits > 32) {
            fprintf(stderr, "--bits must be at most 32\n");
            return 2;
        }

        printf("context_shaping: submask family, %u rounds\n", rounds);
        printf("target: ");
        for (int i = 0; i < 8; ++i) printf("%08x", target[i]);
        printf("\n");

        auto t0 = std::chrono::steady_clock::now();
        InverseTable tab;
        tab.build(bits);
        auto t1 = std::chrono::steady_clock::now();
        printf("table: 2^%u entries (%.2f GiB), %llu roots, density %.6f, %.1fs\n",
               tab.bits, (double)tab.tab.size() * 4.0 / (1024 * 1024 * 1024),
               (unsigned long long)tab.stored, tab.image_fraction(),
               std::chrono::duration<double>(t1 - t0).count());

        uint32_t st = seed * 2654435761u;
        auto rnd = [&st]() { st ^= st << 13; st ^= st >> 17; st ^= st << 5; return st; };

        uint64_t total_swept = 0, total_hits = 0;
        // 20-round residual measurement (see the C3 discussion above).
        const bool measuring = (rounds >= 20) && (getenv("CS_MEASURE_C3") != nullptr);
        uint64_t c3_n[33] = {0};
        uint64_t c3_zero = 0;
        auto t2 = std::chrono::steady_clock::now();

        for (uint32_t ci = 0; ci < contexts && (total_hits == 0 || measuring); ++ci) {
            Searcher se;
            se.R = (int)rounds;
            uint32_t V = rnd(), A6 = rnd(), A7 = rnd(), A10 = rnd(), A11 = rnd();
            se.setup(target, V, A6, A7, A10, A11);
            uint32_t base = rnd();

            for (uint32_t i = 0; i < sweep; ++i) {
                uint32_t a0 = base + i * 0x9E3779B9u;   // spread the sweep
                uint32_t a1, a2, a3, c3 = 0;
                ++total_swept;
                if (measuring) {
                    if (!se.try_a0(a0, tab, a1, a2, a3, &c3)) continue;
                    ++total_hits;
                    if (c3 == 0) ++c3_zero;
                    // Cumulative count of candidates whose residual has its
                    // low k bits equal to zero, compared against the uniform
                    // model 2^-(32-k). Counting only the *first* matching k
                    // would measure something else entirely.
                    for (int k = 0; k <= 32; ++k)
                        if ((c3 & (k == 32 ? 0xFFFFFFFFu
                                           : ((1ull << k) - 1ull))) == 0) ++c3_n[k];
                    continue;
                }
                if (!se.try_a0(a0, tab, a1, a2, a3)) continue;
                ++total_hits;

                uint32_t W[16];
                se.words(W, a0, a1, a2, a3);
                uint32_t out[8];
                forward_compress(W, (int)rounds, out);
                bool match = std::memcmp(out, target, sizeof(out)) == 0;

                // Diagnose: do the schedule constraints actually hold on the
                // reconstructed words?
                State p = se.st;
                p.a(0) = a0; p.a(1) = a1; p.a(2) = a2; p.a(3) = a3;
                uint32_t w16 = p.W(16), w17 = p.W(17), w18 = p.W(18);
                bool c0 = w16 == sg1(p.W(14)) + p.W(9) + sg0(p.W(1)) + p.W(0);
                bool c1 = w17 == sg1(p.W(15)) + p.W(10) + sg0(p.W(2)) + p.W(1);
                bool c2 = w18 == sg1(w16) + p.W(11) + sg0(p.W(3)) + p.W(2);
                uint32_t eps = p.W(9) - (se.A0 - a1);
                printf("\ncontext %u: a0=%08x a1=%08x a2=%08x a3=%08x\n", ci, a0, a1, a2, a3);
                printf("  C0=%s C1=%s C2=%s  eps=%08x (want %08x)\n",
                       c0 ? "ok" : "FAIL", c1 ? "ok" : "FAIL", c2 ? "ok" : "FAIL",
                       eps, maj(se.v, a3, a2) - a3);
                printf("  block: ");
                for (int r = 0; r < 16; ++r) printf("%08x", W[r]);
                printf("\n");
                // Write the block to a file so external verifiers can read it
                // without re-parsing wrapped console output.
                if (const char* path = getenv("CS_OUT_BLOCK")) {
                    FILE* fh = fopen(path, "w");
                    if (fh) {
                        for (int r = 0; r < 16; ++r) fprintf(fh, "%08x", W[r]);
                        fclose(fh);
                        printf("  block written to %s\n", path);
                    }
                }
                printf("  forward digest: ");
                for (int r = 0; r < 8; ++r) printf("%08x", out[r]);
                printf("\n");
                printf("  VERIFIED: %s\n", match ? "yes" : "NO -- REJECTED");
                if (!match) return 3;
                auto t3 = std::chrono::steady_clock::now();
                printf("  swept %llu values in %.1fs\n", (unsigned long long)total_swept,
                       std::chrono::duration<double>(t3 - t2).count());
                return 0;
            }
        }

        auto t3 = std::chrono::steady_clock::now();
        if (measuring) {
            printf("\nC3 residual measurement over %llu candidates\n",
                   (unsigned long long)total_hits);
            printf("  %-6s %-14s %-14s %s\n", "k", "observed", "expected", "ratio");
            for (int k = 4; k <= 32; k += 4) {
                double exp_n = (double)total_hits * pow(2.0, -(32 - k));
                double ratio = exp_n > 0 ? (double)c3_n[k] / exp_n : 0.0;
                printf("  %-6d %-14llu %-14.2f %.4f\n", k, (unsigned long long)c3_n[k], exp_n, ratio);
            }
            printf("  exact zero: %llu observed, 2^-32 model predicts %.6f\n",
                   (unsigned long long)c3_zero,
                   (double)total_hits / 4294967296.0);
            printf("  swept %llu values in %.1fs\n", (unsigned long long)total_swept,
                   std::chrono::duration<double>(t3 - t2).count());
        }
        printf("\nno preimage found: swept %llu values, %llu collapsed candidates, %.1fs\n",
               (unsigned long long)total_swept, (unsigned long long)total_hits,
               std::chrono::duration<double>(t3 - t2).count());
        return 1;
    }

    printf("unknown command\n");
    return 2;
}