// Correctness tests. Exit code 0 = pass. Build with tests/CMakeLists.txt.
#include <PatternScanner/RuntimePattern.hpp>
#include <PatternScanner/CompileTimePattern.hpp>
#include <PatternScanner/XORPattern.hpp>
#include <PatternScanner/ArmPattern.hpp>
#include "multi_scan.hpp"
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#define CHECK(x) do { if (!(x)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

// Reference implementation: every position, every byte
static const uint8_t* naive(const uint8_t* b, size_t n, const uint8_t* p, const uint8_t* m, size_t len, size_t step) {
    for (size_t i = 0; i + len <= n; ++i) {
        if (reinterpret_cast<uintptr_t>(b + i) % step) continue;
        size_t j = 0;
        while (j < len && !((b[i + j] ^ p[j]) & m[j])) ++j;
        if (j == len) return b + i;
    }
    return nullptr;
}

// Arbitrary bit masks (like ArmPattern produces), usable on any platform
struct MaskPattern : patterns::Pattern {
    std::vector<uint8_t> p, m;
    MaskPattern(std::vector<uint8_t> p_, std::vector<uint8_t> m_, bool align) : p(std::move(p_)), m(std::move(m_)) {
        length_ = static_cast<uint32_t>(p.size());
        align_ = align;
    }
    const uint8_t* pattern() const override { return p.data(); }
    const uint8_t* mask() const override { return m.data(); }
};

static void edge_cases() {
    uint8_t t[16] = {};
    memcpy(t + 8, "\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22", 8);
    CHECK("AA BB CC DD EE FF 11 22"_rtpattern.find<uint8_t*>(t, 16) == t + 8);    // match in the last position
    CHECK("EE FF 11 22"_rtpattern.find<uint8_t*>(t, 16) == t + 12);               // short pattern at the very end
    CHECK("AA BB CC DD EE FF 11 22"_rtpattern.find<void*>(t, 4) == nullptr);       // buffer smaller than pattern
    CHECK("? ? ? ?"_rtpattern.find<uint8_t*>(t, 16) == t);                         // all wildcards
    CHECK("EE FF 11 22"_rtpattern.length() == 4);                                 // no padding
    bool threw = false;
    try { "48 8G"_rtpattern; } catch (const std::logic_error&) { threw = true; }
    CHECK(threw);                                                                 // invalid hex rejected
    { const char s[] = "48 8B X4"; patterns::RuntimePattern rp(s, 8); CHECK(rp.length() == 2); }   // X at the end, no overrun

    // X offset, /r (relative value) and /d (rip-relative deref) on a call: E8 <rel32>
    alignas(8) uint8_t code[16] = { 0x90, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3 };
    CHECK("E8 X ? ? ? ? C3"_rtpattern.find<uint8_t*>(code, 16) == code + 2);
    // x86 semantics on any host, as a disassembler plugin scanning x86 code needs (arm64 has no /r)
    for (auto a : { patterns::arch::x86, patterns::arch::x64 }) {
        const patterns::RuntimePattern rel("E8 X4 ? ? ? ? C3 /r", a), deref("E8 X4 ? ? ? ? C3 /d", a);
        CHECK(rel.find<uintptr_t>(code, 16) == 0x10);
        CHECK(deref.find<uint8_t*>(code, 16) == code + 6 + 0x10);
        bool is_value = false;
        CHECK(rel.resolve(rel.match(code, 16), code + 16, &is_value) == reinterpret_cast<void*>(0x10) && is_value);
        CHECK(deref.resolve(deref.match(code, 16), code + 16, &is_value) == code + 6 + 0x10 && !is_value);
        CHECK(rel.target() == a);
    }
    // arm64 semantics for byte patterns: /d decodes the instruction at X (BL #0x1000), X<len> isn't parsed
    alignas(4) const uint32_t bl[] = { 0xD503201F, 0x94000400 };
    const auto bl_bytes = reinterpret_cast<const uint8_t*>(bl);
    CHECK(patterns::RuntimePattern("1F 20 03 D5 X ? ? ? 94 /d", patterns::arch::arm64).find<const uint8_t*>(bl_bytes, 8) == bl_bytes + 4 + 0x1000);
    // /a steps by the target's alignment: 8 for x64, 4 for x86 and arm64
    alignas(8) uint8_t al[24] = {};
    al[12] = 0xAB;
    CHECK(patterns::RuntimePattern("AB /a", patterns::arch::x64).find<uint8_t*>(al, 24) == nullptr);
    CHECK(patterns::RuntimePattern("AB /a", patterns::arch::x86).find<uint8_t*>(al, 24) == al + 12);
    CHECK(patterns::RuntimePattern("AB /a", patterns::arch::arm64).find<uint8_t*>(al, 24) == al + 12);
    threw = false;
    try { patterns::RuntimePattern("E8 X4 ? ? ? ? /r8", patterns::arch::x86); } catch (const std::logic_error&) { threw = true; }
    CHECK(!threw);   // 8 isn't a size on x86, so it's ignored like any other unknown flag
    puts("  edge cases ok");
}

static void literals_and_macros() {
    static const uint8_t buf[] = { 0, 1, 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE, 9 };
#ifdef PATTERNS_LITERALS
    // Same text, different definition sites -> different stored bytes, same results
    constexpr auto a = "DE AD BE EF 13 37 C0 DE"_xorpattern;
    constexpr auto b = "DE AD BE EF 13 37 C0 DE"_xorpattern;
    constexpr auto c = "DE AD BE EF 13 37 C0 DE"_xorpattern; constexpr auto d = "DE AD BE EF 13 37 C0 DE"_xorpattern;
    CHECK(memcmp(a.pattern(), b.pattern(), 8) != 0);
    CHECK(memcmp(c.pattern(), d.pattern(), 8) != 0);
    CHECK(memcmp(a.mask(), b.mask(), 8) != 0);   // masks are XOR'd too
    CHECK(a.find<const uint8_t*>(buf, sizeof buf) == buf + 2);
    CHECK(d.find<const uint8_t*>(buf, sizeof buf) == buf + 2);
    constexpr auto ct = "DE AD ? EF X 13"_ctpattern;
    static_assert(ct.length() == 5 && ct.offset() == 4);
    CHECK(ct.find<const uint8_t*>(buf, sizeof buf) == buf + 6);
    constexpr auto xw = "DE AD ? EF X 13"_xorpattern;
    for (size_t k = 0; k < 5; ++k) CHECK(xw.unmask(k) == ct.mask()[k] && xw[k] == ct.pattern()[k]);
    CHECK(xw.find<const uint8_t*>(buf, sizeof buf) == buf + 6);
#endif
    auto m1 = XOR_PATTERN("DE AD BE EF 13 37 C0 DE");   // deliberately not constexpr: still built at compile time
    auto m2 = XOR_PATTERN("DE AD BE EF 13 37 C0 DE");
    CHECK(memcmp(m1.pattern(), m2.pattern(), 8) != 0);
    CHECK(m2.find<const uint8_t*>(buf, sizeof buf) == buf + 2);
    CHECK(COMPILETIME_PATTERN("DE AD ? EF").find<const uint8_t*>(buf, sizeof buf) == buf + 2);
    puts("  literals and macros ok");
}

// The XOR pattern's plaintext and source text must not be in our own executable. The needle is stored
// scrambled and rebuilt at runtime, otherwise the test itself would put it in the binary.
// Random patterns with random bit masks against the naive reference: both scan modes,
// sizes around the SIMD block boundaries, odd base addresses
static void fuzz(unsigned rounds) {
    std::mt19937 rng(7);
    std::vector<uint8_t> buf(300);
    for (unsigned r = 0; r < rounds; ++r) {
        for (auto& x : buf) x = rng() % 4 ? rng() % 3 : rng();   // small alphabet so partial matches are common
        const size_t len = 1 + rng() % 24, n = rng() % 200, base = rng() % 9;
        std::vector<uint8_t> p(len), m(len);
        for (size_t j = 0; j < len; ++j) {
            const int kind = rng() % 4;
            m[j] = kind == 0 ? 0 : kind == 1 ? static_cast<uint8_t>(rng()) : 0xFF;
            p[j] = (rng() % 2 ? rng() % 3 : rng()) & m[j];
        }
        if (rng() % 3 == 0 && n >= len) {   // plant a match
            const size_t at = rng() % (n - len + 1);
            for (size_t j = 0; j < len; ++j)
                buf[base + at + j] = (buf[base + at + j] & ~m[j]) | p[j];
        }
        const bool align = rng() % 4 == 0;
        MaskPattern mp(p, m, align);
        const auto got = mp.find<uint8_t*>(buf.data() + base, n);
        const size_t align_step = mp.target() == patterns::arch::x64 ? 8 : 4;   // see Pattern::align_size()
        const auto want = naive(buf.data() + base, n, p.data(), m.data(), len, align ? align_step : 1);
        if (got != want) {
            printf("FAIL fuzz round %u: len=%zu n=%zu base=%zu align=%d\n", r, len, n, base, align);
            exit(1);
        }
    }
    printf("  fuzz ok (%u rounds)\n", rounds);
}

// Every multi-pattern strategy must agree with plain find() calls, including /d results and matches
// that straddle chunk boundaries (small chunks force many boundaries)
static void multi_strategies() {
    std::mt19937 rng(3);
    std::vector<uint8_t> mod(1 << 20);
    for (auto& x : mod) x = static_cast<uint8_t>(rng());
    std::vector<patterns::RuntimePattern> owned;
    std::vector<const patterns::Pattern*> pats;
    for (int k = 0; k < 40; ++k) {
        const size_t off = rng() % (mod.size() - 32);
        std::string s;
        char hex[4];
        for (int j = 0; j < 12; ++j) {
            if (j == 3) s += "X ";
            if (j >= 4 && j < 8) s += "? ";
            else { snprintf(hex, sizeof hex, "%02X ", mod[off + j]); s += hex; }
        }
        s += k % 2 ? "/d" : "";
        // x86-style /d on random bytes; arm64 /d would try to decode them as instructions
        owned.emplace_back(s.c_str(), patterns::arch::x64);
    }
    owned.emplace_back("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");   // absent
    for (auto& p : owned) pats.push_back(&p);
    std::vector<void*> want, got;
    multi::sequential(mod.data(), mod.size(), pats, want);
    multi::per_pattern(mod.data(), mod.size(), pats, got);
    CHECK(got == want);
    for (size_t chunk : { 7, 64, 4096, 1 << 20 }) {
        got.assign(pats.size(), &got);   // garbage, find_all must overwrite every entry
        CHECK(patterns::find_all(mod.data(), mod.size(), pats.data(), pats.size(), got.data(), chunk) == pats.size() - 1);
        CHECK(got == want);
        multi::chunked(mod.data(), mod.size(), pats, got, 1, chunk);
        CHECK(got == want);
        multi::chunked(mod.data(), mod.size(), pats, got, 4, chunk);
        CHECK(got == want);
    }
    puts("  multi-pattern strategies agree ok");
}

static void arm_patterns() {
    constexpr auto adrl = "LDR W?, [X?,#0x18]\n"
                          "X ADRP X?, #?\n"
                          "ADD X?, X?, #?\n"
                          "STR W?, [SP,#?]\n"
                          "/d"_armpattern;
    static_assert(adrl.length() == 16 && adrl.offset() == 4 && adrl.deref() && adrl.aligned());
    alignas(4) static const uint32_t code[] = { 0xD503201F, 0xD503201F, 0xD65F03C0, 0 };   // NOP NOP RET
    constexpr auto ret = "NOP\nRET"_armpattern;
    CHECK(ret.find<const uint32_t*>(reinterpret_cast<const uint8_t*>(code), sizeof code) == code + 1);
    puts("  arm64 patterns ok");
}

int main() {
#ifdef PATTERNS_NO_SIMD
    puts("scan path: scalar (PATTERNS_NO_SIMD)");
#elif defined(PATTERNS_SSE2)
    puts("scan path: SSE2");
#elif defined(PATTERNS_NEON)
    puts("scan path: NEON");
#else
    puts("scan path: scalar");
#endif
    edge_cases();
    literals_and_macros();
    fuzz(300000);
    multi_strategies();
    arm_patterns();
    puts("all tests passed");
}
