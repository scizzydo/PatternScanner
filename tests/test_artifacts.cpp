// Compile-time patterns must leave nothing behind in the binary: no pattern text for any of them, and no plaintext
// bytes, words or masks for the XOR ones. tests/CMakeLists.txt builds this at every optimization level and with LTO,
// with debug info, as C++17 (macros) and C++20 (macros and literals). Exit code 0 = pass.
// Needles are written reversed and turned around at runtime, so this file doesn't put them in the binary itself.
#include <PatternScanner/CompileTimePattern.hpp>
#include <PatternScanner/XORPattern.hpp>
#include <PatternScanner/ArmXORPattern.hpp>
#include <PatternScanner/RuntimeArmPattern.hpp>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#define CHECK(x) do { if (!(x)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static std::vector<uint8_t> bin;

static bool contains(const void* needle, size_t len) {
    const auto n = static_cast<const uint8_t*>(needle);
    return std::search(bin.begin(), bin.end(), n, n + len) != bin.end();
}

// Reversed text, turned around at runtime. Read through volatile: otherwise the optimizer reverses the literal at
// compile time and puts the needle in the binary itself (seen with clang -O2, C++20)
static std::string forward(const char* reversed) {
    const volatile char* v = reversed;
    std::string s;
    for (size_t i = 0; v[i]; ++i) s.insert(s.begin(), v[i]);
    return s;
}

// Space-separated hex bytes, ? as 0 (how wildcards are stored)
static std::vector<uint8_t> hex_bytes(const std::string& text) {
    std::vector<uint8_t> out;
    std::istringstream in(text);
    for (std::string tok; in >> tok;)
        out.push_back(tok == "?" ? 0 : static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
    return out;
}

// Needle text, and code containing the pattern for it to find
struct Case {
    std::string text;
    // Fixed size, like most real scans of a known buffer: with a size the optimizer can see, it unrolls and folds more
    uint8_t code[64] = {};
    std::vector<uint8_t> bytes, masks;   // masks: arm64 only
    size_t at = 0;
};

static Case byte_case(const char* reversed) {
    Case c;
    c.text = forward(reversed);
    c.bytes = hex_bytes(c.text);
    memset(c.code, 0x90, sizeof c.code);
    c.at = 3;
    memcpy(c.code + c.at, c.bytes.data(), c.bytes.size());
    return c;
}

static Case arm_case(const char* reversed) {
    Case c;
    c.text = forward(reversed);
    const patterns::RuntimeArmPattern rt(c.text.c_str());
    c.bytes.assign(rt.pattern(), rt.pattern() + rt.length());
    c.masks.assign(rt.mask(), rt.mask() + rt.length());
    for (size_t i = 0; i < sizeof c.code; i += 4) memcpy(&c.code[i], "\x1F\x20\x03\xD5", 4);   // NOPs around it
    c.at = 8;
    memcpy(c.code + c.at, c.bytes.data(), c.bytes.size());
    return c;
}

// No text in the binary (each line on its own for arm64, so partly folded text is caught too); for XOR patterns no
// plaintext bytes or masks either (masks only as a whole: single mask words like FFFFFFFF are everywhere). The
// pattern must still have found its bytes
static bool check(const char* name, const Case& c, const uint8_t* found, bool xored) {
    if (found != c.code + c.at) { printf("FAIL %s: didn't find its bytes\n", name); return false; }
    for (size_t a = 0, b; a < c.text.size(); a = b + 1) {
        b = c.text.find('\n', a);
        if (b == std::string::npos) b = c.text.size();
        if (contains(c.text.data() + a, b - a)) { printf("FAIL %s: pattern text in the binary\n", name); return false; }
    }
    // Folded plaintext may be split into 4-byte immediates (arm64 words always are), so each word on its own
    for (size_t i = 0; xored && i + 4 <= c.bytes.size(); i += 4)
        if (contains(&c.bytes[i], 4)) { printf("FAIL %s: plaintext bytes %zu..%zu in the binary\n", name, i, i + 3); return false; }
    if (xored && !c.masks.empty() && contains(c.masks.data(), c.masks.size())) { printf("FAIL %s: plaintext masks in the binary\n", name); return false; }
    return true;
}

// Each pattern is unique, and its needle is its text reversed. The XOR arm64 ones use mask shapes no plain
// pattern here has: plain patterns' masks are in the binary by design. The XOR byte patterns have no wildcards,
// so each of their 4-byte words is distinctive
#define MACRO_CASES(X) \
    X("COMPILETIME_PATTERN", byte_case, COMPILETIME_PATTERN("1A 2B ? 4D 5E 6F 71 82"), "28 17 F6 E5 D4 ? B2 A1", false) \
    X("XOR_PATTERN", byte_case, XOR_PATTERN("A1 B2 C3 D4 E5 F6 07 18"), "81 70 6F 5E 4D 3C 2B 1A", true) \
    X("ARM_PATTERN", arm_case, ARM_PATTERN("MOVZ W4, #0x1357\nMOVK W4, #0x2468, LSL #16\nLDR W?, [X4,#?]"), \
      "]?#,4X[ ,?W RDL\n61# LSL ,8642x0# ,4W KVOM\n7531x0# ,4W ZVOM", false) \
    X("ARM_XOR_PATTERN", arm_case, ARM_XOR_PATTERN("MOVZ W?, #0x7531\nMOVK W5, #0x8642, LSL #16\nSTR W?, [X5,#0x2C]"), \
      "]C2x0#,5X[ ,?W RTS\n61# LSL ,2468x0# ,5W KVOM\n1357x0# ,?W ZVOM", true)
#ifdef PATTERNS_LITERALS
#define LITERAL_CASES(X) \
    X("_ctpattern", byte_case, "3C 4D ? 6F 71 82 93 A4"_ctpattern, "4A 39 28 17 F6 ? D4 C3", false) \
    X("_xorpattern", byte_case, "C3 D4 E5 F6 17 28 39 4A"_xorpattern, "A4 93 82 71 6F 5E 4D 3C", true) \
    X("_armpattern", arm_case, "MOVZ W6, #0x1A2B\nMOVK W6, #0x3C4D, LSL #16\nLDR W?, [X6,#?]"_armpattern, \
      "]?#,6X[ ,?W RDL\n61# LSL ,D4C3x0# ,6W KVOM\nB2A1x0# ,6W ZVOM", false) \
    X("_armxorpattern", arm_case, "MOVZ W7, #0x2B1A\nMOVK W?, #0x4D3C, LSL #16\nSTR W?, [X7,#0x34]"_armxorpattern, \
      "]43x0#,7X[ ,?W RTS\n61# LSL ,C3D4x0# ,?W KVOM\nA1B2x0# ,7W ZVOM", true)
#else
#define LITERAL_CASES(X)
#endif

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

// All scans in one function with nothing else in it, as a project's signature file does it: the shape in which
// optimizers inline find() and fold constants, e.g. an XOR pattern's decode back into plaintext. Locals, not
// constexpr: the macros and literals must build at compile time on their own. Not static: gcc treats a static
// function only reachable from main() as run once and stops inlining into it, which would hide such a leak
NOINLINE void scan_all(const uint8_t* const* code, size_t size, const uint8_t** found) {
    size_t i = 0;
#define SCAN(name, make_case, def, reversed, xored) { auto p = def; found[i] = p.find<const uint8_t*>(code[i], size); ++i; }
    MACRO_CASES(SCAN)
    LITERAL_CASES(SCAN)
#undef SCAN
}

int main(int, char** argv) {
    FILE* f = fopen(argv[0], "rb");
    if (!f) { printf("FAIL: can't open %s\n", argv[0]); return 1; }
    uint8_t chunk[65536];
    for (size_t n; (n = fread(chunk, 1, sizeof chunk, f)) > 0;) bin.insert(bin.end(), chunk, chunk + n);
    fclose(f);

    struct Entry { const char* name; Case c; bool xored; };
    std::vector<Entry> cases;
#define ADD(name, make_case, def, reversed, xored) cases.push_back({ name, make_case(reversed), xored });
    MACRO_CASES(ADD)
    LITERAL_CASES(ADD)
#undef ADD
    std::vector<const uint8_t*> code, found(cases.size());
    for (const auto& e : cases) code.push_back(e.c.code);
    scan_all(code.data(), sizeof cases[0].c.code, found.data());
    // Every leak reported, not just the first
    bool ok = true;
    for (size_t i = 0; i < cases.size(); ++i) ok &= check(cases[i].name, cases[i].c, found[i], cases[i].xored);
    if (!ok) return 1;
    printf("%zu patterns: no pattern text, no XOR plaintext\n", cases.size());
}
