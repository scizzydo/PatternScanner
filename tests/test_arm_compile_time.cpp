// Compile-time arm64 patterns. A bad operand is a compile error: tests/CMakeLists.txt also builds this with BAD_OPERAND,
// which must fail. And the encoder stays out of the binary: no parser, error message or mnemonic table, checked at -O0
// (where GCC emits unreferenced namespace-scope constants). Exit code 0 = pass
#include <PatternScanner/ArmPattern.hpp>
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#ifdef BAD_OPERAND
#define LINE "ADD X0, X1, X32"
#else
#define LINE "ADD X0, X1, X30"
#endif

int main(int, char** argv) {
#ifdef PATTERNS_LITERALS
    constexpr auto p = LINE ""_armpattern;
#else
    constexpr auto p = ARM_PATTERN(LINE);
#endif
    FILE* f = fopen(argv[0], "rb");
    if (!f) { printf("FAIL: can't open %s\n", argv[0]); return 1; }
    std::vector<char> bin;
    for (int c; (c = fgetc(f)) != EOF;) bin.push_back(static_cast<char>(c));
    fclose(f);
    // Reversed and turned around at runtime (through volatile, so the optimizer can't), to keep them out of this binary
    for (const char* reversed : { "!retsiger dilavnI", "LDDAMS" }) {
        const volatile char* v = reversed;
        std::string needle;
        for (size_t i = 0; v[i]; ++i) needle.insert(needle.begin(), v[i]);
        if (std::search(bin.begin(), bin.end(), needle.begin(), needle.end()) != bin.end()) {
            printf("FAIL: \"%s\" in the binary\n", needle.c_str());
            return 1;
        }
    }
    return p.length() == 4 ? 0 : 1;
}
