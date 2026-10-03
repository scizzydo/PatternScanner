// The pre-C++20 path: macros instead of literals. Built as C++17 by tests/CMakeLists.txt.
#include "RuntimePattern.hpp"
#include "CompileTimePattern.hpp"
#include "XORPattern.hpp"
#include <cstdio>

int main() {
    static const uint8_t buf[] = { 1, 2, 0x48, 0x8B, 5, 6, 7, 8 };
    auto ct = COMPILETIME_PATTERN("48 8B ? ? 07");
    auto x1 = XOR_PATTERN("48 8B ? ? 07");
    auto x2 = XOR_PATTERN("48 8B ? ? 07");
    patterns::RuntimePattern rp("48 8B ? ? 07");
    const bool ok = ct.find<const uint8_t*>(buf, 8) == buf + 2
                 && x1.find<const uint8_t*>(buf, 8) == buf + 2
                 && x2.find<const uint8_t*>(buf, 8) == buf + 2
                 && rp.find<const uint8_t*>(buf, 8) == buf + 2
                 && memcmp(x1.pattern(), x2.pattern(), 5) != 0;   // per-definition keys
    puts(ok ? "c++17 macros ok" : "FAIL c++17 macros");
    return !ok;
}
