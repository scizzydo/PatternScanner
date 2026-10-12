// The pre-C++20 path: macros instead of literals. Built as C++17 by tests/CMakeLists.txt.
#include <PatternScanner/RuntimePattern.hpp>
#include <PatternScanner/CompileTimePattern.hpp>
#include <PatternScanner/XORPattern.hpp>
#include <PatternScanner/ArmXORPattern.hpp>
#include <PatternScanner/RuntimeArmPattern.hpp>
#include <cstdio>

int main() {
    static const uint8_t buf[] = { 1, 2, 0x48, 0x8B, 5, 6, 7, 8 };
    auto ct = COMPILETIME_PATTERN("48 8B ? ? 07");
    auto x1 = XOR_PATTERN("48 8B ? ? 07");
    auto x2 = XOR_PATTERN("48 8B ? ? 07");
    patterns::RuntimePattern rp("48 8B ? ? 07");
    alignas(4) static const uint32_t code[] = { 0xD503201F, 0xD65F03C0 };   // NOP; RET
    const auto code_bytes = reinterpret_cast<const uint8_t*>(code);
    auto arm = ARM_PATTERN("NOP\nRET");
    auto arm_xor = ARM_XOR_PATTERN("NOP\nRET");
    patterns::RuntimeArmPattern arm_rt("NOP\nRET");
    // Negative PC-relative offsets in a constant expression (no left shift of a negative value)
    constexpr auto adr = ARM_PATTERN("ADR X3, #-0x4\nADRP X1, #-0x2000");
    const auto adr_words = reinterpret_cast<const uint32_t*>(adr.pattern());
    const bool ok = ct.find<const uint8_t*>(buf, 8) == buf + 2
                 && x1.find<const uint8_t*>(buf, 8) == buf + 2
                 && x2.find<const uint8_t*>(buf, 8) == buf + 2
                 && rp.find<const uint8_t*>(buf, 8) == buf + 2
                 && arm.find<const uint8_t*>(code_bytes, 8) == code_bytes
                 && arm_xor.find<const uint8_t*>(code_bytes, 8) == code_bytes
                 && arm_rt.find<const uint8_t*>(code_bytes, 8) == code_bytes
                 && adr_words[0] == 0x10FFFFE3 && adr_words[1] == 0xD0FFFFE1
                 && memcmp(x1.pattern(), x2.pattern(), 5) != 0;   // per-definition keys
    puts(ok ? "c++17 macros ok" : "FAIL c++17 macros");
    return !ok;
}
