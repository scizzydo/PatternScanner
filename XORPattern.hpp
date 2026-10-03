#pragma once
#include "CompileTimePattern.hpp"
#include <array>

namespace patterns {
    namespace detail {
        // Key byte from the definition site's seed, mixed with the build time so keys also change every build
        constexpr uint8_t generate_key(uint32_t seed) {
            uint32_t value = 2166136261u + seed;
            for (char c : __TIME__)
                value = static_cast<uint32_t>((value ^ c) * 16777619ull);
            return static_cast<uint8_t>(value);
        }
    }

    template<size_t nstr, size_t narr>
    class XORPattern final : public Pattern {
        std::array<uint8_t, narr> pattern_;
        std::array<uint8_t, narr> mask_;
        std::array<uint8_t, narr> keys_;
    public:
        PATTERNS_CONSTEVAL XORPattern(const char* p, uint32_t seed) :
            pattern_{}, mask_{}, keys_{}
        {
            for (size_t j = 0; j < narr; ++j)
                keys_[j] = detail::generate_key(seed + static_cast<uint32_t>(j));
            length_ = narr;
            auto n = 0;
            for (auto i = 0; i < nstr; i += 2) {
                auto ptr = &p[i];
                if (*ptr == '?') {
                    pattern_[n] = 0 ^ keys_[n];
                    mask_[n] = 0;
                    ++n;
                }
                // Capture where we have our offset marker 'X' at
                else if (*ptr == 'X' || *ptr == 'x') {
                    offset_ = n;
                    if (i + 1 < nstr && p[i + 1] != ' ') {
#ifndef PATTERNS_ARM64
                        insn_len_ = get_inst_len_opt(&p[++i]);
#endif
                        while (i + 1 < nstr && p[i + 1] != ' ')
                            ++i;
                    }
                }
                // Break from parsing the pattern, since / at the end starts the flags
                else if (*ptr == '/') {
                    ++ptr;
                    handle_options(ptr);
                    break;
                }
                else if (*ptr != ' ') {
                    pattern_[n] = value(ptr) ^ keys_[n];
                    mask_[n] = 0xFF;
                    ++n;
                }
                else --i;
            }
        }
        virtual const uint8_t* pattern() const override {
            return pattern_.data();
        }
        virtual const uint8_t* mask() const override {
            return mask_.data();
        }
        // Override on [] operator to perform XOR for original byte
        virtual uint8_t operator[](size_t idx) const override {
            return pattern_[idx] ^ keys_[idx];
        }
        virtual void* find(const uint8_t* bytes, size_t size) const override {
            // Decoded only on the stack for the duration of the scan; the binary still holds just the XOR'd bytes
            std::array<uint8_t, narr> plain{};
            // Keys read through volatile: otherwise, with a constexpr pattern, the optimizer folds the XOR at compile
            // time and emits the plaintext as a constant (seen with clang -O3)
            const volatile uint8_t* keys = keys_.data();
            for (size_t j = 0; j < narr; ++j)
                plain[j] = pattern_[j] ^ keys[j];
            const auto hit = scan(bytes, size, plain.data(), mask_.data());
            return hit ? get_result(const_cast<uint8_t*>(hit), bytes + size) : nullptr;
        }
        template <typename T>
        T find(const uint8_t* bytes, size_t size) const {
            return reinterpret_cast<T>(find(bytes, size));
        }
    };

}

#ifdef PATTERNS_LITERALS
template<patterns::detail::const_string str>
PATTERNS_CONSTEVAL auto operator""_xorpattern() {
    return patterns::XORPattern<str.length, patterns::detail::pattern_length(str.data, str.size)>(str.data, str.seed);
}
#endif

#ifndef XOR_PATTERN
#define XOR_PATTERN(x) ([] { constexpr auto p = patterns::XORPattern<sizeof(x)-1, patterns::detail::pattern_length(x)>(x, patterns::detail::site_seed(__FILE__, __LINE__, __COUNTER__)); return p; }())
#endif