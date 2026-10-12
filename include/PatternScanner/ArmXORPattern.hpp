#pragma once
#include "ArmPattern.hpp"
#include "XORPattern.hpp"
#include <array>

namespace patterns {

    // ArmPattern with the instruction words and masks stored XOR'd, like XORPattern
    template <size_t nstr, size_t narr>
    class ArmXORPattern final : public Pattern {
        std::array<uint32_t, narr> m_instructions{};
        std::array<uint32_t, narr> m_masks{};
        std::array<uint32_t, narr> m_keys{};
        std::array<uint32_t, narr> m_mask_keys{};
    public:
        PATTERNS_CONSTEVAL ArmXORPattern(const char* p, uint32_t seed) :
            m_instructions{}, m_masks{}, m_keys{}, m_mask_keys{}
        {
            arch_ = arch::arm64;
            length_ = narr * 4;
            align_ = true;
            for (size_t j = 0; j < narr; ++j) {
                for (uint32_t b = 0; b < 4; ++b) {
                    const auto at = seed + static_cast<uint32_t>(j * 4 + b);
                    m_keys[j] |= static_cast<uint32_t>(detail::generate_key(at)) << (b * 8);
                    m_mask_keys[j] |= static_cast<uint32_t>(detail::generate_key(at, detail::mask_keys)) << (b * 8);
                }
            }
            // Encoded here at compile time; only the XOR'd words make it into the binary
            detail::parse_arm(p, nstr,
                [&](size_t i, const char* instruction) {
                    const auto encoded = detail::a64_encode_instruction(instruction);
                    m_instructions[i] = encoded.pattern ^ m_keys[i];
                    m_masks[i] = encoded.mask ^ m_mask_keys[i];
                },
                [&](size_t i) { offset_ = static_cast<uint32_t>(i * 4); },
                [&](const char* flags) { handle_options(flags); });
        }
        virtual const uint8_t* pattern() const override {
            return reinterpret_cast<const uint8_t*>(m_instructions.data());
        }
        // XOR'd like pattern(); unmask() gives the original
        virtual const uint8_t* mask() const override {
            return reinterpret_cast<const uint8_t*>(m_masks.data());
        }
        uint8_t unmask(size_t idx) const {
            return byte(m_masks[idx / 4] ^ m_mask_keys[idx / 4], idx);
        }
        // Override on [] operator to perform XOR for original byte
        virtual uint8_t operator[](size_t idx) const override {
            return byte(m_instructions[idx / 4] ^ m_keys[idx / 4], idx);
        }
        virtual const uint8_t* match(const uint8_t* bytes, size_t size) const override {
            // Decoded only on the stack for the duration of the scan; the binary still holds just the XOR'd words
            std::array<uint32_t, narr> plain{}, plain_mask{};
            // Keys read through volatile so the optimizer can't fold the XOR and emit the plaintext (see XORPattern)
            const volatile uint32_t* keys = m_keys.data();
            const volatile uint32_t* mask_keys = m_mask_keys.data();
            for (size_t j = 0; j < narr; ++j) {
                plain[j] = m_instructions[j] ^ keys[j];
                plain_mask[j] = m_masks[j] ^ mask_keys[j];
            }
            return scan(bytes, size, reinterpret_cast<const uint8_t*>(plain.data()),
                        reinterpret_cast<const uint8_t*>(plain_mask.data()));
        }
    private:
        // Byte idx % 4 of a word, in memory order like pattern() and mask()
        static uint8_t byte(uint32_t word, size_t idx) {
            uint8_t bytes[4];
            memcpy(bytes, &word, 4);
            return bytes[idx % 4];
        }
    };
}

#ifdef PATTERNS_LITERALS
template<patterns::detail::const_string str>
PATTERNS_CONSTEVAL auto operator""_armxorpattern() {
    return patterns::ArmXORPattern<str.length, patterns::detail::total_instructions(str.data, str.size)>(str.data, str.seed);
}
#endif

#ifndef ARM_XOR_PATTERN
#define ARM_XOR_PATTERN(x) ([] { constexpr auto p = patterns::ArmXORPattern<sizeof(x)-1, patterns::detail::total_instructions(x)>(x, patterns::detail::site_seed(__FILE__, __LINE__, __COUNTER__)); return p; }())
#endif
