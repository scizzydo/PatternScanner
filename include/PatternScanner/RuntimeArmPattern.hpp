#pragma once
#include "ArmPattern.hpp"
#include <string>
#include <vector>

namespace patterns {

    // ArmPattern built at runtime, for text only known then (user input, config files). Same syntax and results;
    // like RuntimePattern, the text is in the binary if it's a literal.
    class RuntimeArmPattern final : public Pattern {
        std::vector<uint32_t> m_instructions;
        std::vector<uint32_t> m_masks;
    public:
        RuntimeArmPattern(const char* text, size_t len) {
            arch_ = arch::arm64;
            align_ = true;
            // The parser reads up to a terminator, so work on a terminated copy
            const std::string s(text, len);
            const auto count = detail::parse_arm(s.c_str(), len,
                [&](size_t, const char* instruction) {
                    const auto encoded = detail::a64_encode_instruction(instruction);
                    m_instructions.push_back(encoded.pattern);
                    m_masks.push_back(encoded.mask);
                },
                [&](size_t i) { offset_ = static_cast<uint32_t>(i * 4); },
                [&](const char* flags) { handle_options(flags); });
            length_ = static_cast<uint32_t>(count * 4);
        }
        explicit RuntimeArmPattern(const char* text) :
            RuntimeArmPattern(text, strlen(text))
        {
        }
        virtual const uint8_t* pattern() const override {
            return reinterpret_cast<const uint8_t*>(m_instructions.data());
        }
        virtual const uint8_t* mask() const override {
            return reinterpret_cast<const uint8_t*>(m_masks.data());
        }
    };
}
