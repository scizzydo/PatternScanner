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
            // The parser reads up to a terminator, so work on a terminated copy
            const std::string s(text, len);
            const char* p = s.c_str();
            // Same parsing as the ArmPattern constructor
            size_t options = detail::skip_past(p, 0, '/');
            if (options && p[options - 1] == '/') handle_options(&p[options]);
            align_ = true;
            for (size_t i = 0; p[i];) {
                char line[detail::max_line] = {};
                i = detail::read_line(p, i, line);
                if (line[0] == '/') break;
                if (!line[0]) continue;
                size_t start = 0;
                if (line[0] == 'X') { offset_ = static_cast<uint32_t>(m_instructions.size() * 4); start = detail::skip_whitespace(line, 1); }
                auto encoded = detail::a64_encode_instruction(&line[start]);
                m_instructions.push_back(encoded.pattern);
                m_masks.push_back(encoded.mask);
            }
            length_ = static_cast<uint32_t>(m_instructions.size() * 4);
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
