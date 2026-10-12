#pragma once
#include "Pattern.hpp"
#include <array>

namespace patterns {

    namespace detail {
        constexpr size_t pattern_length(const char* s, size_t nstr) {
            size_t res = 0;
            for (size_t i = 0; i < nstr - 1; i += 2) {
                auto c = s[i];
                if (c == 'X' || c == 'x') {
                    while (i + 1 < nstr && s[i + 1] != ' ')
                        ++i;
                    continue;
                }
                else if (c == '/')
                    break;
                else if (c != ' ')
                    ++res;
                else --i;
            }
            return res;
        }

        template<size_t nstr>
        constexpr size_t pattern_length(const char(&s)[nstr]) {
            return pattern_length(s, nstr);
        }
    }

    template<size_t nstr, size_t narr>
    class CompileTimePattern final : public Pattern {
        std::array<uint8_t, narr> m_pattern;
        std::array<uint8_t, narr> m_mask;
    public:
        PATTERNS_CONSTEVAL CompileTimePattern(const char* p) :
            m_pattern{}, m_mask{}
        {
            length_ = narr;
            auto n = 0;
            for (size_t i = 0; i < nstr; i += 2) {
                auto ptr = &p[i];
                if (p[i] == '?') {
                    m_pattern[n] = 0;
                    m_mask[n] = 0;
                    ++n;
                }
                // Capture where we have our offset marker 'X' at
                else if (*ptr == 'X' || *ptr == 'x') {
                    offset_ = n;
                    if (i + 1 < nstr && p[i + 1] != ' ') {
                        if (arch_ != arch::arm64)
                            insn_len_ = get_inst_len_opt(&p[i + 1]);
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
                    m_pattern[n] = value(ptr);
                    m_mask[n] = 0xFF;
                    ++n;
                }
                else --i;
            }
        }
        virtual const uint8_t* pattern() const override {
            return m_pattern.data();
        }
        virtual const uint8_t* mask() const override {
            return m_mask.data();
        }
    };
}

#ifdef PATTERNS_LITERALS
template<patterns::detail::const_string str>
PATTERNS_CONSTEVAL auto operator""_ctpattern() {
    return patterns::CompileTimePattern<str.length, patterns::detail::pattern_length(str.data, str.size)>(str.data);
}
#endif

#ifndef COMPILETIME_PATTERN
#define COMPILETIME_PATTERN(x) ([] { constexpr auto p = patterns::CompileTimePattern<sizeof(x)-1, patterns::detail::pattern_length(x)>(x); return p; }())
#endif
