#pragma once
#include "Pattern.hpp"
#include <array>

namespace patterns {

    namespace detail {
        constexpr size_t pattern_length(const char* s, size_t nstr) {
            return parse_bytes(s, nstr - 1, [](size_t, char, char) {}, [](size_t, const char*) {}, [](const char*) {});
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
            parse(p, nstr, [&](size_t n, uint8_t byte, uint8_t mask) { m_pattern[n] = byte; m_mask[n] = mask; });
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
