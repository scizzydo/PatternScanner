#pragma once
#include "Pattern.hpp"
#include <array>

namespace patterns {

    namespace detail {
        constexpr size_t pattern_length(const char* s, size_t nstr, bool pad = true) {
            size_t res = 0;
#ifdef __arm64__
            bool align = false;
#endif
            for (auto i = 0; i < nstr - 1; i += 2) {
                auto c = s[i];
                if (c == 'X' || c == 'x') {
                    while (s[i + 1] != ' ')
                        ++i;
                    continue;
                }
                else if (c == '/') {
#ifdef __arm64__
                    while (i < nstr - 1 && (c = s[++i])) {
                        if (c == 'a') {
                            align = true;
                            break;
                        }
                    }
#endif
                    break;
                }
                else if (c != ' ')
                    ++res;
                else --i;
            }
#ifdef __arm64__
            while (pad && align && res % sizeof(uint32_t))
                ++res;
#else
            while (pad && res % sizeof(void*))
                ++res;
#endif
            return res;
        }

        template<size_t nstr>
        constexpr size_t pattern_length(const char(&s)[nstr], bool pad = true) {
            return pattern_length(s, nstr, pad);
        }

#if __cplusplus > 201703L
        template <size_t nstr>
        struct const_string {
            char data[nstr]{};
            static constexpr size_t length = nstr - 1;
            static constexpr size_t size = nstr;

            constexpr const_string(const char(&s)[nstr]) {
                std::copy_n(s, length, data);
            }
        };
#endif
    }

    template<size_t nstr, size_t narr>
    class CompileTimePattern : public Pattern {
        std::array<uint8_t, narr> m_pattern;
        std::array<uint8_t, narr> m_mask;
    public:
        constexpr CompileTimePattern(const char* p) :
            m_pattern{}, m_mask{}
        {
            length_ = narr;
            auto n = 0;
            for (auto i = 0; i < nstr; i += 2) {
                auto ptr = &p[i];
                if (p[i] == '?') {
                    m_pattern[n] = 0;
                    m_mask[n] = 0;
                    ++n;
                }
                // Capture where we have our offset marker 'X' at
                else if (*ptr == 'X' || *ptr == 'x') {
                    offset_ = n;
                    if (p[i + 1] != ' ') {
                        insn_len_ = get_inst_len_opt(&p[++i]);
                        while (p[i + 1] != ' ')
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
#ifdef __arm64__
            while (align_ && n % align_size_) {
                m_pattern[n] = 0;
                m_mask[n] = 0;
                ++n;
            }
#else
            while (n % sizeof(void*)) {
                m_pattern[n] = 0;
                m_mask[n] = 0;
                ++n;
            }
#endif
        }
        virtual const uint8_t* pattern() const override {
            return m_pattern.data();
        }
        virtual const uint8_t* mask() const override {
            return m_mask.data();
        }
    };
}

#if __cplusplus > 201703L
template<patterns::detail::const_string str>
constexpr auto operator"" _ctpattern() {
    return patterns::CompileTimePattern<str.length, patterns::detail::pattern_length(str.data, str.size)>(str.data);
}
#else
#ifndef COMPILETIME_PATTERN
#define COMPILETIME_PATTERN(x) patterns::CompileTimePattern<sizeof(x)-1, patterns::detail::pattern_length(x)>(x)
#endif
#endif
