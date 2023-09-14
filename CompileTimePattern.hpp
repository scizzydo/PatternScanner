#pragma once
#include "Pattern.hpp"
#include <array>

template<size_t nstr>
constexpr size_t pattern_length(const char(&s)[nstr]) {
    size_t res = 0;
    for (auto i = 0; i < nstr - 1; i += 2) {
        auto c = s[i];
        if (c == 'X' || c == 'x')
            continue;
        else if (c == '/')
            break;
        else if (c != ' ')
            ++res;
        else --i;
    }
    while (res % sizeof(void*))
        ++res;
    return res;
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
            if (*ptr == '?') {
                m_pattern[n] = 0;
                m_mask[n] = 0;
                ++n;
            }
            // Capture where we have our offset marker 'X' at
            else if (*ptr == 'X' || *ptr == 'x')
                offset_ = n;
            // Break from parsing the pattern, since / at the end starts the flags
            else if (*ptr == '/') {
                ++ptr;
                while (*ptr) {
                    if (*ptr == 'd') {
                        static_assert(rel_ == false, "Cannot use relative and dereference together.");
                        deref_ = true;
                    }
                    else if (*ptr == 'r') {
                        static_assert(deref_ == false, "Cannot use relative and dereference together.");
                        rel_ = true;
                    }
                    else if (*ptr == 'a')
                        align_ = true;
                    // Check the next character to see what size we're reading at this relative address
                    else if (*ptr > '0' && (sizeof(void*) == 0x8 ? *ptr < '9' : *ptr < '5')) {
                        size_ = *ptr - '0';
                        static_assert((size_ & (size_ - 1)) == 0, "Value for the relative address is not a valid base 2 digit");
                    }
                    ++ptr;
                }
                break;
            }
            else if (*ptr != ' ') {
                m_pattern[n] = value(ptr);
                m_mask[n] = 0xFF;
                ++n;
            }
            else --i;
        }
        while (n % sizeof(void*)) {
            m_pattern[n] = 0;
            m_mask[n] = 0;
            ++n;
        }
    }
    virtual const uint8_t* pattern() const override {
        return m_pattern.data();
    }
    virtual const uint8_t* mask() const override {
        return m_mask.data();
    }
};

#ifndef COMPILETIME_PATTERN
#define COMPILETIME_PATTERN(x) CompileTimePattern<sizeof(x)-1, pattern_length(x)>(x)
#endif