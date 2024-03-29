#pragma once
#include "Pattern.hpp"
#include <vector>
#include <stdexcept>

namespace patterns {

    class RuntimePattern : public Pattern {
        std::vector<uint8_t> m_pattern;
        std::vector<uint8_t> m_mask;
    public:
        RuntimePattern(const char* p, size_t len) {
            int n = 0;
            for (int i = 0; i < len; i += 2) {
                auto ptr = &p[i];
                if (*ptr == '?') {
                    m_pattern.push_back(0);
                    m_mask.push_back(0);
                    ++n;
                }
                // Capture where we have our offset marker 'X' at
                else if (*ptr == 'X' || *ptr == 'x')
                    offset_ = n;
                // Break from parsing the pattern, since / at the end starts the flags
                else if (*ptr == '/') {
                    ++ptr;
                    handle_options(ptr);
                    break;
                }
                else if (*ptr != ' ') {
                    m_pattern.push_back(value(ptr));
                    m_mask.push_back(0xFF);
                    ++n;
                }
                else i--;
            }
#ifndef __arm64__
            while (n % sizeof(void*)) {
                m_pattern.push_back(0);
                m_mask.push_back(0);
                ++n;
            }
#endif
            length_ = n;
        }
        RuntimePattern(const char* p) :
            RuntimePattern(p, strlen(p))
        {
        }
        ~RuntimePattern() = default;
        virtual const uint8_t* pattern() const override {
            return m_pattern.data();
        }
        virtual const uint8_t* mask() const override {
            return m_mask.data();
        }
    };
}

auto operator"" _rtpattern(const char* str, size_t size) {
    return patterns::RuntimePattern(str, size);
}