#pragma once
#include "Pattern.hpp"
#include <cstddef>
#include <vector>
#include <stdexcept>

namespace patterns {

    class RuntimePattern final : public Pattern {
        std::vector<uint8_t> m_pattern;
        std::vector<uint8_t> m_mask;
    public:
        // target: the architecture of the code being scanned, for /d /r, X<len> and /a (see patterns::arch)
        RuntimePattern(const char* p, size_t len, arch target = host_arch) {
            arch_ = target;
            length_ = static_cast<uint32_t>(parse(p, len, [&](size_t, uint8_t byte, uint8_t mask) {
                m_pattern.push_back(byte);
                m_mask.push_back(mask);
            }));
        }
        RuntimePattern(const char* p, arch target = host_arch) :
            RuntimePattern(p, strlen(p), target)
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

inline auto operator""_rtpattern(const char* str, size_t size) {
    return patterns::RuntimePattern(str, size);
}