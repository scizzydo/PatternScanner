#pragma once
#include "Pattern.hpp"
#include <vector>

class RuntimePattern : public Pattern {
    std::vector<uint8_t> m_pattern;
    std::vector<uint8_t> m_mask;
public:
    RuntimePattern(const char* p);
    ~RuntimePattern() = default;
    virtual const uint8_t* pattern() const override;
    virtual const uint8_t* mask() const override;
};