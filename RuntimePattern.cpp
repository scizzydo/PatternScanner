#include "RuntimePattern.h"

#include <cstring>
#include <stdexcept>

RuntimePattern::RuntimePattern(const char* p) {
    int n = 0;
    for (int i = 0; i < strlen(p); i += 2) {
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
            while (*ptr) {
                if (*ptr == 'd') {
                    if (rel_)
                        throw std::runtime_error("Cannot use relative and dereference together.");
                    deref_ = true;
                }
                else if (*ptr == 'r'){
                    if (deref_)
                        throw std::runtime_error("Cannot use relative and dereference together.");
                    rel_ = true;
                }
                else if (*ptr == 'a')
                    align_ = true;
                // Check the next character to see what size we're reading at this relative address
                else if (*ptr > '0' && (sizeof(void*) == 0x8 ? *ptr < '9' : *ptr < '5')) {
                    size_ = *ptr - '0';
                    if ((size_ & (size_ - 1)) != 0)
                        throw std::runtime_error("Value for the relative address is not a valid base 2 digit");
                }
                ++ptr;
            }
            break;
        }
        else if (*ptr != ' ') {
            m_pattern.push_back(value(ptr));
            m_mask.push_back(0xFF);
            ++n;
        }
        else i--;
    }
    while (n % sizeof(void*)) {
        m_pattern.push_back(0);
        m_mask.push_back(0);
        ++n;
    }
    length_ = n;
}

const uint8_t* RuntimePattern::pattern() const {
    return m_pattern.data();
}

const uint8_t* RuntimePattern::mask() const {
    return m_mask.data();
}