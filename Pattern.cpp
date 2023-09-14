#include "Pattern.hpp"

extern "C" {
    #include "nmd/nmd_assembly.h"
}

const intptr_t Pattern::relative_value(uint8_t* ptr) const {
    switch(size_) {
    case 1:
        return static_cast<intptr_t>(*reinterpret_cast<int8_t*>(ptr));
    case 2:
        return static_cast<intptr_t>(*reinterpret_cast<int16_t*>(ptr));
    case 4:
        return static_cast<intptr_t>(*reinterpret_cast<int32_t*>(ptr));
#if ((ULLONG_MAX) != (UINT_MAX))
    case 8:
        return static_cast<intptr_t>(*reinterpret_cast<int64_t*>(ptr));
#endif
    }
    // Should never hit here
    return NULL;
}

void* Pattern::find(const uint8_t* bytes, size_t size) const {
    void* result = nullptr;
    const auto pattern = const_cast<uint8_t*>(this->pattern());
    const auto mask = const_cast<uint8_t*>(this->mask());
    const auto end = bytes + size - length_;
    for (auto i = const_cast<uint8_t*>(bytes); i < end; align_ ? i += sizeof(void*) : ++i) {
        bool found = true;
        for (auto j = 0U; j < length_; j += sizeof(void*)) {
            const auto data = *reinterpret_cast<uintptr_t*>(pattern + j);
            const auto msk = *reinterpret_cast<uintptr_t*>(mask + j);
            const auto mem = *reinterpret_cast<uintptr_t*>(i + j);
            if (data ^ mem & msk) {
                found = false;
                break;
            }
        }
        if (found) {
            if (deref_ || rel_) {
                const auto relative_address = relative_value(i + offset_);
                if (deref_) {
                    auto instrlen = nmd_x86_ldisasm(i, end - i, 
                        static_cast<NMD_X86_MODE>(sizeof(void*)));
                    while (instrlen < offset_)
                        instrlen += nmd_x86_ldisasm(i + instrlen, (end - i) - instrlen, 
                            static_cast<NMD_X86_MODE>(sizeof(void*)));
                    result = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(i) 
                        + instrlen + relative_address);
                } else {
                    result = reinterpret_cast<void*>(relative_address);
                }
            }
            else {
                result = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(i) + offset_);
            }
            break;
        }
    }
    return result;
}