#pragma once
#include <cstdint>
#include <stdexcept>

namespace patterns {
    // Define your own ldisasm in use if using dereference
    extern size_t ldisasm(const void* buffer, size_t buffer_size);

    class Pattern {
    protected:
        uint32_t length_ = 0;
        uint32_t offset_ = 0;
        // Defaulting 4 byte relative address reading
        uint32_t size_ = 4;
        bool deref_ = false;
        bool align_ = false;
        bool rel_ = false;
    public:
        Pattern() = default;
        ~Pattern() = default;
        const uint32_t __forceinline length() const {
            return length_;
        }
        const uint32_t __forceinline offset() const {
            return offset_;
        }
        const bool __forceinline deref() const {
            return deref_;
        }
        const bool __forceinline aligned() const {
            return align_;
        }
        const bool __forceinline relative() const {
            return rel_;
        }
        virtual const uint8_t* mask() const = 0;
        virtual const uint8_t* pattern() const = 0;
        template <typename T>
        T find(const uint8_t* bytes, size_t size) const {
            return reinterpret_cast<T>(find(bytes, size));
        }
        virtual void* find(const uint8_t* bytes, size_t size) const {
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
                            auto instrlen = ldisasm(i, end - i);
                            while (instrlen < offset_)
                                instrlen += ldisasm(i + instrlen, (end - i) - instrlen);
                            result = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(i)
                                + instrlen + relative_address);
                        }
                        else {
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
        virtual uint8_t operator[](size_t idx) const {
            return pattern()[idx];
        }
    protected:
        // Credits to EJT for the helper functions here!
        constexpr __forceinline uint8_t value(const char* c) const {
            return (get_bits(c[0]) << 4 | get_bits(c[1]));
        }
        constexpr __forceinline char get_bits(char c) const {
            return ('9' >= c && '0' <= c) ? (c - '0') : ((c & (~0x20)) - 'A' + 0xA);
        }
        constexpr void handle_options(const char* ptr) {
            while (*ptr) {
                if (*ptr == 'd') {
                    if (rel_) throw std::logic_error("Cannot use relative and deref together!");
                    deref_ = true;
                }
                else if (*ptr == 'r') {
                    if (deref_) throw std::logic_error("Cannot use relative and deref together!");
                    rel_ = true;
                }
                else if (*ptr == 'a')
                    align_ = true;
                // Check the next character to see what size we're reading at this relative address
                else if (*ptr > '0' && (sizeof(void*) == 0x8 ? *ptr < '9' : *ptr < '5')) {
                    size_ = *ptr - '0';
                    if ((size_ & (size_ - 1)) != 0) throw std::logic_error("Size is not a valid data type size!");
                }
                ++ptr;
            }
        }
        const intptr_t relative_value(uint8_t* ptr) const {
            switch (size_) {
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
    };
}