#pragma once
#include <cstdint>

class Pattern {
protected:
    uint32_t length_ = 0;
    uint32_t offset_ = 0;
    // Defaulting 4 byte relative address reading
    uint32_t size_ = 4;
    bool deref_ = false;
    bool align_ = false;
    bool rel_ = false;
    // Credits to EJT for the helper functions here!
    constexpr __forceinline uint8_t value(const char* c) const {
        return (get_bits(c[0]) << 4 | get_bits(c[1]));
    }
    constexpr __forceinline char get_bits(char c) const {
        return (in_range(c, '0', '9') ? (c - '0') : ((c & (~0x20)) - 'A' + 0xA));
    }
    constexpr __forceinline bool in_range(char c, char a, char b) const {
        return (c >= a && c <= b);
    }
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
    virtual const uint8_t* mask() const = 0;
    virtual const uint8_t* pattern() const = 0;
    template <typename T>
    T find(const uint8_t* bytes, size_t size) const {
        return reinterpret_cast<T>(find_internal(bytes, size));
    }
    void* find(const uint8_t* bytes, size_t size) const;
private:
    const intptr_t relative_value(uint8_t* ptr) const;
};