#pragma once
#include "CompileTimePattern.hpp"
#include <array>

namespace patterns {
    namespace detail {
        // Used to generate the pattern string hash
        constexpr uint32_t fnv1a(const char* s, size_t count) {
            return ((count ? fnv1a(s, count - 1) : 2166136261u) ^ s[count]) * 16777619u;
        }

        template<size_t count>
        constexpr __forceinline uint32_t fnv1a(const char(&s)[count]) {
            return fnv1a(s, count - 1);
        }

        template<uint32_t seed>
        constexpr __forceinline uint8_t generate_key() {
            uint32_t value = 2166136261u + seed;
            for (char c : __TIME__)
                value = static_cast<uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<uint32_t hash, size_t... Keys>
        constexpr auto generate_keys(std::index_sequence<Keys...>) {
            return std::array<uint8_t, sizeof...(Keys)>{ detail::generate_key<hash + Keys>()...};
        }
    }

    template<size_t nstr, size_t narr, uint32_t hash>
    class XORPattern : public Pattern {
        std::array<uint8_t, narr> pattern_;
        std::array<uint8_t, narr> mask_;
        std::array<uint8_t, narr> keys_;
    public:
        constexpr XORPattern(const char* p) :
            pattern_{}, mask_{}, keys_{ detail::generate_keys<hash>(std::make_index_sequence<narr>()) }
        {
            length_ = narr;
            auto n = 0;
            for (auto i = 0; i < nstr; i += 2) {
                auto ptr = &p[i];
                if (*ptr == '?') {
                    pattern_[n] = 0 ^ keys_[n];
                    mask_[n] = 0;
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
                    pattern_[n] = value(ptr) ^ keys_[n];
                    mask_[n] = 0xFF;
                    ++n;
                }
                else --i;
            }
        }
        virtual const uint8_t* pattern() const override {
            return pattern_.data();
        }
        virtual const uint8_t* mask() const override {
            return mask_.data();
        }
        // Override on [] operator to perform XOR for original byte
        virtual uint8_t operator[](size_t idx) const override {
            return pattern_[idx] ^ keys_[idx];
        }
        virtual void* find(const uint8_t* bytes, size_t size) const override {
            void* result = nullptr;
            const auto end = bytes + size - length_;
            for (auto i = const_cast<uint8_t*>(bytes); i < end; align_ ? i += sizeof(void*) : ++i) {
                bool found = true;
                for (auto j = 0U; j < length_; ++j) {
                    if (mask_[j] == 0xFF && (*this)[j] != i[j]) {
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
        template <typename T>
        T find(const uint8_t* bytes, size_t size) const {
            return reinterpret_cast<T>(find(bytes, size));
        }
    };

}

#if __cplusplus > 201703L
template<patterns::detail::const_string str>
constexpr auto operator"" _xorpattern() {
    return patterns::XORPattern<str.length, patterns::detail::pattern_length(str.data, str.size, false), patterns::detail::fnv1a(str.data, str.length)>(str.data);
}
#else
#ifndef XOR_PATTERN
#define XOR_PATTERN(x) patterns::XORPattern<sizeof(x)-1, patterns::detail::pattern_length(x, false), patterns::detail::fnv1a(x)>(x)
#endif
#endif