#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

// Define PATTERNS_NO_SIMD where vector registers are off-limits (e.g. kernel code); find() then uses 64-bit integer (SWAR) scanning
#if defined(PATTERNS_NO_SIMD)
#elif (defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)) && !defined(_M_ARM64EC)
#include <emmintrin.h>
#define PATTERNS_SSE2
#elif defined(__ARM_NEON) || defined(_M_ARM64)
#include <arm_neon.h>
#define PATTERNS_NEON
#endif

#ifndef _MSC_VER
#define __forceinline inline __attribute__((always_inline))
#endif

// Compile-time patterns must never be built at runtime: that would put the pattern text in the binary.
// consteval enforces it (C++20); before that the macros force it with a constexpr local.
#ifdef __cpp_consteval
#define PATTERNS_CONSTEVAL consteval
#else
#define PATTERNS_CONSTEVAL constexpr
#endif

// String literal operators (_ctpattern, _xorpattern, _armpattern) need C++20. MSVC reports __cplusplus as
// 199711L unless /Zc:__cplusplus is passed, so check _MSVC_LANG as well
#if __cplusplus > 201703L || (defined(_MSVC_LANG) && _MSVC_LANG > 201703L)
#define PATTERNS_LITERALS
#if __has_include(<source_location>)
#include <source_location>
#endif
#endif

namespace patterns {
    namespace detail {
        constexpr uint32_t hash(const char* s, uint32_t h = 2166136261u) {
            while (*s)
                h = (h ^ static_cast<uint8_t>(*s++)) * 16777619u;
            return h;
        }

        // Unique per definition site (file + line + column/counter), so identical patterns get different XOR keys
        constexpr uint32_t site_seed(const char* file, uint32_t line, uint32_t column) {
            return hash(file) ^ line * 0x9E3779B1u ^ column * 0x85EBCA77u;
        }

#ifdef PATTERNS_LITERALS
        // Literal operator template argument. The defaulted source_location is evaluated where the literal is
        // written, which is how "..."_xorpattern gets per-definition keys without a macro
        template <size_t nstr>
        struct const_string {
            char data[nstr]{};
            uint32_t seed = 0;
            static constexpr size_t length = nstr - 1;
            static constexpr size_t size = nstr;

#ifdef __cpp_lib_source_location
            PATTERNS_CONSTEVAL const_string(const char(&s)[nstr], std::source_location loc = std::source_location::current())
                : seed(site_seed(loc.file_name(), loc.line(), loc.column())) {
#else
            // No source_location (older standard library): keys still vary per pattern and per build, not per site
            PATTERNS_CONSTEVAL const_string(const char(&s)[nstr]) : seed(hash(s)) {
#endif
                for (size_t i = 0; i < nstr; ++i)
                    data[i] = s[i];
            }
        };
#endif
        constexpr bool __forceinline is_digit(char c) {
            return c <= '9' && c >= '0';
        }
        constexpr bool __forceinline is_hex_digit(char c) {
            return is_digit(c) || ((c | 0x20) >= 'a' && (c | 0x20) <= 'f');
        }
        constexpr __forceinline char get_bits(char c) {
            return is_digit(c) ? (c - '0') : ((c & (~0x20)) - 'A' + 0xA);
        }
        template<typename T = int32_t>
        constexpr T stoi_impl(const char* str, T value = 0, bool negative = false, bool hex = false) {
            if (*str == '\0') return negative ? -value : value;
            if (hex) {
                if (is_hex_digit(*str))
                    return stoi_impl<T>(str + 1, get_bits(*str) + value * 16, negative, hex);
            } else {
                if (is_digit(*str))
                    return stoi_impl<T>(str + 1, (*str - '0') + value * 10, negative, hex);
            }
            return negative ? -value : value;
        }
        template<typename T = int32_t>
        constexpr T stoi(const char* str) {
            if (*str == '-') {
                ++str;
                if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
                    return stoi_impl<T>(str + 2, 0, true, true);
                return stoi_impl<T>(str, 0, true);
            }
            if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
                return stoi_impl<T>(str + 2, 0, false, true);
            return stoi_impl<T>(str);
        }

        // Masked compare, 8 bytes at a time (memcpy keeps unaligned loads legal; compilers emit a single mov)
        inline bool masked_equal(const uint8_t* at, const uint8_t* pat, const uint8_t* msk, size_t len) {
            size_t j = 0;
            for (; j + 8 <= len; j += 8) {
                uint64_t d, p, m;
                memcpy(&d, at + j, 8); memcpy(&p, pat + j, 8); memcpy(&m, msk + j, 8);
                if ((d ^ p) & m) return false;
            }
            for (; j < len; ++j)
                if ((at[j] ^ pat[j]) & msk[j]) return false;
            return true;
        }
#ifdef __arm64__
        template<typename T>
        T extract_bitfield(uint32_t insn, unsigned width, unsigned offset) {
            constexpr size_t int_width = sizeof(int32_t) * 8;
            return (static_cast<T>(insn) << (int_width - (offset + width))) >> (int_width - width);
        }

        bool __forceinline decode_masked_match(uint32_t insn, uint32_t mask, uint32_t pattern) {
            return (insn & mask) == pattern;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/NOP--No-Operation-
        inline bool a64_decode_nop(uint32_t insn) {
            if (insn == 0b1101'0101'0000'0011'0010'0000'0001'1111)
                return true;
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/B--Branch-
        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/BL--Branch-with-Link-
        inline bool a64_decode_b(uint32_t insn, bool* is_bl, int64_t* offset) {
            // x001 01?? ???? ???? ???? ???? ???? ????
            // 1 - BL
            // 0 - B
            if (decode_masked_match(insn, 0b0111'1100'0000'0000'0000'0000'0000'0000, 0b0001'0100'0000'0000'0000'0000'0000'0000)) {
                if (is_bl) *is_bl = (insn >> 31) & 0x1;
                *offset = extract_bitfield<int32_t>(insn, 26, 0) << 2;
                return true;
            }
            return false;
        }
        
        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/ADR--Form-PC-relative-address-
        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/ADRP--Form-PC-relative-address-to-4KB-page-
        inline bool a64_decode_adr(uint32_t insn, bool* is_adrp, unsigned* rd, int64_t* offset) {
            // rd - destination register
            // x??1 0000 ???? ???? ???? ???? ???? ????
            // 1 - ADRP
            // 0 - ADR
            // bits 30 & 29 - immlo
            // bits 23 -> 5 - immhi
            // bits 4 -> 0 - rd
            if (decode_masked_match(insn, 0b0001'1111'0000'0000'0000'0000'0000'0000, 0b0001'0000'0000'0000'0000'0000'0000'0000)) {
                if (rd) *rd = insn & 0x1f;
                uint32_t immlo = (insn >> 29) & 0x3;
                int32_t immhi = extract_bitfield<int32_t>(insn, 19, 5) << 2;
                auto adrp = (insn >> 31) & 0x1;
                if (is_adrp) *is_adrp = adrp;
                *offset = (adrp ? (immhi | immlo) * 4096 : (immhi | immlo));
                return true;
            }
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/LDRH--immediate---Load-Register-Halfword--immediate--
        inline bool a64_decode_ldrh(uint32_t insn, unsigned* rn, unsigned* rt, int64_t* offset) {
            // rn - name of general-purpose base register or stack pointer
            // rt - name of general-purpose base register to be transfered
            // Post-index & Pre-index masks
            // 0111 1000 010? ???? ???? x1?? ???? ????
            //                          1 - pre-index
            //                          0 - post-index
            if (decode_masked_match(insn, 0b1111'1111'1110'0000'0000'0100'0000'0000, 0b0111'1000'0100'0000'0000'0100'0000'0000)) {
                *offset = extract_bitfield<int32_t>(insn, 9, 12);
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (rt) *rt = insn & 0x1f;
                return true;
            }
            // Unsigned offset mask
            // 0111 1001 01?? ???? ???? ???? ???? ????
            if (decode_masked_match(insn, 0b1111'1111'1100'0000'0000'0000'0000'0000, 0b0111'1001'0100'0000'0000'0000'0000'0000)) {
                *offset = extract_bitfield<uint32_t>(insn, 12, 10) << 1;
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (rt) *rt = insn & 0x1f;
                return true;
            }
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/LDR--immediate---Load-Register--immediate--
        inline bool a64_decode_ldr(uint32_t insn, unsigned* rn, unsigned* rt, int64_t* offset) {
            // rn - name of general-purpose base register or stack pointer
            // rt - name of general-purpose register to be transferred
            // Post-index & Pre-index masks
            // 1x11 1000 010? ???? ???? x1?? ???? ????
            //  1 - 64 bit              1 - pre-index
            //  0 - 32 bit              0 - post-index
            if (decode_masked_match(insn, 0b1011'1111'1110'0000'0000'0100'0000'0000, 0b1011'1000'0100'0000'0000'0100'0000'0000)) {
                // Have not tested this yet
                *offset = extract_bitfield<int32_t>(insn, 9, 12);
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (rt) *rt = insn & 0x1f;
                return true;
            }
            // Unsigned offset mask
            // 1x11 1001 01?? ???? ???? ???? ???? ????
            //  1 - 64 bit
            //  0 - 32 bit
            if (decode_masked_match(insn, 0b1011'1011'1100'0000'0000'0000'0000'0000, 0b1011'1001'0100'0000'0000'0000'0000'0000)) {
                *offset = extract_bitfield<uint32_t>(insn, 12, 10) << (insn >> 30);
                // bit 26 annotated as "VR" - Variant Register (Not sure it's use yet)
                //auto vr = (insn >> 26) & 1;
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (rt) *rt = insn & 0x1f;
                return true;
            }
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/STR--immediate---Store-Register--immediate--
        inline bool a64_decode_str(uint32_t insn, unsigned* rn, unsigned* rt, int64_t* offset) {
            // rn - name of general-purpose base register or stack pointer
            // rt - name of general-purpose register to be transferred
            // Post-index & Pre-index masks
            // 1x11 1000 000? ???? ???? x1?? ???? ????
            //  1 - 64 bit              1 - pre-index
            //  0 - 32 bit              0 - post-index
            if (decode_masked_match(insn, 0b1011'1011'1110'0000'0000'0100'0000'0000, 0b1011'1000'0000'0000'0000'0100'0000'0000)) {
                *offset = extract_bitfield<int32_t>(insn, 9, 12);
                // bit 26 annotated as "VR" - Variant Register (Not sure it's use yet)
                //auto vr = (insn >> 26) & 1;
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (rt) *rt = insn & 0x1f;
                return true;
            }
            // Unsigned offset mask
            // 1x11 1000 000? ???? ???? ???? ???? ????
            //  1 - 64 bit
            //  0 - 32 bit
            if (decode_masked_match(insn, 0b1011'1011'1110'0000'0000'0000'0000'0000, 0b1011'1001'0000'0000'0000'0000'0000'0000)) {
                *offset = extract_bitfield<uint32_t>(insn, 12, 10) << (insn >> 30);
                // bit 26 annotated as "VR" - Variant Register (Not sure it's use yet)
                //auto vr = (insn >> 26) & 1;
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (rt) *rt = insn & 0x1f;
                return true;
            }
            return false;
        } 

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/MOVZ--Move-wide-with-zero-
        inline bool a64_decode_movz(uint32_t insn, unsigned* sf, unsigned* rd, int64_t* offset) {
            // sf - 1 for 64 bit, 0 for 32 bit
            // rd - destination register
            // x101 0010 1xx? ???? ???? ???? ???? ????
            // 1 = 64 bit 0x - shift ammount
            // 0 = 32 bit
            if (decode_masked_match(insn, 0b0111'1111'1000'0000'0000'0000'0000'0000, 0b0101'0010'1000'0000'0000'0000'0000'0000)) {
                auto hw = (insn >> 21) & 3;
                *offset = hw ? extract_bitfield<uint32_t>(insn, 16, 5) << hw : extract_bitfield<uint32_t>(insn, 16, 5);
                if (sf) *sf = (insn >> 31) & 0x1;
                if (rd) *rd = insn & 0x1f;
                return true;
            }
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/ADD--immediate---Add--immediate--
        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/SUB--immediate---Subtract--immediate--
        inline bool a64_decode_arithmetic(uint32_t insn, bool* is_sub, unsigned* sf, unsigned* rd, unsigned* rn, int64_t* offset) {
            // rd - destination register
            // rn - source register
            // sf - 1 for 64 bit, 0 for 32 bit
            // ?x01 0001 0??? ???? ???? ???? ???? ????
            //  1 = subtraction
            //  0 = addition
            if (decode_masked_match(insn, 0b0011'1111'1000'0000'0000'0000'0000'0000, 0b0001'0001'0000'0000'0000'0000'0000'0000)) {
                if (sf) *sf = (insn >> 31) & 0x1;
                if (rd) *rd = insn & 0x1f;
                if (rn) *rn = (insn >> 5) & 0x1f;
                if (is_sub) *is_sub = (insn >> 30) & 0x1;
                uint32_t imm12 = extract_bitfield<uint32_t>(insn, 12, 10);
                // sh = 1 is LSL#12
                auto sh = (insn >> 22) & 0x1;
                *offset = (sh ? (imm12 << 12) : imm12);
                return true;
            }
            return false;
        }
#endif
    }

    class Pattern {
    protected:
        uint32_t length_ = 0;
        uint32_t offset_ = 0;
        bool deref_ = false;
#ifndef __arm64__
        // Remaining bytes from the offset when used in dereferencing
        uint32_t insn_len_ = 0;
        // Since all arm64 instructions are 32 bit and encoded, just doing deref instead of both deref and relative
        // Defaulting 4 byte relative address reading
        uint32_t size_ = 4;
        bool rel_ = false;
#endif
        bool align_ = false;
#ifdef __arm64__
        // arm64 instructions are all 32 bits, so the align scanning will be at the instruction level
        static constexpr size_t align_size_ = 4;
#else
        static constexpr size_t align_size_ = sizeof(void*);
#endif
    public:
        Pattern() = default;
        ~Pattern() = default;
        constexpr uint32_t length() const {
            return length_;
        }
        constexpr uint32_t offset() const {
            return offset_;
        }
        constexpr bool deref() const {
            return deref_;
        }
#ifndef __arm64__
        constexpr bool relative() const {
            return rel_;
        }
#endif
        constexpr bool aligned() const {
            return align_;
        }
        virtual const uint8_t* mask() const = 0;
        virtual const uint8_t* pattern() const = 0;
        template <typename T>
        T find(const uint8_t* bytes, size_t size) const {
            return reinterpret_cast<T>(find(bytes, size));
        }
        virtual void* find(const uint8_t* bytes, size_t size) const {
            const auto hit = scan(bytes, size, pattern(), mask());
            return hit ? get_result(const_cast<uint8_t*>(hit), bytes + size) : nullptr;
        }
        virtual uint8_t operator[](size_t idx) const {
            return pattern()[idx];
        }
    protected:
        // First match of pat/msk in [bytes, bytes + size). Two anchor bytes are checked first
        // (16 positions at a time with SIMD), and only positions passing both get a full compare.
        const uint8_t* scan(const uint8_t* bytes, size_t size, const uint8_t* pat, const uint8_t* msk) const {
            if (size < length_) return nullptr;
            if (!length_) return bytes;
            const size_t last = size - length_;
            const size_t step = align_ ? align_size_ : 1;
            // Aligned scans align to the absolute address, not to wherever the caller's buffer starts
            size_t i = (step - reinterpret_cast<uintptr_t>(bytes) % step) % step;
            // Anchors: first and last of the most specific bytes (most mask bits set). Far apart, so random
            // data rarely satisfies both at once
            size_t a1 = 0, a2 = 0;
            int best = 0;
            for (size_t j = 0; j < length_; ++j) {
                int bits = 0;
                for (unsigned m = msk[j]; m; m &= m - 1) ++bits;
                if (bits > best) { best = bits; a1 = a2 = j; }
                else if (bits && bits == best) a2 = j;
            }
            // All wildcards leaves m1 = m2 = 0, so every position passes the filter and gets compared
            const uint8_t m1 = msk[a1], p1 = pat[a1] & m1, m2 = msk[a2], p2 = pat[a2] & m2;
#if defined(PATTERNS_SSE2)
            const auto vm1 = _mm_set1_epi8(static_cast<char>(m1)), vp1 = _mm_set1_epi8(static_cast<char>(p1));
            const auto vm2 = _mm_set1_epi8(static_cast<char>(m2)), vp2 = _mm_set1_epi8(static_cast<char>(p2));
            auto block = [&](size_t at) {
                const auto v1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + at + a1));
                const auto v2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + at + a2));
                return static_cast<uint64_t>(static_cast<unsigned>(_mm_movemask_epi8(_mm_and_si128(
                    _mm_cmpeq_epi8(_mm_and_si128(v1, vm1), vp1), _mm_cmpeq_epi8(_mm_and_si128(v2, vm2), vp2)))));
            };
            // 64 positions per branch (measured ~1.4x over 16 on real x64 code), then 16 at a time for the remainder
            for (; i + 63 <= last; i += 64) {
                const uint64_t hits = block(i) | block(i + 16) << 16 | block(i + 32) << 32 | block(i + 48) << 48;
                if (hits)
                    for (size_t k = 0; k < 64; k += step)
                        if ((hits >> k & 1) && detail::masked_equal(bytes + i + k, pat, msk, length_))
                            return bytes + i + k;
            }
            for (; i + 15 <= last; i += 16) {
                const auto hits = block(i);
                if (hits)
                    for (size_t k = 0; k < 16; k += step)
                        if ((hits >> k & 1) && detail::masked_equal(bytes + i + k, pat, msk, length_))
                            return bytes + i + k;
            }
#elif defined(PATTERNS_NEON)
            const auto vm1 = vdupq_n_u8(m1), vp1 = vdupq_n_u8(p1), vm2 = vdupq_n_u8(m2), vp2 = vdupq_n_u8(p2);
            for (; i + 15 <= last; i += 16) {
                const auto eq = vandq_u8(vceqq_u8(vandq_u8(vld1q_u8(bytes + i + a1), vm1), vp1),
                                         vceqq_u8(vandq_u8(vld1q_u8(bytes + i + a2), vm2), vp2));
                // NEON has no movemask; a narrowing shift packs lane k into bits 4k..4k+3
                const uint64_t hits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(eq), 4)), 0);
                if (hits)
                    for (size_t k = 0; k < 16; k += step)
                        if ((hits >> (k * 4) & 1) && detail::masked_equal(bytes + i + k, pat, msk, length_))
                            return bytes + i + k;
            }
#else
            // No vector registers: same filter on 8 positions at once in a plain 64-bit integer (SWAR)
            constexpr uint64_t ones = 0x0101010101010101ULL;
            for (; i + 7 <= last; i += 8) {
                uint64_t v1, v2;
                memcpy(&v1, bytes + i + a1, 8);
                memcpy(&v2, bytes + i + a2, 8);
                // Byte k of x is zero when position i + k passes both anchors
                const uint64_t x = ((v1 & m1 * ones) ^ p1 * ones) | ((v2 & m2 * ones) ^ p2 * ones);
                // High bit set for zero bytes (may also flag a byte above a zero; masked_equal weeds those out)
                const uint64_t hits = (x - ones) & ~x & 0x8080808080808080ULL;
                if (hits)
                    for (size_t k = 0; k < 8; k += step) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        const auto lane = 7 - k;
#else
                        const auto lane = k;
#endif
                        if ((hits >> (lane * 8 + 7) & 1) && detail::masked_equal(bytes + i + k, pat, msk, length_))
                            return bytes + i + k;
                    }
            }
#endif
            // Remainder that doesn't fill a full block
            for (; i <= last; i += step)
                if ((bytes[i + a1] & m1) == p1 && (bytes[i + a2] & m2) == p2 && detail::masked_equal(bytes + i, pat, msk, length_))
                    return bytes + i;
            return nullptr;
        }
        // Credits to EJT for the helper functions here!
        constexpr __forceinline uint8_t value(const char* c) const {
            if (!detail::is_hex_digit(c[0]) || !detail::is_hex_digit(c[1]))
                throw std::logic_error("Invalid hex byte in pattern!");
            return (detail::get_bits(c[0]) << 4 | detail::get_bits(c[1]));
        }
        constexpr void handle_options(const char* ptr) {
            while (*ptr) {
#ifdef __arm64__
                if (*ptr == 'd')
                    deref_ = true;
#else
                if (*ptr == 'd') {
                    if (rel_) throw std::logic_error("Cannot use relative and deref together!");
                    deref_ = true;
                }
                else if (*ptr == 'r') {
                    if (deref_) throw std::logic_error("Cannot use relative and deref together!");
                    rel_ = true;
                }
#endif
                else if (*ptr == 'a')
                    align_ = true;
#ifndef __arm64__
                // Check the next character to see what size we're reading at this relative address
                else if (*ptr > '0' && (sizeof(void*) == 0x8 ? *ptr < '9' : *ptr < '5')) {
                    size_ = *ptr - '0';
                    if ((size_ & (size_ - 1)) != 0) throw std::logic_error("Size is not a valid data type size!");
                }
#endif
                ++ptr;
            }
        }
        void* get_result(uint8_t* address, const uint8_t* end) const {
#ifdef __arm64__
            if (deref_) {
                auto insn = reinterpret_cast<uint32_t*>(address + offset_);
                int64_t offset = 0;
                bool is_sub = false, is_adrp = false;
                unsigned rd = 0, sf = 0, rn = 0;
                if (detail::a64_decode_b(*insn, nullptr, &offset)) {
                    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(insn) + offset);
                }
                else if (detail::a64_decode_adr(*insn, &is_adrp, &rd, &offset)) {
                    auto saved_offset = offset;
                    auto saved_rd = rd;
                    auto curr_insn = insn + 1;
                    if (is_adrp) {
                        while (*curr_insn) {
                            unsigned rt = 0;
                            if (detail::a64_decode_arithmetic(*curr_insn, &is_sub, &sf, &rd, &rn, &offset)) {
                                if (saved_rd == rd && rn == rd) {
                                    uint64_t val = (sf ? offset : static_cast<uint32_t>(offset));
                                    if (is_sub) saved_offset -= val;
                                    else saved_offset += val;
                                    ++curr_insn;
                                    continue;
                                }
                            // Placing this here for sneaky programs that want to put nops in between ADRL
                            } else if (detail::a64_decode_nop(*curr_insn)) {
                                ++curr_insn;
                                continue;
                            } else if (detail::a64_decode_ldr(*curr_insn, &rn, &rt, &offset) 
                                    || detail::a64_decode_ldrh(*curr_insn, &rn, &rt, &offset)
                                    || detail::a64_decode_str(*curr_insn, &rn, &rt, &offset)) {
                                if (saved_rd == rn) {
                                    saved_offset += (offset < 0 ? -offset : offset);
                                }
                            }
                            break;
                        }
                    }
                    const auto from_addr = is_adrp ? reinterpret_cast<uintptr_t>(insn) & ~0xfff : reinterpret_cast<uintptr_t>(insn);
                    return reinterpret_cast<void*>(from_addr + saved_offset);
                }
                else if (detail::a64_decode_ldr(*insn, nullptr, nullptr, &offset) 
                        || detail::a64_decode_ldrh(*insn, nullptr, nullptr, &offset)
                        || detail::a64_decode_str(*insn, nullptr, nullptr, &offset)) {
                    return reinterpret_cast<void*>(offset);
                }
                else if (detail::a64_decode_movz(*insn, &sf, nullptr, &offset)
                    || detail::a64_decode_arithmetic(*insn, nullptr, &sf, nullptr, nullptr, &offset)) {
                    return reinterpret_cast<void*>((sf ? offset : static_cast<int32_t>(offset)));
                }
                else
                    throw std::logic_error("Failed to decode instruction with defined functions");
#else
            if (deref_ || rel_) {
                const auto relative_address = relative_value(address + offset_);
                if (deref_) {
                    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address)
                        + offset_ + insn_len_ + relative_address);
                }
                else {
                    return reinterpret_cast<void*>(relative_address);
                }
#endif
            }
            else {
                return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) + offset_);
            }
            return nullptr;
        }
#ifndef __arm64__
        const intptr_t relative_value(uint8_t* ptr) const {
            switch (size_) {
            case 1:
                return static_cast<intptr_t>(*reinterpret_cast<int8_t*>(ptr));
            case 2:
                return static_cast<intptr_t>(*reinterpret_cast<int16_t*>(ptr));
            case 4:
                return static_cast<intptr_t>(*reinterpret_cast<int32_t*>(ptr));
#if UINTPTR_MAX > 0xFFFFFFFF
            case 8:
                return static_cast<intptr_t>(*reinterpret_cast<int64_t*>(ptr));
#endif
            }
            // Should never hit here
            return NULL;
        }
#endif
        constexpr int32_t get_inst_len_opt(const char* ptr) const {
            if (*ptr > '9' || *ptr < '0')
                throw std::logic_error("Invalid data for calculating remaining instruction size!");
            return detail::stoi(ptr);
        }
    };
}
