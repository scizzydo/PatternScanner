#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <type_traits>

// Define PATTERNS_NO_SIMD where vector registers are off-limits (e.g. kernel code); find() then uses 64-bit integer (SWAR) scanning
#if defined(PATTERNS_NO_SIMD)
#elif (defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)) && !defined(_M_ARM64EC)
#include <emmintrin.h>
#define PATTERNS_SSE2
#elif defined(__ARM_NEON) || defined(_M_ARM64)
#include <arm_neon.h>
#define PATTERNS_NEON
#endif

// Compiling for arm64: patterns default to arm64 semantics (/d decoding, 4-byte alignment). __arm64__ alone is
// Apple only: GCC and clang elsewhere define __aarch64__, MSVC _M_ARM64
#if defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#define PATTERNS_ARM64
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
        // Decimal or 0x hex, optionally negative; stops at the first other character. Accumulates unsigned, so long
        // numbers wrap instead of overflowing
        template<typename T = int32_t>
        constexpr T stoi(const char* str) {
            using U = std::make_unsigned_t<T>;
            const bool negative = *str == '-';
            if (negative) ++str;
            const bool hex = str[0] == '0' && (str[1] == 'x' || str[1] == 'X');
            if (hex) str += 2;
            U value = 0;
            for (; hex ? is_hex_digit(*str) : is_digit(*str); ++str)
                value = value * (hex ? 16 : 10) + static_cast<U>(get_bits(*str));
            return static_cast<T>(negative ? U(0) - value : value);
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

        // The byte pattern syntax ("48 8B ? X4 ? ? ? ? /d"). Calls byte(index, hi, lo) for each byte (its two characters:
        // hex digits or '?'; lo is '\0' past the end), x(index, len_text) for the X marker (len_text at the digits after
        // X, or nullptr) and flags(text) for the text after '/'. Returns the number of bytes
        template <class Byte, class X, class Flags>
        constexpr size_t parse_bytes(const char* p, size_t len, Byte&& byte, X&& x, Flags&& flags) {
            size_t n = 0;
            for (size_t i = 0; i < len; i += 2) {
                const char c = p[i];
                if (c == 'X' || c == 'x') {
                    x(n, i + 1 < len && p[i + 1] != ' ' ? &p[i + 1] : nullptr);
                    while (i + 1 < len && p[i + 1] != ' ')
                        ++i;
                }
                // The flags end the pattern
                else if (c == '/') {
                    flags(&p[i + 1]);
                    break;
                }
                else if (c != ' ')
                    byte(n++, c, i + 1 < len ? p[i + 1] : '\0');
                else --i;
            }
            return n;
        }

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
                // Back to signed (immlo is unsigned) before widening, and a 64-bit multiply: ADRP reaches +-4GB
                const int64_t imm = static_cast<int32_t>(immhi | immlo);
                *offset = (adrp ? imm * 4096 : imm);
                return true;
            }
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Index-by-Encoding/Loads-and-Stores
        // Single-register loads/stores with an immediate offset (LDR/STR/LDRB/LDRH/LDRSW... and the LDUR/STUR forms,
        // general-purpose or floating-point/SIMD). *offset is signed; *post_index is set for [Rn],#imm, which accesses
        // Rn itself
        inline bool a64_decode_load_store(uint32_t insn, unsigned* rn, unsigned* rt, int64_t* offset, bool* post_index = nullptr) {
            // size 111 V 01 opc imm12 Rn Rt: unsigned offset, scaled by the access size (a Q register is size 00, opc 1x)
            if (decode_masked_match(insn, 0x3B000000, 0x39000000)) {
                const unsigned scale = (insn >> 30) | ((insn >> 26) & (insn >> 23) & 1) << 2;
                *offset = static_cast<int64_t>(extract_bitfield<uint32_t>(insn, 12, 10)) << scale;
                if (post_index) *post_index = false;
            }
            // size 111 V 00 opc 0 imm9 mode Rn Rt: unscaled (00), post-index (01), unprivileged (10), pre-index (11)
            else if (decode_masked_match(insn, 0x3B200000, 0x38000000)) {
                *offset = extract_bitfield<int32_t>(insn, 9, 12);
                if (post_index) *post_index = ((insn >> 10) & 3) == 1;
            }
            else return false;
            if (rn) *rn = (insn >> 5) & 0x1f;
            if (rt) *rt = insn & 0x1f;
            return true;
        }

        // B.cond, CBZ/CBNZ and LDR (literal, general-purpose or floating-point/SIMD): a PC-relative imm19.
        // TBZ/TBNZ: imm14
        inline bool a64_decode_branch_imm(uint32_t insn, int64_t* offset) {
            if (decode_masked_match(insn, 0xFF000010, 0x54000000) || decode_masked_match(insn, 0x7E000000, 0x34000000)
                || decode_masked_match(insn, 0x3B000000, 0x18000000)) {
                *offset = static_cast<int64_t>(extract_bitfield<int32_t>(insn, 19, 5)) * 4;
                return true;
            }
            if (decode_masked_match(insn, 0x7E000000, 0x36000000)) {
                *offset = static_cast<int64_t>(extract_bitfield<int32_t>(insn, 14, 5)) * 4;
                return true;
            }
            return false;
        }

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/MOVZ--Move-wide-with-zero-
        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/MOVN--Move-wide-with-NOT-
        inline bool a64_decode_movz(uint32_t insn, unsigned* sf, unsigned* rd, int64_t* offset) {
            // sf - 1 for 64 bit, 0 for 32 bit
            // rd - destination register
            // sx01 0010 1hh? ???? ???? ???? ???? ????
            // s: 1 = 64 bit, 0 = 32 bit. x: 1 = MOVZ, 0 = MOVN (bit 29 clear excludes MOVK). hh: shift / 16
            if (decode_masked_match(insn, 0b0011'1111'1000'0000'0000'0000'0000'0000, 0b0001'0010'1000'0000'0000'0000'0000'0000)) {
                const auto hw = (insn >> 21) & 3;
                const uint64_t imm = static_cast<uint64_t>(extract_bitfield<uint32_t>(insn, 16, 5)) << (hw * 16);
                *offset = static_cast<int64_t>((insn >> 30) & 1 ? imm : ~imm);
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
    }

    // Instruction set a pattern's /d /r, X<len> and /a follow. Defaults to the one being compiled for; RuntimePattern
    // takes another, to scan code of a different architecture (e.g. from a disassembler plugin)
    enum class arch : uint8_t { x86, x64, arm64 };
#ifdef PATTERNS_ARM64
    constexpr arch host_arch = arch::arm64;
#else
    constexpr arch host_arch = sizeof(void*) == 8 ? arch::x64 : arch::x86;
#endif

    class Pattern {
    protected:
        uint32_t length_ = 0;
        uint32_t offset_ = 0;
        bool deref_ = false;
        // x86/x64 only. Remaining bytes from the offset when used in dereferencing
        uint32_t insn_len_ = 0;
        // x86/x64 only (arm64 instructions are 32 bit and encoded, so arm64 has just deref). Defaulting 4 byte
        // relative address reading
        uint32_t size_ = 4;
        bool rel_ = false;
        bool align_ = false;
        // Set before parsing: the flags and X<len> are read per architecture
        arch arch_ = host_arch;
        // arm64 instructions are all 32 bits, so the align scanning will be at the instruction level
        constexpr size_t align_size() const {
            return arch_ == arch::x64 ? 8 : 4;
        }
        // Patterns are used through Pattern* but never deleted through one; protected keeps the destructor
        // trivial (constexpr patterns in C++17) while making `delete` through a Pattern* a compile error
        ~Pattern() = default;
    public:
        Pattern() = default;
        constexpr uint32_t length() const {
            return length_;
        }
        constexpr uint32_t offset() const {
            return offset_;
        }
        constexpr bool deref() const {
            return deref_;
        }
        constexpr bool relative() const {
            return rel_;
        }
        constexpr bool aligned() const {
            return align_;
        }
        constexpr arch target() const {
            return arch_;
        }
        virtual const uint8_t* mask() const = 0;
        virtual const uint8_t* pattern() const = 0;
        template <typename T>
        T find(const uint8_t* bytes, size_t size) const {
            return reinterpret_cast<T>(find(bytes, size));
        }
        void* find(const uint8_t* bytes, size_t size) const {
            const auto hit = match(bytes, size);
            return hit ? resolve(hit, bytes + size) : nullptr;
        }
        // Address of the first match, before the X offset and /d /r are applied
        virtual const uint8_t* match(const uint8_t* bytes, size_t size) const {
            return scan(bytes, size, pattern(), mask());
        }
        // What find() returns for a match from match(). end bounds how far /d may read (arm64 ADRP sequences).
        // *is_value is set when the result is a value read from the code (/r; arm64 /d on LDR/STR offsets, MOVZ,
        // ADD) rather than an address
        void* resolve(const uint8_t* match, const uint8_t* end, bool* is_value = nullptr) const {
            return get_result(const_cast<uint8_t*>(match), end, is_value);
        }
        virtual uint8_t operator[](size_t idx) const {
            return pattern()[idx];
        }
    protected:
        // Parses a byte pattern: sets the X offset, X<len> and flags, and calls emit(index, byte, mask) for each byte.
        // Set arch_ first. Returns the number of bytes
        template <class Emit>
        constexpr size_t parse(const char* p, size_t len, Emit&& emit) {
            return detail::parse_bytes(p, len,
                [&](size_t n, char hi, char lo) {
                    // A lone ? (or ??) is a whole byte; a ? next to a hex digit is a nibble ("4?", "?8")
                    if (hi == '?' && lo != '?' && !detail::is_hex_digit(lo)) lo = '?';
                    emit(n, uint8_t(nibble(hi) << 4 | nibble(lo)), uint8_t((hi == '?' ? 0 : 0xF0) | (lo == '?' ? 0 : 0x0F)));
                },
                [&](size_t n, const char* len_text) {
                    offset_ = static_cast<uint32_t>(n);
                    if (len_text && arch_ != arch::arm64)
                        insn_len_ = get_inst_len_opt(len_text);
                },
                [&](const char* flags) { handle_options(flags); });
        }
        // First match of pat/msk in [bytes, bytes + size). Two anchor bytes are checked first
        // (16 positions at a time with SIMD), and only positions passing both get a full compare.
        const uint8_t* scan(const uint8_t* bytes, size_t size, const uint8_t* pat, const uint8_t* msk) const {
            if (size < length_) return nullptr;
            if (!length_) return bytes;
            const size_t last = size - length_;
            const size_t step = align_ ? align_size() : 1;
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
        static constexpr uint8_t nibble(char c) {
            if (c == '?') return 0;
            if (!detail::is_hex_digit(c))
                throw std::logic_error("Invalid hex byte in pattern!");
            return static_cast<uint8_t>(detail::get_bits(c));
        }
        constexpr void handle_options(const char* ptr) {
            const bool arm64 = arch_ == arch::arm64;
            while (*ptr) {
                if (*ptr == 'd') {
                    if (rel_) throw std::logic_error("Cannot use relative and deref together!");
                    deref_ = true;
                }
                else if (*ptr == 'r' && !arm64) {
                    if (deref_) throw std::logic_error("Cannot use relative and deref together!");
                    rel_ = true;
                }
                else if (*ptr == 'a')
                    align_ = true;
                // Check the next character to see what size we're reading at this relative address
                else if (!arm64 && *ptr > '0' && (arch_ == arch::x64 ? *ptr < '9' : *ptr < '5')) {
                    size_ = *ptr - '0';
                    if ((size_ & (size_ - 1)) != 0) throw std::logic_error("Size is not a valid data type size!");
                }
                ++ptr;
            }
        }
        void* get_result(uint8_t* address, const uint8_t* end, bool* is_value = nullptr) const {
            if (is_value) *is_value = false;
            if (arch_ == arch::arm64 && deref_) {
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
                        // Follow the instructions after ADRP, never reading past the end of the scanned buffer.
                        // Instructions that leave the register alone (NOP, another ADRP, unrelated ADD/MOVZ/loads/
                        // stores; compilers interleave them) are skipped; anything else ends the chain
                        for (; reinterpret_cast<const uint8_t*>(curr_insn + 1) <= end && *curr_insn; ++curr_insn) {
                            unsigned rt = 0;
                            bool post_index = false;
                            if (detail::a64_decode_arithmetic(*curr_insn, &is_sub, &sf, &rd, &rn, &offset)) {
                                // ADD may write a different register (ADRP X8 / ADD X0, X8, #lo); keep following that one
                                if (rn == saved_rd) {
                                    uint64_t val = (sf ? offset : static_cast<uint32_t>(offset));
                                    if (is_sub) saved_offset -= val;
                                    else saved_offset += val;
                                    saved_rd = rd;
                                    continue;
                                }
                                if (rd == saved_rd) break;
                            }
                            else if (detail::a64_decode_load_store(*curr_insn, &rn, &rt, &offset, &post_index)) {
                                // The address it accesses; [Rn],#imm accesses Rn and only then adds
                                if (rn == saved_rd) {
                                    if (!post_index) saved_offset += offset;
                                    break;
                                }
                                if (rt == saved_rd) break;
                            }
                            else if (detail::a64_decode_adr(*curr_insn, nullptr, &rd, &offset)
                                    || detail::a64_decode_movz(*curr_insn, nullptr, &rd, &offset)) {
                                if (rd == saved_rd) break;
                            }
                            else if (!detail::a64_decode_nop(*curr_insn))
                                break;
                        }
                    }
                    const auto from_addr = is_adrp ? reinterpret_cast<uintptr_t>(insn) & ~0xfff : reinterpret_cast<uintptr_t>(insn);
                    return reinterpret_cast<void*>(from_addr + saved_offset);
                }
                else if (detail::a64_decode_branch_imm(*insn, &offset)) {
                    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(insn) + offset);
                }
                else if (detail::a64_decode_load_store(*insn, nullptr, nullptr, &offset)) {
                    if (is_value) *is_value = true;
                    return reinterpret_cast<void*>(offset);
                }
                else if (detail::a64_decode_movz(*insn, &sf, nullptr, &offset)
                    || detail::a64_decode_arithmetic(*insn, nullptr, &sf, nullptr, nullptr, &offset)) {
                    if (is_value) *is_value = true;
                    return reinterpret_cast<void*>((sf ? offset : static_cast<int32_t>(offset)));
                }
                else
                    throw std::logic_error("Failed to decode instruction with defined functions");
            }
            else if (arch_ != arch::arm64 && (deref_ || rel_)) {
                const auto relative_address = relative_value(address + offset_);
                if (deref_) {
                    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address)
                        + offset_ + insn_len_ + relative_address);
                }
                else {
                    if (is_value) *is_value = true;
                    return reinterpret_cast<void*>(relative_address);
                }
            }
            else {
                return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) + offset_);
            }
            return nullptr;
        }
        // memcpy: operands in x86 code are rarely aligned for their type
        template <typename T>
        static intptr_t read_signed(const uint8_t* ptr) {
            T v;
            memcpy(&v, ptr, sizeof v);
            return static_cast<intptr_t>(v);
        }
        intptr_t relative_value(uint8_t* ptr) const {
            switch (size_) {
            case 1:
                return read_signed<int8_t>(ptr);
            case 2:
                return read_signed<int16_t>(ptr);
            case 4:
                return read_signed<int32_t>(ptr);
#if UINTPTR_MAX > 0xFFFFFFFF
            case 8:
                return read_signed<int64_t>(ptr);
#endif
            }
            // Should never hit here
            return 0;
        }
        constexpr int32_t get_inst_len_opt(const char* ptr) const {
            if (*ptr > '9' || *ptr < '0')
                throw std::logic_error("Invalid data for calculating remaining instruction size!");
            return detail::stoi(ptr);
        }
    };

    // Resolves many patterns over one range: out[i] = pats[i]->find(start, size). Returns how many matched.
    // Faster than a find() per pattern: the range is walked in cache-sized chunks with every pattern run over a
    // chunk while it's hot, so memory is read once instead of once per pattern.
    // No allocation, threads, CRT state or static initialization, so it's safe from TLS callbacks and DllMain.
    inline size_t find_all(const uint8_t* start, size_t size, const Pattern* const* pats, size_t count, void** out,
                           size_t chunk = 1 << 20) {
        if (!chunk) chunk = 1 << 20;
        size_t found = 0;
        for (size_t i = 0; i < count; ++i) out[i] = nullptr;
        // out[i] holds the raw match until the end. Chunks go in order, so the first hit is the lowest address
        for (size_t pos = 0; pos < size && found < count; pos += chunk) {
            for (size_t i = 0; i < count; ++i) {
                if (out[i]) continue;
                // Reach length - 1 bytes into the next chunk, so matches straddling the boundary are found,
                // but no match starting in the next chunk is
                const size_t n = chunk + pats[i]->length() - 1;
                if (auto hit = pats[i]->match(start + pos, n < size - pos ? n : size - pos)) {
                    out[i] = const_cast<uint8_t*>(hit);
                    ++found;
                }
            }
        }
        for (size_t i = 0; i < count; ++i)
            if (out[i]) out[i] = pats[i]->resolve(static_cast<uint8_t*>(out[i]), start + size);
        return found;
    }
}
