#pragma once
#include <cstdint>
#include <stdexcept>

#ifndef _MSVC_VER
#define __forceinline inline __attribute__((always_inline))
#endif

namespace patterns {
    // Define your own ldisasm in use if using dereference
    extern size_t ldisasm(const void* buffer, size_t buffer_size);

    namespace detail {
        constexpr bool __forceinline is_digit(char c) {
            return c <= '9' && c >= '0';
        }
        constexpr int32_t stoi(const char* str, int32_t value = 0) {
            return *str && is_digit(*str) ? stoi(str + 1, (*str - '0') + value * 10) : value;
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

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/B--Branch-
        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/BL--Branch-with-Link-
        bool a64_decode_b(uint32_t insn, bool* is_bl, int64_t* offset) {
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
        bool a64_decode_adr(uint32_t insn, bool* is_adrp, unsigned* rd, int64_t* offset) {
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
        bool a64_decode_ldrh(uint32_t insn, unsigned* rn, unsigned* rt, int64_t* offset) {
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
        bool a64_decode_ldr(uint32_t insn, unsigned* rn, unsigned* rt, int64_t* offset) {
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

        // https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/MOVZ--Move-wide-with-zero-
        bool a64_decode_movz(uint32_t insn, unsigned* sf, unsigned* rd, int64_t* offset) {
            // sf - 1 for 64 bit, 0 for 32 bit
            // rd - destination register
            // x101 0010 1xx? ???? ???? ???? ???? ????
            // 1 = 64 bit 0x - shift ammount
            // 0 = 32 bit
            if (decode_masked_match(insn, 0b0111'0010'1000'0000'0000'0000'0000'0000, 0b0101'0010'1000'0000'0000'0000'0000'0000)) {
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
        bool a64_decode_arithmetic(uint32_t insn, bool* is_sub, unsigned* sf, unsigned* rd, unsigned* rn, int64_t* offset) {
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
        uint32_t insn_len_ = 0;
        // Added to avoid using the length disassembler if passed in
        bool deref_ = false;
#ifndef __arm64__
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
        const uint32_t __forceinline length() const {
            return length_;
        }
        const uint32_t __forceinline offset() const {
            return offset_;
        }
        const bool __forceinline deref() const {
            return deref_;
        }
#ifndef __arm64__
        const bool __forceinline relative() const {
            return rel_;
        }
#endif
        const bool __forceinline aligned() const {
            return align_;
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
            for (auto i = const_cast<uint8_t*>(bytes); i < end; align_ ? i += align_size_ : ++i) {
                bool found = true;
#ifdef __arm64__
                // Doing byte by byte match due to arm being encoded instructions
                for (auto j = 0U; j < length_; ++j) {
                    if (mask[j] == 0xFF && pattern[j] != i[j]) {
                        found = false;
                        break;
                    }
                }
#else
                for (auto j = 0U; j < length_; j += sizeof(void*)) {
                    const auto data = *reinterpret_cast<uintptr_t*>(pattern + j);
                    const auto msk = *reinterpret_cast<uintptr_t*>(mask + j);
                    const auto mem = *reinterpret_cast<uintptr_t*>(i + j);
                    if ((data ^ mem) & msk) {
                        found = false;
                        break;
                    }
                }
#endif
                if (found)
                    return get_result(i, end);
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
            return detail::is_digit(c) ? (c - '0') : ((c & (~0x20)) - 'A' + 0xA);
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
                            } else if (detail::a64_decode_ldr(*curr_insn, &rn, &rt, &offset) 
                                    || detail::a64_decode_ldrh(*curr_insn, &rn, &rt, &offset)) {
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
                        || detail::a64_decode_ldrh(*insn, nullptr, nullptr, &offset)) {
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
                    size_t instrlen = insn_len_;
                    if (!instrlen) {
                        auto instrlen = ldisasm(address, end - address);
                        while (instrlen < offset_)
                            instrlen += ldisasm(address + instrlen, (end - address) - instrlen);
                    }
                    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address)
                        + instrlen + relative_address);
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
#if ((ULLONG_MAX) != (UINT_MAX))
            case 8:
                return static_cast<intptr_t>(*reinterpret_cast<int64_t*>(ptr));
#endif
            }
            // Should never hit here
            return NULL;
        }
#endif
        constexpr int32_t get_inst_len_opt(const char* ptr) const {
            const auto c = *ptr;
            if (c == ' ' || c > '9' || c < '0')
                return 0;
            return detail::stoi(ptr);
        }
    };
}