#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <tuple>

#include "Pattern.hpp"

namespace patterns {
    namespace detail {
        constexpr bool str_eq(const char* a, const char* b) {
            while (*a && *b) {
                if (*a != *b) return false;
                ++a; ++b;
            }
            return *a == *b;
        }

        constexpr bool isspace(char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r';
        }

        constexpr size_t skip_whitespace(const char* str, size_t i) {
            while (isspace(str[i])) ++i;
            return i;
        }

        constexpr size_t skip_char(const char* str, size_t i, char target) {
            while (str[i] && str[i] == target) ++i;
            return i;
        }

        constexpr size_t skip_past(const char* str, size_t i, char target) {
            while (str[i] && str[i] != target) ++i;
            return str[i] == target ? i + 1 : i;
        }

        template <size_t N>
        constexpr size_t parse_token(const char* str, size_t i, char  (&out)[N]) {
            size_t j = 0;
            while (str[i] && str[i] != ',' && str[i] != ' ' && str[i] != ']' && j + 1 < N)
                out[j++] = str[i++];
            out[j] = '\0';
            return i;
        }

        template <size_t N>
        constexpr size_t parse_imm_token(const char* str, size_t i, char (&out)[N]) {
            if (str[i] == '#') ++i;
            size_t j = 0;
            while (str[i] && !isspace(str[i]) && str[i] != ',' && str[i] != ']' && j + 1 < N)
                out[j++] = str[i++];
            out[j] = '\0';
            return i;
        }

        constexpr size_t max_line = 128;

        constexpr bool starts_with(const char* a, const char* prefix) {
            while (*prefix) {
                if (*a != *prefix) return false;
                ++a; ++prefix;
            }
            return true;
        }

        struct ArmOpcode {
            uint32_t pattern;
            uint32_t mask;
            constexpr void set_bits(uint32_t p, uint32_t m, uint32_t shift = 0) {
                pattern |= ((p & m) << shift);
                mask    |= (m << shift);
            }
            constexpr void set_mask(uint32_t m, uint32_t shift = 0) {
                mask    |= (m << shift);
            }
        };

        struct InstructionDescriptor {
            const char* mnemonic;
            ArmOpcode opcode;
        };

        constexpr uint32_t parse_register(const char* token) {
            if (token[0] == '?' && token[1] == '\0')
                return 0xFFFFFFFF;

            if ((token[0] == 'W' || token[0] == 'X') && token[1] >= '0' && token[1] <= '9') {
                uint32_t val = 0;
                for (int i = 1; token[i] >= '0' && token[i] <= '9'; ++i) {
                    val = val * 10 + (token[i] - '0');
                }
                return val;
            }

            if (str_eq(token, "SP") || str_eq(token, "WSP") || str_eq(token, "XSP") ||
                str_eq(token, "ZR") || str_eq(token, "WZR") || str_eq(token, "XZR")) {
                return 31;
            }

            return 0xFFFFFFFF;
        }

        // 1 for a 64-bit register (X, SP, XZR), 0 for 32-bit (W, WSP, WZR), -1 when unknown ("?")
        constexpr int register_width(const char* token) {
            return token[0] == 'X' || str_eq(token, "SP") ? 1 : token[0] == 'W' ? 0 : -1;
        }

        constexpr bool is_sp(const char* token) {
            return str_eq(token, "SP") || str_eq(token, "WSP");
        }

        template <size_t N>
        constexpr void parse_register(char(&buffer)[N], uint32_t mask, uint32_t shift, ArmOpcode& base) {
            if (auto val = parse_register(buffer); val != 0xFFFFFFFF)
                base.set_bits(val, mask, shift);
        }

        template <size_t N>
        constexpr size_t parse_register(const char* instr, size_t i, char(&buffer)[N], uint32_t mask, uint32_t shift, ArmOpcode& base, char skipchar = '\0') {
            if (skipchar) i = skip_char(instr, i, skipchar);
            i = skip_whitespace(instr, i);
            parse_register(buffer, mask, shift, base);
            return i;
        }

        constexpr size_t parse_register(const char* instr, size_t i, uint32_t mask, uint32_t shift, ArmOpcode& base, char skipchar = '\0') {
            char buffer[5] = {};
            return parse_register(instr, parse_token(instr, i, buffer), buffer, mask, shift, base, skipchar);
        }

        using ParseFunc = ArmOpcode(*)(const char* instr, ArmOpcode base);

        // Passthrough parser (no field parsing)
        constexpr ArmOpcode parse_passthrough(const char*, ArmOpcode base) {
            return base;
        }

        constexpr size_t skip_mnemonic(const char* instr) {
            size_t i = 0;
            while (instr[i] && !isspace(instr[i])) ++i;
            return i;
        }

        constexpr std::pair<bool, uint32_t> parse_lsl_shift(const char* instr, size_t i) {
            i = skip_whitespace(instr, skip_char(instr, i, ','));
            if (starts_with(&instr[i], "LSL")) {
                i = skip_char(instr, skip_whitespace(instr, i + 3), '#');
                if (instr[i] == '?') {
                    return { false, 0 };
                } else {
                    return { true, static_cast<uint32_t>(stoi(&instr[i]) / 16) };
                }
            }
            return { true, 0 };
        }

        constexpr uint64_t rotate_right(uint64_t v, int n) {
            return (v >> (n & 63)) | (v << (-n & 63));
        }

        // std::countr_zero / countl_zero are C++20; the macros need C++17
        constexpr int countr_zero(uint64_t n) {
            int c = 0;
            for (; c < 64 && !(n >> c & 1); ++c) {}
            return c;
        }
        constexpr int countl_zero(uint64_t n) {
            int c = 0;
            for (; c < 64 && !(n >> (63 - c) & 1); ++c) {}
            return c;
        }

        constexpr uint64_t clear_trailing_ones(uint64_t n) {
            return n & (n + 1);
        }

        // 32-bit (W) immediates are encoded as the value repeated in both halves; 64-bit (X) ones as they are
        constexpr std::tuple<bool, uint32_t, uint32_t, uint32_t> encode_bitmask_immediate(uint64_t value, bool is64) {
            if (!is64 && value > 0xFFFFFFFFULL)
                return { false, 0, 0, 0 };
            uint64_t val = is64 ? value : (value << 32) | value;

            if (val == 0 || ~val == 0)
                return { false, 0, 0, 0 };

            int rotation = countr_zero(clear_trailing_ones(val));
            uint64_t normalized = rotate_right(val, rotation & 63);

            int zeroes = countl_zero(normalized);
            int ones = countr_zero(~normalized);
            int size = zeroes + ones;

            if (rotate_right(val, size & 63) != val)
                return { false, 0, 0, 0 };

            int immr = -rotation & (size - 1);
            int imms = -(size << 1) | (ones - 1);
            int N = (size >> 6);

            return { true, static_cast<uint32_t>(N), static_cast<uint32_t>(imms & 0x3f), static_cast<uint32_t>(immr & 0x3F) };
        }

        constexpr ArmOpcode parse_movX(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rd[5] = {};
            i = parse_register(instr, parse_token(instr, i, rd), rd, 0x1F, 0, base, ',');
            if (rd[0] != '?') base.set_bits((rd[0] == 'W' ? 0 : 1), 1, 31);

            char imm[24] = {};
            i = parse_imm_token(instr, skip_char(instr, i, '#'), imm);
            if (imm[0] != '?') {
                if (int32_t val = stoi(imm); val >= 0 && val <= 0xFFFF) base.set_bits(val, 0xFFFF, 5);
            }

            auto [has_hw, hw] = parse_lsl_shift(instr, i);
            if (has_hw) base.set_bits(hw, 3, 21);

            return base;
        }

        constexpr ArmOpcode parse_branch_imm26(const char* instr, ArmOpcode base) {
            size_t i = skip_char(instr, skip_whitespace(instr, skip_mnemonic(instr)), '#');

            if (instr[i] == '?') {
                base.pattern &= 0xFC000000;
                base.mask    &= 0xFC000000;
            } else {
                base.set_bits(static_cast<uint32_t>(stoi(&instr[i]) >> 2), 0x3FFFFFF);
            }

            return base;
        }

        // BR/BLR/RET Xn (a bare RET returns through X30)
        constexpr ArmOpcode parse_branch_reg(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            if (instr[i]) parse_register(instr, i, 0x1F, 5, base);
            else base.set_bits(30, 0x1F, 5);
            return base;
        }

        constexpr ArmOpcode parse_adr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            // Rd
            i = parse_register(instr, i, 0x1F, 0, base, ',');

            char imm[24] = {};
            i = parse_imm_token(instr, skip_char(instr, i, '#'), imm);
            if (!(imm[0] == '?' && imm[1] == '\0')) {
                int64_t offset = stoi<int64_t>(imm);
                if ((base.pattern >> 31) & 1) offset >>= 12;
                base.set_bits(static_cast<uint32_t>((offset << 24) | ((offset >> 2) & 0x7FFFF)), (3 << 24 | 0x7FFFF), 5);
            }
            return base;
        }

        // imm19 (bits 5-23) from a byte offset, for CBZ/CBNZ, B.cond and LDR (literal)
        constexpr void parse_imm19(const char* instr, size_t i, ArmOpcode& base) {
            char imm[24] = {};
            parse_imm_token(instr, i, imm);
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(stoi(imm) >> 2), 0x7FFFF, 5);
        }

        // Single-register loads/stores. op is the unsigned offset form; the unscaled (LDUR), pre/post-index and
        // register offset forms differ from it in fixed bits. scale is log2 of the access size, or -1 to take it
        // from Rt (W or X, bit 30). An offset the unsigned form can't hold (negative, unaligned) is encoded unscaled,
        // the way assemblers pick LDUR/STUR. Floating-point/SIMD registers aren't supported: the line is a wildcard
        template <uint32_t op, int scale, bool unscaled = false>
        constexpr ArmOpcode parse_load_store(const char* instr, ArmOpcode) {
            ArmOpcode base{ 0, 0 };
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rt[5] = {}, imm[24] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (rt[0] != 'W' && rt[0] != 'X' && rt[0] != '?') return { 0, 0 };
            int size = scale;
            if (scale < 0 && rt[0] != '?') {
                size = rt[0] == 'W' ? 2 : 3;
                base.set_bits(size - 2, 1, 30);
            }
            if (instr[i++] != '[') return { 0, 0 };

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base);

            bool is_register_offset = false, is_pre_index = false, is_post_index = false;
            uint32_t option_val = 0b011, s_val = 0, s_mask = 1;

            if (instr[i] == ',') {
                i = skip_whitespace(instr, ++i);
                if (instr[i] == '#') {
                    i = parse_imm_token(instr, i, imm);
                } else {
                    // Rm
                    i = parse_register(instr, i, 0x1F, 16, base, ',');
                    is_register_offset = true;

                    if      (starts_with(&instr[i], "LSL"))  { option_val = 0b011; i += 3; }
                    else if (starts_with(&instr[i], "UXTW")) { option_val = 0b010; i += 4; }
                    else if (starts_with(&instr[i], "SXTW")) { option_val = 0b110; i += 4; }
                    else if (starts_with(&instr[i], "SXTX")) { option_val = 0b111; i += 4; }

                    i = skip_whitespace(instr, skip_char(instr, i, ','));
                    if (instr[i] == '#') {
                        // For bytes an explicit #0 is the shifted form; for the rest the amount is 0 or the scale
                        if (instr[++i] == '?') s_mask = 0;
                        else s_val = (size == 0 || stoi(&instr[i]) != 0) ? 1 : 0;
                    }
                }
            }

            i = skip_whitespace(instr, skip_past(instr, i, ']'));
            if (instr[i] == '!') { is_pre_index = true; ++i; }
            i = skip_whitespace(instr, i);
            if (instr[i] == ',') {
                i = skip_whitespace(instr, i + 1);
                if (instr[i] == '#') {
                    i = parse_imm_token(instr, i + 1, imm);
                    is_post_index = true;
                }
            }

            const bool known_imm = imm[0] != '?';
            const int32_t val = known_imm ? stoi(imm) : 0;
            bool is_unsigned_offset = !unscaled && !is_register_offset && !is_pre_index && !is_post_index;
            if (is_unsigned_offset && known_imm && (val < 0 || (size > 0 && (val & ((1 << size) - 1)))))
                is_unsigned_offset = false;

            const uint32_t width_mask = scale < 0 ? ~(1u << 30) : ~0u;   // Rt's width bit, set above when known
            if (is_unsigned_offset) {
                base.set_bits(op, 0xFFC00000 & width_mask);
                if (known_imm && size >= 0) {
                    if ((val >> size) > 0xFFF) return { 0, 0 };
                    base.set_bits(val >> size, 0xFFF, 10);
                }
                return base;
            }

            const uint32_t form = is_register_offset ? 0x00200800 : is_pre_index ? 0xC00 : is_post_index ? 0x400 : 0;
            base.set_bits((op & ~0x01000000u) | form, 0xFFE00C00 & width_mask);
            if (is_register_offset) {
                base.set_bits(option_val << 1 | s_val, 0xE | s_mask, 12);
            } else if (known_imm) {
                if (val < -256 || val > 255) return { 0, 0 };
                base.set_bits(val, 0x1FF, 12);
            }
            return base;
        }

        // LDR is a load/store, or a PC-relative literal load (LDR Rt, #offset)
        constexpr ArmOpcode parse_ldr(const char* instr, ArmOpcode base) {
            char rt[5] = {};
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (instr[i] == '[') return parse_load_store<0xB9400000, -1>(instr, base);
            if (rt[0] != 'W' && rt[0] != 'X' && rt[0] != '?') return { 0, 0 };
            if (rt[0] != '?') base.set_bits((rt[0] == 'W' ? 0 : 1), 1, 30);
            parse_imm19(instr, i, base);
            return base;
        }

        constexpr ArmOpcode parse_orr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rd[5] = {}, rn[5] = {};
            i = parse_register(instr, parse_token(instr, i, rd), rd, 0x1F, 0, base, ',');
            // Rn
            i = parse_register(instr, parse_token(instr, i, rn), rn, 0x1F, 5, base, ',');
            // Width from Rd, or from Rn when Rd is "?"
            const int width = register_width(rd) >= 0 ? register_width(rd) : register_width(rn);
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);

            if (instr[i] == '#') {
                base.set_bits((2 << 4), (3 << 4 | 1), 23);

                char imm[24] = {};
                i = parse_imm_token(instr, i, imm);
                if (imm[0] != '?') {
                    uint64_t immVal = stoi<uint64_t>(imm);
                    // Unknown width (Rd is "?"): a value that fits in 32 bits can be either, and the two only differ in N
                    const bool is64 = width == 1 || (width < 0 && immVal > 0xFFFFFFFFULL);
                    const uint32_t n_mask = (width >= 0 || is64) ? 1 : 0;
                    auto [ ok, N, imms, immr ] = encode_bitmask_immediate(immVal, is64);
                    if (ok) base.set_bits((N << 12 | immr << 6 | imms), (n_mask << 12 | 0x3F << 6 | 0x3F), 10);
                }
                return base;
            }
            base.set_bits((1 << 6), (3 << 6 | 1), 21);

            // Rm
            i = parse_register(instr, i, 0x1F, 16, base);

            if (instr[i] == ',') {
                i = skip_whitespace(instr, skip_char(instr, i, ','));
                if      (starts_with(&instr[i], "LSL")) { base.set_bits(0, 3, 22); i += 3; }
                else if (starts_with(&instr[i], "LSR")) { base.set_bits(1, 3, 22); i += 3; }
                else if (starts_with(&instr[i], "ASR")) { base.set_bits(2, 3, 22); i += 3; }
                else if (starts_with(&instr[i], "ROR")) { base.set_bits(3, 3, 22); i += 3; }
                else base.set_bits(0, 3, 22);

                i = skip_char(instr, skip_whitespace(instr, i), '#');
                if (instr[i] != '?') base.set_bits(stoi(&instr[i]), 0x3F, 10);

            } else {
                base.set_mask((3 << 12 | 0x3F), 10);
            }
            
            return base;
        }

        constexpr ArmOpcode parse_arithmetic(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rd[5] = {}, rn[5] = {};
            i = parse_register(instr, parse_token(instr, i, rd), rd, 0x1F, 0, base, ',');
            // Rn
            i = parse_register(instr, parse_token(instr, i, rn), rn, 0x1F, 5, base, ',');
            // Width from Rd, or from Rn when Rd is "?"
            const int width = register_width(rd) >= 0 ? register_width(rd) : register_width(rn);
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);

            if (instr[i] == '#') {
                base.set_bits((2 << 4 | 2), (3 << 4 | 7), 23);
                char imm[24] = {};
                i = skip_whitespace(instr, parse_imm_token(instr, i, imm));
                int sh = -1;   // LSL #12 (1) or #0 (0) when written, -1 if not or #?
                if (instr[i] == ',') {
                    i = skip_whitespace(instr, i + 1);
                    if (starts_with(&instr[i], "LSL")) {
                        i = skip_char(instr, skip_whitespace(instr, i + 3), '#');
                        if (instr[i] != '?') sh = stoi(&instr[i]) == 12 ? 1 : 0;
                    }
                }
                if (imm[0] != '?') {
                    int64_t val = stoi<int64_t>(imm);
                    // As assemblers do: a negative immediate is the opposite operation (ADD #-8 is SUB #8, CMP #-1
                    // is CMN #1), and a multiple of 0x1000 the shifted form (#0x1000 is #1, LSL #12)
                    if (val < 0) { base.pattern ^= 1u << 30; val = -val; }
                    if (sh < 0 && val > 0xFFF && !(val & 0xFFF)) { sh = 1; val >>= 12; }
                    if (val > 0xFFF) return { 0, 0 };
                    base.set_bits(static_cast<uint32_t>(val), 0xFFF, 10);
                    if (sh < 0) sh = 0;
                }
                if (sh >= 0) base.set_bits(static_cast<uint32_t>(sh), 1, 22);
                return base;
            }

            // With SP as Rd or Rn only the extended register form exists: assemblers write LSL as UXTX (UXTW for W)
            const bool sp = is_sp(rd) || is_sp(rn);
            const uint32_t sp_extend = str_eq(rd, "WSP") || str_eq(rn, "WSP") ? 2 : 3;

            base.set_bits(5, 0xF, 25);
            // Rm
            i = parse_register(instr, i, 0x1F, 16, base);

            if (instr[i] == ',') {
                i = skip_whitespace(instr, i + 1);
                bool shifted = false, extended = false;
                if      (starts_with(&instr[i], "LSL") && sp) { base.set_bits(sp_extend, 7, 13); extended = true; i += 3; }
                else if (starts_with(&instr[i], "LSL"))  { base.set_bits(0, 7, 21); shifted = true;  i += 3; }
                else if (starts_with(&instr[i], "LSR"))  { base.set_bits(2, 7, 21); shifted = true;  i += 3; }
                else if (starts_with(&instr[i], "ASR"))  { base.set_bits(4, 7, 21); shifted = true;  i += 3; }
                else if (starts_with(&instr[i], "UXTB")) { base.set_bits(0, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "UXTH")) { base.set_bits(1, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "UXTW")) { base.set_bits(2, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "UXTX")) { base.set_bits(3, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "SXTB")) { base.set_bits(4, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "SXTH")) { base.set_bits(5, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "SXTW")) { base.set_bits(6, 7, 13); extended = true; i += 4; }
                else if (starts_with(&instr[i], "SXTX")) { base.set_bits(7, 7, 13); extended = true; i += 4; }
                i = skip_whitespace(instr, i);
                if (instr[i] == '#') {
                    char amount[12] = {};
                    i = parse_imm_token(instr, i, amount);
                    if (amount[0] != '?') {
                        auto val = stoi(amount);
                        if (shifted) {
                            base.set_bits(val, 0x3F, 10);
                        } else if (extended) {
                            base.set_bits(val, 7, 10);
                        }
                    }
                    if (shifted) {
                        base.set_bits(0, 1, 21);
                    } else if (extended) {
                        base.set_bits(1, 7, 21);
                    }
                } else {
                    if (shifted) {
                        base.set_bits(0, (1 << 11 | 0x3F), 10);
                    } else if (extended) {
                        base.set_bits((1 << 11), (7 << 11 | 7), 10);
                    }
                }
            } else if (sp) {
                base.set_bits((1 << 11 | sp_extend << 3), (7 << 11 | 0x3F), 10);
            } else {
                base.set_bits(0, (7 << 11 | 0x3F), 10);
            }

            return base;
        }

        constexpr ArmOpcode parse_ldp(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rt1[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt1), rt1, 0x1F, 0, base, ',');
            if (rt1[0] != 'W' && rt1[0] != 'X' && rt1[0] != '?') return { 0, 0 };   // FP/SIMD pairs aren't supported
            char rt2[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt2), rt2, 0x1F, 10, base, ',');
            // Width from Rt1, or from Rt2 when Rt1 is "?"
            const int width = register_width(rt1) >= 0 ? register_width(rt1) : register_width(rt2);
            const bool know_size = width >= 0;
            const uint32_t size_bits = know_size ? static_cast<uint32_t>(width) : 0;
            if (know_size) base.set_bits(size_bits, 1, 31);

            if (instr[i] != '[') return base;
            i = skip_whitespace(instr, skip_char(instr, i, '['));

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base, ',');

            // [Rn] alone is the signed offset form with offset 0 (imm stays empty, which reads as 0)
            bool post_index = false, pre_index = false;
            char imm[24] = {};
            if (instr[i] == '#')
                i = skip_whitespace(instr, parse_imm_token(instr, i, imm));
            if (instr[i] == ']') {
                i = skip_whitespace(instr, skip_char(instr, skip_char(instr, i, ']'), ','));
                if (instr[i] == '!') {
                    pre_index = true;
                } else if (instr[i] == '#') {
                    post_index = true;
                    i = parse_imm_token(instr, i, imm);
                }
            }
            base.set_bits((post_index    ? 0b0010100011 :
                           pre_index     ? 0b0010100111 :
                                           0b0010100101), 0x1FF, 22);
            if (imm[0] != '?' && know_size) {
                int32_t immVal = stoi(imm);
                int32_t scale = (size_bits == 0) ? 4 : 8;
                if ((immVal % scale) == 0) {
                    int32_t encoded = immVal / scale;
                    if (encoded >= -64 && encoded <= 63) {
                        base.set_bits(encoded, 0x7F, 15);
                    }
                }
            }
            return base;
        }

        // STP is LDP with the load bit (22) clear
        constexpr ArmOpcode parse_stp(const char* instr, ArmOpcode base) {
            base = parse_ldp(instr, base);
            base.pattern &= ~(1u << 22);
            return base;
        }

        // MOV is an alias; encoded the way assemblers pick: ADD #0 when SP is involved, ORR from the zero register for
        // registers, and MOVZ, then MOVN, then ORR (bitmask) for immediates. MOV Rd, #? matches MOVZ or MOVN
        constexpr ArmOpcode parse_mov(const char* instr, ArmOpcode) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rd[5] = {};
            i = skip_whitespace(instr, skip_char(instr, parse_token(instr, i, rd), ','));
            const bool rd_sp = str_eq(rd, "SP") || str_eq(rd, "WSP");
            const bool known_width = rd[0] == 'W' || rd[0] == 'X' || rd_sp;
            const bool is64 = rd[0] == 'X' || str_eq(rd, "SP");
            ArmOpcode op{ 0, 0 };
            if (known_width) op.set_bits(is64 ? 1 : 0, 1, 31);
            if (auto r = parse_register(rd); r != 0xFFFFFFFF) op.set_bits(r, 0x1F);

            if (instr[i] == '#') {
                char imm[24] = {};
                parse_imm_token(instr, i, imm);
                if (imm[0] == '?') {
                    op.set_bits(0x12800000, 0x3F800000);   // MOVZ or MOVN: bit 30 of opc left open, bit 29 clear (not MOVK)
                    return op;
                }
                const unsigned width = is64 ? 64 : 32;
                const uint64_t ones = is64 ? ~0ULL : 0xFFFFFFFFULL;
                const uint64_t v = stoi<uint64_t>(imm) & ones;   // unsigned: 64-bit hex fits, and negatives wrap
                for (uint32_t hw = 0; hw < width / 16; ++hw) {
                    if ((v & ~(0xFFFFULL << (hw * 16))) == 0) {
                        op.set_bits(0x52800000 | hw << 21 | static_cast<uint32_t>(v >> (hw * 16)) << 5, 0x7FFFFFE0);
                        return op;
                    }
                }
                for (uint32_t hw = 0; hw < width / 16; ++hw) {
                    if ((~v & ones & ~(0xFFFFULL << (hw * 16))) == 0) {
                        op.set_bits(0x12800000 | hw << 21 | static_cast<uint32_t>((~v & ones) >> (hw * 16)) << 5, 0x7FFFFFE0);
                        return op;
                    }
                }
                auto [ ok, N, imms, immr ] = encode_bitmask_immediate(v, is64);
                if (!ok) return { 0, 0 };
                op.set_bits(0x320003E0 | N << 22 | immr << 16 | imms << 10, 0x7FFFFFE0);
                return op;
            }

            char rm[5] = {};
            parse_token(instr, i, rm);
            const auto rm_val = parse_register(rm);
            if (rd_sp || str_eq(rm, "SP") || str_eq(rm, "WSP")) {
                op.set_bits(0x11000000, 0x7FFFFC00);   // ADD Rd, Rn, #0
                if (rm_val != 0xFFFFFFFF) op.set_bits(rm_val, 0x1F, 5);
            } else {
                op.set_bits(0x2A0003E0, 0x7FE0FFE0);   // ORR Rd, ZR, Rm
                if (rm_val != 0xFFFFFFFF) op.set_bits(rm_val, 0x1F, 16);
            }
            return op;
        }

        constexpr ArmOpcode parse_cbz(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rt[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (rt[0] != '?') base.set_bits((rt[0] == 'W' ? 0 : 1), 1, 31);

            parse_imm19(instr, i, base);
            return base;
        }

        // CMP/CMN/TST Rn, ... are SUBS/ADDS/ANDS ZR, Rn, ...: parsed as that, with the zero register of Rn's width
        template <ParseFunc parse>
        constexpr ArmOpcode parse_zr_dest(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            const char* zr = instr[i] == 'W' ? "WZR, " : instr[i] == 'X' ? "XZR, " : "?, ";
            char line[max_line + 8] = { '_', ' ' };
            size_t j = 2;
            while (*zr) line[j++] = *zr++;
            while (instr[i]) line[j++] = instr[i++];
            ArmOpcode op = parse(line, base);
            op.set_bits(31, 0x1F);
            return op;
        }

        constexpr const char* conditions[] = { "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV" };

        // B.cond: the condition is part of the mnemonic (B.EQ, B.HS); B.? matches any
        constexpr ArmOpcode parse_bcond(const char* instr) {
            ArmOpcode base{ 0x54000000, 0xFF000010 };
            char cond[4] = {};
            for (size_t j = 0; j < 3 && instr[2 + j] && !isspace(instr[2 + j]); ++j) cond[j] = instr[2 + j];
            if (cond[0] != '?') {
                uint32_t c = str_eq(cond, "HS") ? 2 : str_eq(cond, "LO") ? 3 : 16;
                for (uint32_t k = 0; k < 16 && c == 16; ++k)
                    if (str_eq(cond, conditions[k])) c = k;
                if (c == 16) return { 0, 0 };
                base.set_bits(c, 0xF);
            }
            parse_imm19(instr, skip_whitespace(instr, skip_mnemonic(instr)), base);
            return base;
        }

        struct ParseDescriptor {
            const char* mnemonic;
            ParseFunc func;
        };

        constexpr ParseDescriptor parseTable[] = {
            { "B",    parse_branch_imm26 },
            { "BL",   parse_branch_imm26 },
            { "ADR",  parse_adr },
            { "ADRP", parse_adr },
            { "LDR",  parse_ldr },
            { "LDRB", parse_load_store<0x39400000, 0> },
            { "LDRH", parse_load_store<0x79400000, 1> },
            { "LDRSW", parse_load_store<0xB9800000, 2> },
            { "STR",  parse_load_store<0xB9000000, -1> },
            { "STRB", parse_load_store<0x39000000, 0> },
            { "STRH", parse_load_store<0x79000000, 1> },
            { "LDUR", parse_load_store<0xB9400000, -1, true> },
            { "LDURB", parse_load_store<0x39400000, 0, true> },
            { "LDURH", parse_load_store<0x79400000, 1, true> },
            { "LDURSW", parse_load_store<0xB9800000, 2, true> },
            { "STUR", parse_load_store<0xB9000000, -1, true> },
            { "STURB", parse_load_store<0x39000000, 0, true> },
            { "STURH", parse_load_store<0x79000000, 1, true> },
            { "MOVZ", parse_movX },
            { "MOVN", parse_movX },
            { "MOVK", parse_movX },
            { "ORR",  parse_orr },
            { "AND",  parse_orr },
            { "ANDS", parse_orr },
            { "EOR",  parse_orr },
            { "TST",  parse_zr_dest<parse_orr> },
            { "CMP",  parse_zr_dest<parse_arithmetic> },
            { "CMN",  parse_zr_dest<parse_arithmetic> },
            { "LDP",  parse_ldp },
            { "STP",  parse_stp },
            { "MOV",  parse_mov },
            { "ADD",  parse_arithmetic },
            { "ADDS", parse_arithmetic },
            { "SUB",  parse_arithmetic },
            { "SUBS", parse_arithmetic },
            { "CBZ",  parse_cbz },
            { "CBNZ", parse_cbz },
            { "BR",   parse_branch_reg },
            { "BLR",  parse_branch_reg },
            { "RET",  parse_branch_reg },
        };

        constexpr InstructionDescriptor instructions[] = {
            { "B",    { 0x14000000, 0xFC000000 } },
            { "BL",   { 0x94000000, 0xFC000000 } },
            { "ADR",  { 0x10000000, 0x9F000000 } },
            { "ADRP", { 0x90000000, 0x9F000000 } },
            { "ADD",  { 0x01000000, 0x65800000 } },
            { "ADDS", { 0x21000000, 0x65800000 } },
            { "SUB",  { 0x41000000, 0x65000000 } },
            { "SUBS", { 0x61000000, 0x65000000 } },
            { "LDR",  { 0x18000000, 0xBF000000 } },
            { "MOVZ", { 0x52800000, 0x7F800000 } },
            { "MOVN", { 0x12800000, 0x7F800000 } },
            { "MOVK", { 0x72800000, 0x7F800000 } },
            { "ORR",  { 0x22000000, 0x67000000 } },
            { "AND",  { 0x02000000, 0x67000000 } },
            { "ANDS", { 0x62000000, 0x67000000 } },
            { "EOR",  { 0x42000000, 0x67000000 } },
            { "TST",  { 0x62000000, 0x67000000 } },   // ANDS ZR
            { "CMP",  { 0x61000000, 0x65000000 } },   // SUBS ZR
            { "CMN",  { 0x21000000, 0x65800000 } },   // ADDS ZR
            { "LDP",  { 0x28400000, 0x7E400000 } },
            { "STP",  { 0x28000000, 0x7E400000 } },
            { "BR",   { 0xD61F0000, 0xFFFFFC1F } },
            { "BLR",  { 0xD63F0000, 0xFFFFFC1F } },
            { "CBZ",  { 0x34000000, 0x7F000000 } },
            { "CBNZ", { 0x35000000, 0x7F000000 } },
            { "NOP",  { 0xD503201F, 0xFFFFFFFF } },
            { "RET",  { 0xD65F0000, 0xFFFFFC1F } },
            { "RETAA", { 0xD65F0BFF, 0xFFFFFFFF } },
            { "RETAB", { 0xD65F0FFF, 0xFFFFFFFF } },
            { "PACIASP", { 0xD503233F, 0xFFFFFFFF } },
            { "PACIBSP", { 0xD503237F, 0xFFFFFFFF } },
            { "AUTIASP", { 0xD50323BF, 0xFFFFFFFF } },
            { "AUTIBSP", { 0xD50323FF, 0xFFFFFFFF } },
        };

        constexpr ArmOpcode find_opcode(const char* mnemonic) {
            for (const auto& entry : instructions) {
                if (str_eq(entry.mnemonic, mnemonic)) {
                    return entry.opcode;
                }
            }
            return { 0, 0 };
        }

        constexpr ArmOpcode a64_encode_instruction(const char* instr) {
            char mnemonic[8] = {};
            size_t i = 0;
            while (instr[i] && !isspace(instr[i]) && i < 7) {
                mnemonic[i] = instr[i];
                ++i;
            }
            mnemonic[i] = '\0';

            if (starts_with(mnemonic, "B.")) return parse_bcond(instr);
            ArmOpcode base = find_opcode(mnemonic);

            for (const auto& entry : parseTable) {
                if (str_eq(entry.mnemonic, mnemonic)) {
                    return entry.func(instr, base);
                }
            }

            return base;
        }
        
        // Copies the line at str[i] into out, trimmed and uppercased (lldb/objdump print lowercase), so each
        // instruction is parsed on its own and can't run into the next line. Returns where the next line starts
        template <size_t N>
        constexpr size_t read_line(const char* str, size_t i, char (&out)[N]) {
            while (str[i] == ' ' || str[i] == '\t') ++i;
            size_t j = 0;
            for (; str[i] && str[i] != '\n'; ++i) {
                if (j + 1 >= N) throw std::logic_error("Instruction line is too long!");
                out[j++] = (str[i] >= 'a' && str[i] <= 'z') ? static_cast<char>(str[i] - 'a' + 'A') : str[i];
            }
            while (j && isspace(out[j - 1])) --j;
            out[j] = '\0';
            return str[i] ? i + 1 : i;
        }

        // The ArmPattern syntax: one instruction per line, X before the one to resolve, flags after '/'. Calls
        // line(index, instruction) for each instruction (trimmed and uppercased), x(index) for the X line and
        // flags(text) for the text after '/'. Reads up to n chars or a terminator. Returns the number of instructions
        template <class Line, class X, class Flags>
        constexpr size_t parse_arm(const char* p, size_t n, Line&& line, X&& x, Flags&& flags) {
            const size_t options = skip_past(p, 0, '/');
            if (options && p[options - 1] == '/') flags(&p[options]);
            size_t count = 0;
            for (size_t i = 0; i < n && p[i];) {
                char text[max_line] = {};
                i = read_line(p, i, text);
                if (text[0] == '/') break;
                if (!text[0]) continue;
                size_t start = 0;
                if (text[0] == 'X' && (!text[1] || isspace(text[1]))) { x(count); start = skip_whitespace(text, 1); }
                line(count++, &text[start]);
            }
            return count;
        }

        constexpr size_t total_instructions(const char* str, size_t nstr) {
            return parse_arm(str, nstr - 1, [](size_t, const char*) {}, [](size_t) {}, [](const char*) {});
        }

        template <size_t N>
        constexpr size_t total_instructions(const char (&str)[N]) {
            return total_instructions(str, N);
        }
    }

    template <size_t nstr, size_t narr>
    class ArmPattern final : public Pattern {
        std::array<uint32_t, narr> m_instructions{};
        std::array<uint32_t, narr> m_masks{};
    public:
        PATTERNS_CONSTEVAL ArmPattern(const char* p) :
            m_instructions{}, m_masks{}
        {
            arch_ = arch::arm64;
            length_ = narr * 4;
            align_ = true;
            detail::parse_arm(p, nstr,
                [&](size_t i, const char* instruction) {
                    const auto encoded = detail::a64_encode_instruction(instruction);
                    m_instructions[i] = encoded.pattern;
                    m_masks[i] = encoded.mask;
                },
                [&](size_t i) { offset_ = static_cast<uint32_t>(i * 4); },
                [&](const char* flags) { handle_options(flags); });
        }
        virtual const uint8_t* pattern() const override {
            return reinterpret_cast<const uint8_t*>(m_instructions.data());
        }
        virtual const uint8_t* mask() const override {
            return reinterpret_cast<const uint8_t*>(m_masks.data());
        }
    };
}

#ifdef PATTERNS_LITERALS
template<patterns::detail::const_string str>
PATTERNS_CONSTEVAL auto operator""_armpattern() {
    return patterns::ArmPattern<str.length, patterns::detail::total_instructions(str.data, str.size)>(str.data);
}
#endif

#ifndef ARM_PATTERN
#define ARM_PATTERN(x) ([] { constexpr auto p = patterns::ArmPattern<sizeof(x)-1, patterns::detail::total_instructions(x)>(x); return p; }())
#endif