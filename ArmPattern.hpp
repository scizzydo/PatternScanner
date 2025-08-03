#pragma once
#include <cstdint>
#include <cstddef>
#include <bit>
#include <array>

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
            while (instr[i] && instr[i] != ' ') ++i;
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

        constexpr uint64_t clear_trailing_ones(uint64_t n) {
            return n & (n + 1);
        }

        template <typename T>
        constexpr std::tuple<bool, uint32_t, uint32_t, uint32_t> encode_bitmask_immediate(T value) {
            uint64_t val = (value > 0xFFFFFFFFULL) ? value : (static_cast<uint64_t>(static_cast<uint32_t>(value)) << 32) | static_cast<uint32_t>(value);

            if (val == 0 || ~val == 0)
                return { false, 0, 0, 0 };

            int rotation = std::countr_zero(clear_trailing_ones(val));
            uint64_t normalized = rotate_right(val, rotation & 63);

            int zeroes = std::countl_zero(normalized);
            int ones = std::countr_zero(~normalized);
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
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            if (instr[i] == '?') {
                base.pattern &= 0xFC000000;
                base.mask    &= 0xFC000000;
            } else {
                base.set_bits(static_cast<uint32_t>(stoi(&instr[i]) >> 2), 0x3FFFFFF);
            }

            return base;
        }

        constexpr ArmOpcode parse_adr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            // Rd
            i = parse_register(instr, i, 0x1F, 0, base, ',');

            char imm[24] = {};
            i = parse_imm_token(instr, skip_char(instr, i, '#'), imm);
            if (!(imm[0] == '?' && imm[1] == '\0')) {
                if (int64_t offset = stoi<int64_t>(imm); offset != -1) {
                    if ((base.pattern >> 31) & 1) offset >>= 12;
                    base.set_bits(static_cast<uint32_t>((offset << 24) | ((offset >> 2) & 0x7FFFF)), (3 << 24 | 0x7FFFF), 5);
                }
            }
            return base;
        }

        constexpr std::tuple<bool, bool, bool, bool> parse_load_store_defaults(const char* instr, size_t i, ArmOpcode& base, uint32_t size_bit = 0) {
            char rt[5] = {}, imm[24] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (size_bit && rt[0] != '?') base.set_bits((rt[0] == 'W' ? 0 : 1), 1, size_bit);
            if (instr[i++] != '[') return { false, false, false, false };

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base);

            bool is_register_offset = false, is_pre_index = false, is_post_index = false;
            uint32_t option_val = 0b011, s_val = 0;

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
                        s_val = static_cast<uint32_t>(stoi(&instr[++i])) > 0 ? 1 : 0;
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

            if (is_register_offset) base.set_bits((option_val << 1) | s_val, 0xF, 12);

            if (imm[0] != '?') {
                int32_t val = stoi(imm);
                if (!is_register_offset && (is_pre_index || is_post_index)) {
                    if (val >= -256 && val <= 255)
                        base.set_bits(val, 0x1FF, 12);
                } else if (!is_register_offset && (size_bit == 0 || rt[0] != '?')) {
                    auto shift = size_bit > 0 ? (rt[0] == 'W' ? 2 : 3) : 1;
                    if ((val & 1) == 0 && (val >> shift) <= 0xFFF) {
                        base.set_bits((val >> shift), 0xFFF, 10);
                    }
                }
            }

            return { true, is_register_offset, is_pre_index, is_post_index };
        }

        constexpr ArmOpcode parse_ldrh(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            auto [ ok, is_register_offset, is_pre_index, is_post_index ] = parse_load_store_defaults(instr, i, base);
            if (!ok) return base;

            if (is_register_offset)   base.set_bits(0x78600800, 0xFFE00C00);
            else if (is_pre_index)    base.set_bits(0x78400C00, 0xFFE00C00);
            else if (is_post_index)   base.set_bits(0x78400400, 0xFFE00C00);
            else /* Unsigned offset*/ base.set_bits(0x79400000, 0xFFC00000);

            return base;
        }

        constexpr ArmOpcode parse_ldr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            auto [ ok, is_register_offset, is_pre_index, is_post_index ] = parse_load_store_defaults(instr, i, base, 30);
            if (!ok) {
                char imm[24] = {};
                i = parse_imm_token(instr, skip_whitespace(instr, skip_past(instr, i, ',')), imm);

                if (!(imm[0] == '?' && imm[1] == '\0')) {
                    int32_t val = stoi(imm);
                    if ((val & 3) != 0) val &= ~3;
                    base.set_bits((val >> 2), 0x7FFFF, 5);
                }
                return base;
            }

            if (is_register_offset) base.set_bits(0xB8600800, 0xBFE00C00);
            else if (is_pre_index)  base.set_bits(0xB8400C00, 0xBFE00C00);
            else if (is_post_index) base.set_bits(0xB8400400, 0xBFE00C00);
            else                    base.set_bits(0xB9400000, 0xBFC00000);

            return base;
        }

        constexpr ArmOpcode parse_orr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rd[5] = {}/*, rn[5] = {}*/;
            i = parse_register(instr, parse_token(instr, i, rd), rd, 0x1F, 0, base, ',');
            if (rd[0] != '?') base.set_bits((rd[0] == 'W' ? 0 : 1), 1, 31);

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base, ',');
            
            if (instr[i] == '#') {
                base.set_bits((2 << 4), (3 << 4 | 1), 23);

                char imm[24] = {};
                i = parse_imm_token(instr, i, imm);
                if (imm[0] != '?') {
                    uint64_t immVal = stoi<uint64_t>(imm);
                    auto [ ok, N, imms, immr ] = encode_bitmask_immediate(immVal);
                    if (ok) base.set_bits((N << 12 | immr << 6 | imms), (1 << 12 | 0x3F << 6 | 0x3F), 10);
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

                i = skip_whitespace(instr, skip_char(instr, i, '#'));
                if (instr[i] != '?') base.set_bits(stoi(&instr[i]), 0x3F, 10);

            } else {
                base.set_mask((3 << 12 | 0x3F), 10);
            }
            
            return base;
        }

        constexpr ArmOpcode parse_arithmetic(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rd[5] = {};
            i = parse_register(instr, parse_token(instr, i, rd), rd, 0x1F, 0, base, ',');
            if (rd[0] != '?') base.set_bits((rd[0] == 'W' ? 0b0 : 0b1), 1, 31);

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base, ',');

            if (instr[i] == '#') {
                base.set_bits((2 << 4 | 2), (3 << 4 | 7), 23);
                char imm[24] = {};
                i = parse_imm_token(instr, i, imm);
                if (imm[0] != '?') base.set_bits(stoi(imm), 0xFFF, 10);

                if (instr[i] == ',') {
                    i = skip_whitespace(instr, i+1);
                    if      (starts_with(&instr[i], "LSL#0"))  base.set_mask(1, 22);
                    else if (starts_with(&instr[i], "LSL#12")) base.set_bits(1, 1, 22);
                } else {
                    base.set_mask(1, 22);
                }
                return base;
            }

            base.set_bits(5, 0xF, 25);
            // Rm
            i = parse_register(instr, i, 0x1F, 16, base);

            if (instr[i] == ',') {
                i = skip_whitespace(instr, i + 1);
                bool shifted = false, extended = false;
                if      (starts_with(&instr[i], "LSL"))  { base.set_bits(0, 7, 21); shifted = true;  i += 3; }
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
            } else {
                base.set_bits(0, (7 << 11 | 0x7F), 10);
            }

            return base;
        }

        constexpr ArmOpcode parse_ldp(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rt1[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt1), rt1, 0x1F, 0, base, ',');
            bool know_size = rt1[0] != '?';
            uint32_t size_bits = know_size ? (rt1[0] == 'W' ? 0b0 : 0b1) : 0;
            if (know_size) base.set_bits(size_bits, 1, 31);

            // Rt2
            i = parse_register(instr, i, 0x1F, 10, base, ',');

            if (instr[i] != '[') return base;
            i = skip_whitespace(instr, skip_char(instr, i, '['));

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base, ',');

            bool post_index = false, signed_offset = false, pre_index = false;
            char imm[24] = {};
            if (instr[i] == '#') {
                i = skip_whitespace(instr, parse_imm_token(instr, i, imm));
                signed_offset = true;
            }
            if (instr[i] == ']') {
                i = skip_whitespace(instr, skip_char(instr, skip_char(instr, i, ']'), ','));
                if (instr[i] == '!') {
                    pre_index = true;
                } else if (instr[i] == '#') {
                    post_index = true;
                    i = parse_imm_token(instr, i, imm);
                }
            }
            if (!(post_index || pre_index || signed_offset)) return base;
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

        constexpr ArmOpcode parse_str(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            auto [ ok, is_register_offset, is_pre_index, is_post_index ] = parse_load_store_defaults(instr, i, base, 30);
            if (!ok) return base;

            if (is_register_offset) base.set_bits(0xB8200800, 0xBFE00C00);
            else if (is_pre_index)  base.set_bits(0xB8000C00, 0xBFE00C00);
            else if (is_post_index) base.set_bits(0xB8000400, 0xBFE00C00);
            else                    base.set_bits(0xB9000000, 0xBFC00000);     

            return base;
        }

        constexpr ArmOpcode parse_cbz(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rt[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (rt[0] != '?') base.set_bits((rt[0] == 'W' ? 0 : 1), 1, 31);

            char imm[24] = {};
            i = parse_imm_token(instr, i, imm);

            if (!(imm[0] == '?' && imm[1] == '\0')) {
                int32_t val = stoi(imm);
                if ((val & 3) != 0) val &= ~3;
                base.set_bits((val >> 2), 0x7FFFF, 5);
            }
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
            { "LDRH", parse_ldrh },
            { "LDR",  parse_ldr },
            { "MOVZ", parse_movX },
            { "MOVN", parse_movX },
            { "MOVK", parse_movX },
            { "ORR",  parse_orr },
            { "LDP",  parse_ldp },
            { "ADD",  parse_arithmetic },
            { "ADDS", parse_arithmetic },
            { "SUB",  parse_arithmetic },
            { "SUBS", parse_arithmetic },
            { "STR",  parse_str },
            { "CBZ",  parse_cbz },
            { "CBNZ", parse_cbz },
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
            { "LDRH", { 0x38400000, 0x3B200000 } },
            { "LDR",  { 0x18000000, 0xBF000000 } },
            { "MOVZ", { 0x52800000, 0x7F800000 } },
            { "MOVN", { 0x12800000, 0x7F800000 } },
            { "MOVK", { 0x72800000, 0x7F800000 } },
            { "ORR",  { 0x22000000, 0x67000000 } },
            { "LDP",  { 0x28400000, 0x7E400000 } },
            { "BR",   { 0xD61F0000, 0xFFFFFC1F } },
            { "BLR",  { 0xD63F0000, 0xFFFFFC1F } },
            { "STR",  { 0xB8000000, 0xBEC00000 } },
            { "CBZ",  { 0x34000000, 0x7F000000 } },
            { "CBNZ", { 0x35000000, 0x7F000000 } },
            { "NOP",  { 0xD503201F, 0xFFFFFFFF } },
            { "RET",  { 0xD65F03C0, 0xFFFFFFFF } },
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
            while (instr[i] && instr[i] != ' ' && i < 7) {
                mnemonic[i] = instr[i];
                ++i;
            }
            mnemonic[i] = '\0';

            ArmOpcode base = find_opcode(mnemonic);

            for (const auto& entry : parseTable) {
                if (str_eq(entry.mnemonic, mnemonic)) {
                    return entry.func(instr, base);
                }
            }

            return base;
        }
        
        constexpr size_t total_instructions(const char* str, size_t nstr) {
            size_t line = 0, count = 0;
            for (size_t i = 0; i < nstr - 1; ++i) {
                if (str[i] == '\n') ++line, count = 0;
                else if (count == 0 && str[i] == '/') break;
                else ++count;
            }
            return line + (count > 0 ? 1 : 0);
        }

        template <size_t N>
        constexpr size_t total_instructions(const char (&str)[N]) {
            return total_instructions(str, N);
        }
    }

    template <size_t nstr, size_t narr>
    class ArmPattern : public Pattern {
        std::array<uint32_t, narr> m_instructions{};
        std::array<uint32_t, narr> m_masks{};
    public:
        constexpr ArmPattern(const char* p) :
            m_instructions{}, m_masks{}
        {
            length_ = narr * 4;
            uint32_t idx = 0;
            // Find the options
            size_t options = detail::skip_past(p, 0, '/');
            if (p[options - 1] == '/') handle_options(&p[options]);
            align_ = true;
            for (size_t i = detail::skip_whitespace(p, 0); i < nstr && idx < narr;) {
                size_t start = detail::skip_char(p, i, ' ');
                if (p[start] == 'X') { offset_ = idx * 4; start = detail::skip_whitespace(p, start + 1); }
                size_t end = detail::skip_past(p, start, '\n');
                if (idx + 1 == narr && end > options) end = options;
                auto encoded = detail::a64_encode_instruction(&p[start]);
                m_instructions[idx] = encoded.pattern;
                m_masks[idx++] = encoded.mask;
                i = end;
            }
        }
        virtual const uint8_t* pattern() const override {
            return reinterpret_cast<const uint8_t*>(m_instructions.data());
        }
        virtual const uint8_t* mask() const override {
            return reinterpret_cast<const uint8_t*>(m_masks.data());
        }
    };
}

#ifndef ARM_PATTERN
#define ARM_PATTERN(x) patterns::ArmPattern<sizeof(x)-1, patterns::detail::total_instructions(x)>(x)
#endif