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

        constexpr size_t skip_mnemonic(const char* instr) {
            size_t i = 0;
            while (instr[i] && !isspace(instr[i])) ++i;
            return i;
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

        // Matches what either encoding matches: the bits they share. One with mask 0 (the operands don't fit it) drops out
        constexpr ArmOpcode either(ArmOpcode a, ArmOpcode b) {
            if (!a.mask || !b.mask) return a.mask ? a : b;
            const uint32_t m = a.mask & b.mask & ~(a.pattern ^ b.pattern);
            return { a.pattern & m, m };
        }

        struct InstructionDescriptor {
            const char* mnemonic;
            ArmOpcode opcode;
        };

        constexpr uint32_t parse_register(const char* token) {
            if (token[0] == '?' && token[1] == '\0')
                return 0xFFFFFFFF;

            if ((token[0] == 'W' || token[0] == 'X' || token[0] == 'B' || token[0] == 'H' || token[0] == 'S' ||
                 token[0] == 'D' || token[0] == 'Q') && token[1] >= '0' && token[1] <= '9') {
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

        // Floating-point/SIMD register: log2 of its size (B 0, H 1, S 2, D 3, Q 4), or -1 for any other token
        constexpr int fp_size(const char* token) {
            if (!((token[1] >= '0' && token[1] <= '9') || (token[1] == '?' && !token[2]))) return -1;
            switch (token[0]) {
                case 'B': return 0;
                case 'H': return 1;
                case 'S': return 2;
                case 'D': return 3;
                case 'Q': return 4;
                default:  return -1;
            }
        }

        // Comma-separated registers (brackets and '!' skipped), each into the 5-bit field at shifts[k] (-1: not
        // encoded); widths[k] gets register_width. Returns the index past them
        template <size_t N>
        constexpr size_t parse_reg_list(const char* instr, size_t i, const int (&shifts)[N], ArmOpcode& base, int (&widths)[N]) {
            for (size_t k = 0; k < N; ++k) {
                while (instr[i] == ',' || instr[i] == '[' || isspace(instr[i])) ++i;
                char token[5] = {};
                i = parse_token(instr, i, token);
                widths[k] = register_width(token);
                if (auto r = parse_register(token); r != 0xFFFFFFFF && shifts[k] >= 0) base.set_bits(r, 0x1F, shifts[k]);
                while (instr[i] == ']' || instr[i] == '!' || isspace(instr[i])) ++i;
            }
            return i;
        }

        // Instructions that are only registers. width_bit (sf at 31, or size bit 30 for loads/stores) is set from the
        // first known width among the registers in the width_regs bitmask
        template <int width_bit, unsigned width_regs, int... shifts>
        constexpr ArmOpcode parse_regs(const char* instr, ArmOpcode base) {
            constexpr int sh[] = { shifts... };
            int w[sizeof...(shifts)] = {};
            parse_reg_list(instr, skip_mnemonic(instr), sh, base, w);
            for (size_t k = 0; k < sizeof...(shifts) && width_bit >= 0; ++k)
                if ((width_regs >> k & 1) && w[k] >= 0) { base.set_bits(static_cast<uint32_t>(w[k]), 1, width_bit); break; }
            return base;
        }

        constexpr const char* conditions[] = { "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV" };

        // Condition code: 0-15 (HS and LO too), 16 for "?", 17 if unknown
        constexpr uint32_t parse_cond(const char* c) {
            if (c[0] == '?' && !c[1]) return 16;
            if (str_eq(c, "HS")) return 2;
            if (str_eq(c, "LO")) return 3;
            for (uint32_t k = 0; k < 16; ++k)
                if (str_eq(c, conditions[k])) return k;
            return 17;
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

        // A PC-relative word offset at bit 5 from a byte offset: imm19 for CBZ/CBNZ, B.cond and LDR (literal), imm14 for TBZ/TBNZ
        template <int bits = 19>
        constexpr void parse_branch_imm(const char* instr, size_t i, ArmOpcode& base) {
            char imm[24] = {};
            parse_imm_token(instr, i, imm);
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(stoi(imm) >> 2), (1u << bits) - 1, 5);
        }

        // Single-register loads/stores. op is the unsigned offset form; the unscaled (LDUR), pre/post-index and
        // register offset forms differ from it in fixed bits. scale is log2 of the access size, or -1 to take it
        // from Rt: W or X (bit 30), or a floating-point/SIMD register B/H/S/D/Q (size, V bit 26, opc bit 23). A bare
        // "?" Rt is W or X. sign_extend (LDRSB/LDRSH): opc is 11 for a W Rt and 10 for X, so bit 22 comes from Rt.
        // An offset the unsigned form can't hold (negative, unaligned) is encoded unscaled, the way assemblers pick
        // LDUR/STUR
        template <uint32_t op_int, int scale, bool unscaled = false, bool sign_extend = false>
        constexpr ArmOpcode parse_load_store(const char* instr, ArmOpcode) {
            ArmOpcode base{ 0, 0 };
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));

            char rt[5] = {}, imm[24] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (scale < 0 && str_eq(rt, "?")) {
                // W or X: the offset's scaling and form (LDR or LDUR) depend on which, so encode both
                const size_t at = skip_whitespace(instr, skip_mnemonic(instr));
                char w[max_line + 8] = {}, x[max_line + 8] = {};
                for (size_t s = 0, j = 0; instr[s]; ++s, ++j) {
                    w[j] = x[j] = instr[s];
                    if (s == at) { w[j] = 'W'; x[j] = 'X'; ++j; w[j] = x[j] = '0'; }
                }
                ArmOpcode e = either(parse_load_store<op_int, scale, unscaled, sign_extend>(w, {}),
                                     parse_load_store<op_int, scale, unscaled, sign_extend>(x, {}));
                e.pattern &= ~0x1Fu;
                e.mask &= ~0x1Fu;
                return e;
            }
            const int fp = scale < 0 ? fp_size(rt) : -1;
            if (rt[0] != 'W' && rt[0] != 'X' && rt[0] != '?' && fp < 0) return { 0, 0 };
            int size = scale;
            uint32_t op = op_int, width_mask = ~0u;   // width_mask: Rt's width bit, set below when known
            if (fp >= 0) {
                size = fp;
                op = (op & 0x3FFFFFFF) | static_cast<uint32_t>(fp & 3) << 30 | 1u << 26 | static_cast<uint32_t>(fp >> 2) << 23;
            } else if (scale < 0) {
                width_mask = ~(1u << 30);
                if (rt[0] != '?') {
                    size = rt[0] == 'W' ? 2 : 3;
                    base.set_bits(size - 2, 1, 30);
                }
            } else if (sign_extend) {
                width_mask = ~(1u << 22);
                if (rt[0] != '?') base.set_bits(rt[0] == 'W' ? 1 : 0, 1, 22);
            }
            if (instr[i++] != '[') return { 0, 0 };

            // Rn
            i = parse_register(instr, i, 0x1F, 5, base);

            bool is_register_offset = false, is_pre_index = false, is_post_index = false;
            uint32_t option_val = 0b011, option_mask = 0b111, s_val = 0, s_mask = 1;

            if (instr[i] == ',') {
                i = skip_whitespace(instr, ++i);
                if (instr[i] == '#') {
                    i = parse_imm_token(instr, i, imm);
                } else {
                    // Rm
                    i = parse_register(instr, i, 0x1F, 16, base, ',');
                    is_register_offset = true;

                    // "?": any extend, and any amount unless one follows
                    if      (instr[i] == '?')                { option_mask = 0; s_mask = 0; ++i; }
                    else if (starts_with(&instr[i], "LSL"))  { option_val = 0b011; i += 3; }
                    else if (starts_with(&instr[i], "UXTW")) { option_val = 0b010; i += 4; }
                    else if (starts_with(&instr[i], "SXTW")) { option_val = 0b110; i += 4; }
                    else if (starts_with(&instr[i], "SXTX")) { option_val = 0b111; i += 4; }

                    i = skip_whitespace(instr, skip_char(instr, i, ','));
                    if (instr[i] == '#') {
                        // For bytes an explicit #0 is the shifted form; for the rest the amount is 0 or the scale
                        s_mask = 1;
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
                base.set_bits(option_val << 1 | s_val, option_mask << 1 | s_mask, 12);
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
            // opc (bits 30-31) is 00 for W, 01 for X; with V (bit 26) 00 for S, 01 for D, 10 for Q
            if (const int fp = fp_size(rt); fp >= 2) base.set_bits(static_cast<uint32_t>(fp - 2) << 4 | 1, 0x31, 26);
            else if (rt[0] != 'W' && rt[0] != 'X' && rt[0] != '?') return { 0, 0 };
            else if (rt[0] != '?') base.set_bits((rt[0] == 'W' ? 0 : 1), 1, 30);
            parse_branch_imm(instr, i, base);
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
                if (base.pattern >> 21 & 1) return { 0, 0 };   // BIC/ORN/EON (N set) have no immediate form
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
            // Shifted register; N (bit 21) comes from the table: set for BIC/ORN/EON
            base.set_bits((1 << 6), (3 << 6), 21);
            base.set_mask(1, 21);

            // Rm
            i = parse_register(instr, i, 0x1F, 16, base);

            if (instr[i] == ',') {
                i = skip_whitespace(instr, skip_char(instr, i, ','));
                const bool any = instr[i] == '?';   // any shift: type and amount
                if      (any) ++i;
                else if (starts_with(&instr[i], "LSL")) { base.set_bits(0, 3, 22); i += 3; }
                else if (starts_with(&instr[i], "LSR")) { base.set_bits(1, 3, 22); i += 3; }
                else if (starts_with(&instr[i], "ASR")) { base.set_bits(2, 3, 22); i += 3; }
                else if (starts_with(&instr[i], "ROR")) { base.set_bits(3, 3, 22); i += 3; }
                else base.set_bits(0, 3, 22);

                i = skip_char(instr, skip_whitespace(instr, i), '#');
                if (instr[i] != '?' && !(any && !instr[i])) base.set_bits(stoi(&instr[i]), 0x3F, 10);

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
                // Any shift or extend: they share bits 10-15 and 21-23 (the table pins bit 23, which only ASR sets)
                if (instr[i] == '?') {
                    base.pattern &= ~(7u << 21 | 0x3Fu << 10);
                    base.mask    &= ~(7u << 21 | 0x3Fu << 10);
                    return base;
                }
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

        // LDP/STP and the forms sharing their layout; the table gives the load bit (22). opc (bits 30-31) is 00 for W
        // and 10 for X, or with V (bit 26) 00 for S, 01 for D, 10 for Q; LDPSW passes it (01). no_allocate: LDNP/STNP,
        // which only have the signed offset form
        template <int opc = -1, bool no_allocate = false>
        constexpr ArmOpcode parse_ldp(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rt1[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt1), rt1, 0x1F, 0, base, ',');
            char rt2[5] = {};
            i = parse_register(instr, parse_token(instr, i, rt2), rt2, 0x1F, 10, base, ',');
            // Width from Rt1, or from Rt2 when Rt1 is "?"
            const int width = register_width(rt1) >= 0 ? register_width(rt1) : register_width(rt2);
            const int fp = fp_size(rt1) >= 0 ? fp_size(rt1) : fp_size(rt2);
            int scale = -1;   // log2 of one register's size, when known
            if (fp >= 2 && opc < 0) {
                base.set_bits(static_cast<uint32_t>(fp - 2) << 4 | 1, 0x31, 26);
                scale = fp;
            } else if (fp >= 0 || (rt1[0] != 'W' && rt1[0] != 'X' && rt1[0] != '?')) {
                return { 0, 0 };
            } else if (opc >= 0) {
                if (width == 0) return { 0, 0 };   // LDPSW loads into X
                base.set_bits(static_cast<uint32_t>(opc), 3, 30);
                scale = 2;
            } else if (width >= 0) {
                base.set_bits(static_cast<uint32_t>(width), 1, 31);
                scale = 2 + width;
            }

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
            if (no_allocate && (pre_index || post_index)) return { 0, 0 };
            // Bits 23-25: post-index 001, signed offset 010, pre-index 011, no-allocate offset 000
            base.set_bits(post_index ? 1 : pre_index ? 3 : no_allocate ? 0 : 2, 7, 23);
            if (imm[0] != '?' && scale >= 0) {
                int32_t immVal = stoi(imm);
                if ((immVal % (1 << scale)) == 0) {
                    int32_t encoded = immVal / (1 << scale);
                    if (encoded >= -64 && encoded <= 63) {
                        base.set_bits(encoded, 0x7F, 15);
                    }
                }
            }
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

            parse_branch_imm(instr, i, base);
            return base;
        }

        // Aliases that write the zero register (of the first operand's width) as operand pos, parsed as the full form:
        // CMP/CMN/TST Rn, ... are SUBS/ADDS/ANDS ZR, Rn, ... (pos 0); MVN/NEG(S)/NGC(S) Rd, ... are
        // ORN/SUB(S)/SBC(S) Rd, ZR, ... (pos 1)
        template <ParseFunc parse, int pos = 0>
        constexpr ArmOpcode parse_zr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            const char* zr = instr[i] == 'W' ? "WZR, " : instr[i] == 'X' ? "XZR, " : "?, ";
            char line[max_line + 8] = { '_', ' ' };
            size_t j = 2;
            if (pos == 1) {
                while (instr[i] && instr[i] != ',') line[j++] = instr[i++];
                line[j++] = ',';
                line[j++] = ' ';
                i = skip_whitespace(instr, skip_char(instr, i, ','));
            }
            while (*zr) line[j++] = *zr++;
            while (instr[i]) line[j++] = instr[i++];
            ArmOpcode op = parse(line, base);
            op.set_bits(31, 0x1F, pos == 0 ? 0 : 5);
            return op;
        }

        // B.cond: the condition is part of the mnemonic (B.EQ, B.HS); B.? matches any
        constexpr ArmOpcode parse_bcond(const char* instr) {
            ArmOpcode base{ 0x54000000, 0xFF000010 };
            char cond[4] = {};
            for (size_t j = 0; j < 3 && instr[2 + j] && !isspace(instr[2 + j]); ++j) cond[j] = instr[2 + j];
            const uint32_t c = parse_cond(cond);
            if (c == 17) return { 0, 0 };
            if (c < 16) base.set_bits(c, 0xF);
            parse_branch_imm(instr, skip_whitespace(instr, skip_mnemonic(instr)), base);
            return base;
        }

        // TBZ/TBNZ Rt, #bit, #offset: b5 (bit 31) is the bit number's top bit, b40 (bits 19-23) the rest. A W register
        // (or a bit number below 32) means b5 is 0
        constexpr ArmOpcode parse_tbz(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rt[5] = {}, bit[24] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            i = skip_whitespace(instr, skip_char(instr, parse_imm_token(instr, i, bit), ','));
            const int width = register_width(rt);
            if (bit[0] == '?') {
                if (width == 0) base.set_bits(0, 1, 31);
            } else {
                const int32_t b = stoi(bit);
                if (b < 0 || b >= (width == 0 ? 32 : 64)) return { 0, 0 };
                base.set_bits(static_cast<uint32_t>(b), 0x1F, 19);
                base.set_bits(static_cast<uint32_t>(b) >> 5, 1, 31);
            }
            parse_branch_imm<14>(instr, i, base);
            return base;
        }

        // SVC/HVC/SMC/BRK/HLT #imm16 (bit 5), UDF #imm16 (bit 0)
        template <int shift>
        constexpr ArmOpcode parse_imm16(const char* instr, ArmOpcode base) {
            char imm[24] = {};
            parse_imm_token(instr, skip_whitespace(instr, skip_mnemonic(instr)), imm);
            if (imm[0] != '?') {
                const int64_t v = stoi<int64_t>(imm);
                if (v < 0 || v > 0xFFFF) return { 0, 0 };
                base.set_bits(static_cast<uint32_t>(v), 0xFFFF, shift);
            }
            return base;
        }

        // BTI {C|J|JC}: the targets at bits 6-7, BTI ? for any
        constexpr ArmOpcode parse_bti(const char* instr, ArmOpcode base) {
            const char* t = &instr[skip_whitespace(instr, skip_mnemonic(instr))];
            const uint32_t targets = !*t ? 0 : str_eq(t, "C") ? 1 : str_eq(t, "J") ? 2 : str_eq(t, "JC") ? 3 : 4;
            if (str_eq(t, "?")) base.mask &= ~(3u << 6);
            else if (targets == 4) return { 0, 0 };
            else base.set_bits(targets, 3, 6);
            return base;
        }

        // LDRAA/LDRAB Xt, [Xn{,#imm}]{!}: imm10 scaled by 8 (sign at bit 22, the rest at 12-20), writeback at bit 11
        constexpr ArmOpcode parse_ldraa(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rt[5] = {}, imm[24] = {};
            i = parse_register(instr, parse_token(instr, i, rt), rt, 0x1F, 0, base, ',');
            if (rt[0] != 'X' && rt[0] != '?') return { 0, 0 };
            if (instr[i++] != '[') return { 0, 0 };
            i = parse_register(instr, i, 0x1F, 5, base);
            if (instr[i] == ',') i = parse_imm_token(instr, skip_whitespace(instr, i + 1), imm);
            i = skip_whitespace(instr, skip_past(instr, i, ']'));
            base.set_bits(instr[i] == '!' ? 1 : 0, 1, 11);
            if (imm[0] != '?') {
                const int32_t val = stoi(imm);
                if (val % 8 || val < -4096 || val > 4088) return { 0, 0 };
                const uint32_t enc = static_cast<uint32_t>(val / 8) & 0x3FF;
                base.set_bits(enc, 0x1FF, 12);
                base.set_bits(enc >> 9, 1, 22);
            }
            return base;
        }

        // Exact decimal (1, -2.5, 0.125) as num / den; false if it isn't one
        constexpr bool parse_decimal(const char* s, bool& negative, uint64_t& num, uint64_t& den) {
            negative = *s == '-';
            if (*s == '-' || *s == '+') ++s;
            num = 0; den = 1;
            bool digits = false, dot = false;
            for (; *s; ++s) {
                if (*s == '.' && !dot) { dot = true; continue; }
                if (*s < '0' || *s > '9' || den > 1000000000000ULL || num > 1000000000000ULL) return false;
                num = num * 10 + static_cast<uint64_t>(*s - '0');
                if (dot) den *= 10;
                digits = true;
            }
            return digits;
        }

        // FMOV: register (Hd/Sd/Dd, same type), general-purpose to/from floating-point (Sd/Wn, Dd/Xn, Hd/Wn|Xn, and
        // back), or an 8-bit immediate (#1.0, #-2.5: +-n/16 * 2^e, n 16-31, e -3..4; #0.0 is FMOV from the zero
        // register). A bare "?" register is the same kind as the other one
        constexpr ArmOpcode parse_fmov(const char* instr, ArmOpcode) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rd[5] = {}, rn[5] = {};
            i = skip_whitespace(instr, skip_char(instr, parse_token(instr, i, rd), ','));
            constexpr uint32_t ftype[] = { 4, 3, 0, 1, 4 };   // by fp_size: H 11, S 00, D 01 (B and Q: none)
            const int fd = fp_size(rd);
            ArmOpcode op{ 0, 0 };
            if (auto r = parse_register(rd); r != 0xFFFFFFFF) op.set_bits(r, 0x1F);

            char imm[24] = {};
            if (instr[i] == '#') {
                parse_imm_token(instr, i, imm);
                if (fd < 0 || ftype[fd] > 3) return { 0, 0 };
                bool negative = false;
                uint64_t num = 0, den = 1;
                if (imm[0] != '?' && !parse_decimal(imm, negative, num, den)) return { 0, 0 };
                if (imm[0] != '?' && num == 0) {
                    if (negative) return { 0, 0 };
                    rn[0] = fd == 3 ? 'X' : 'W'; rn[1] = 'Z'; rn[2] = 'R';   // FMOV Rd, ZR
                } else {
                    op.set_bits(0x1E201000 | ftype[fd] << 22, 0xFFE01FE0);
                    if (imm[0] == '?') return op;
                    for (uint32_t imm8 = 0; imm8 < 256; ++imm8) {
                        // (16 + n) / 16 * 2^e == num / den
                        const int e = (imm8 >> 6 & 1) ? static_cast<int>(imm8 >> 4 & 3) - 3 : static_cast<int>(imm8 >> 4 & 3) + 1;
                        const uint64_t m = 16 + (imm8 & 15);
                        const bool eq = e >= 0 ? m * den << e == num * 16 : m * den == num * 16 << -e;
                        if (eq && (imm8 >> 7) == (negative ? 1u : 0u)) {
                            op.set_bits(imm8, 0xFF, 13);
                            return op;
                        }
                    }
                    return { 0, 0 };
                }
            } else {
                parse_token(instr, i, rn);
            }
            if (auto r = parse_register(rn); r != 0xFFFFFFFF) op.set_bits(r, 0x1F, 5);
            const int fn = fp_size(rn);
            const int gd = register_width(rd), gn = register_width(rn);
            const bool qd = str_eq(rd, "?"), qn = str_eq(rn, "?");
            if ((fd >= 0 || qd) && (fn >= 0 || qn)) {
                // Between floating-point registers
                const int f = fd >= 0 ? fd : fn;
                if (f >= 0 && (ftype[f] > 3 || (fd >= 0 && fn >= 0 && fd != fn))) return { 0, 0 };
                op.set_bits(0x1E204000, 0xFF3FFC00);
                if (f >= 0) op.set_bits(ftype[f], 3, 22);
                return op;
            }
            // General-purpose <-> floating-point: sf, type, then rmode 00 and opcode 110 (to general) or 111 (from it)
            const bool to_fp = fd >= 0;
            const int f = to_fp ? fd : fn, g = to_fp ? gn : gd;
            if (f < 0 || g < 0 || ftype[f] > 3 || (f == 2 && g != 0) || (f == 3 && g != 1)) return { 0, 0 };
            op.set_bits(0x1E260000 | static_cast<uint32_t>(g) << 31 | ftype[f] << 22 | (to_fp ? 1u : 0u) << 16, 0xFFFFFC00);
            return op;
        }

        // CSEL/CSINC/CSINV/CSNEG Rd, Rn, Rm, cond. regs is how many registers are written: 1 for CSET/CSETM (Rn = Rm =
        // ZR), 2 for CINC/CINV/CNEG (Rm = Rn). The aliases store the inverted condition, and can't take AL or NV
        template <size_t regs>
        constexpr ArmOpcode parse_csel(const char* instr, ArmOpcode base) {
            constexpr int all[] = { 0, 5, 16 };
            int shifts[regs] = {}, w[regs] = {};
            for (size_t k = 0; k < regs; ++k) shifts[k] = all[k];
            size_t i = parse_reg_list(instr, skip_mnemonic(instr), shifts, base, w);
            for (size_t k = 0; k < regs; ++k)
                if (w[k] >= 0) { base.set_bits(static_cast<uint32_t>(w[k]), 1, 31); break; }
            if (regs == 1) base.set_bits(31 << 11 | 31, 0x1F << 11 | 0x1F, 5);
            if (regs == 2 && (base.mask >> 5 & 0x1F)) base.set_bits(base.pattern >> 5, 0x1F, 16);
            char cond[4] = {};
            parse_token(instr, skip_whitespace(instr, skip_char(instr, i, ',')), cond);
            uint32_t c = parse_cond(cond);
            if (c == 17 || (regs < 3 && c >= 14 && c < 16)) return { 0, 0 };
            if (c < 16) base.set_bits(regs < 3 ? c ^ 1 : c, 0xF, 12);
            return base;
        }

        // CCMP/CCMN Rn, Rm|#imm5, #nzcv, cond: the immediate form sets bit 11
        constexpr ArmOpcode parse_ccmp(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char rn[5] = {}, imm[24] = {}, cond[4] = {};
            i = parse_register(instr, parse_token(instr, i, rn), rn, 0x1F, 5, base, ',');
            if (register_width(rn) >= 0) base.set_bits(static_cast<uint32_t>(register_width(rn)), 1, 31);
            if (instr[i] == '#') {
                i = parse_imm_token(instr, i, imm);
                base.set_bits(1, 1, 11);
                if (imm[0] != '?') {
                    const int32_t v = stoi(imm);
                    if (v < 0 || v > 31) return { 0, 0 };
                    base.set_bits(static_cast<uint32_t>(v), 0x1F, 16);
                }
            } else {
                char rm[5] = {};
                i = parse_token(instr, i, rm);
                parse_register(rm, 0x1F, 16, base);
                base.set_bits(0, 1, 11);
            }
            i = parse_imm_token(instr, skip_whitespace(instr, skip_char(instr, i, ',')), imm);
            if (imm[0] != '?') {
                const int32_t v = stoi(imm);
                if (v < 0 || v > 15) return { 0, 0 };
                base.set_bits(static_cast<uint32_t>(v), 0xF);
            }
            parse_token(instr, skip_whitespace(instr, skip_char(instr, i, ',')), cond);
            const uint32_t c = parse_cond(cond);
            if (c == 17) return { 0, 0 };
            if (c < 16) base.set_bits(c, 0xF, 12);
            return base;
        }

        enum BitfieldKind { bf_raw, bf_lsl, bf_lsr, bf_extract, bf_insert, bf_extend, bf_ror, bf_extr };

        // UBFM/SBFM/BFM and their aliases, and EXTR (ROR #imm is EXTR Rd, Rn, Rn): immr (bits 16-21) and imms (10-15)
        // computed for the register size; N (bit 22) equals sf. With the width unknown ("?" registers) both sizes
        // are encoded and only the bits they agree on are kept; a size the operands don't fit drops out.
        // bf_extend (SXTB/SXTH/SXTW, UXTB/UXTH) has imms fixed to extend_imms
        template <BitfieldKind kind, uint32_t extend_imms = 0>
        constexpr ArmOpcode parse_bitfield(const char* instr, ArmOpcode base) {
            constexpr size_t nregs = kind == bf_extr ? 3 : 2;
            constexpr int all[] = { 0, 5, 16 };
            int shifts[nregs] = {}, w[nregs] = {};
            for (size_t k = 0; k < nregs; ++k) shifts[k] = all[k];
            size_t i = parse_reg_list(instr, skip_mnemonic(instr), shifts, base, w);
            if (kind == bf_ror && (base.mask >> 5 & 0x1F)) base.set_bits(base.pattern >> 5, 0x1F, 16);
            // Width from Rd; SXT*/UXT* sources are always W, so only Rd says
            int width = -1;
            for (size_t k = 0; k < (kind == bf_extend ? 1 : nregs) && width < 0; ++k) width = w[k];

            char a_text[24] = {}, b_text[24] = {};
            i = parse_imm_token(instr, skip_whitespace(instr, skip_char(instr, i, ',')), a_text);
            parse_imm_token(instr, skip_whitespace(instr, skip_char(instr, i, ',')), b_text);
            const bool ak = a_text[0] != '?', bk = b_text[0] != '?';
            const int32_t a = ak ? stoi(a_text) : 0, b = bk ? stoi(b_text) : 1;
            const bool ubfm = (base.pattern >> 29 & 3) == 2 && kind != bf_ror && kind != bf_extr;

            // Only known values are checked; a field depending on a "?" is left open
            auto encode = [&](int32_t size) -> ArmOpcode {
                if (kind == bf_extend ? (ubfm && size == 64) || (size == 32 && extend_imms == 31) : ak && (a < 0 || a >= size))
                    return { 0, 0 };
                if ((kind == bf_raw && bk && (b < 0 || b >= size)) ||
                    ((kind == bf_extract || kind == bf_insert) && bk && (b < 1 || (ak ? a : 0) + b > size)))
                    return { 0, 0 };
                int32_t immr = 0, imms = 0;
                bool immr_known = true, imms_known = true;
                switch (kind) {
                    case bf_raw:     immr = a; imms = b; immr_known = ak; imms_known = bk; break;
                    case bf_lsl:     immr = (size - a) & (size - 1); imms = size - 1 - a; immr_known = imms_known = ak; break;
                    case bf_lsr:     immr = a; imms = size - 1; immr_known = ak; break;
                    case bf_extract: immr = a; imms = a + b - 1; immr_known = ak; imms_known = ak && bk; break;
                    case bf_insert:  immr = (size - a) & (size - 1); imms = b - 1; immr_known = ak; imms_known = bk; break;
                    case bf_extend:  imms = static_cast<int32_t>(extend_imms); break;
                    case bf_ror:
                    case bf_extr:    imms = a; immr_known = false; imms_known = ak; break;   // EXTR has Rm at immr
                }
                ArmOpcode op{ 0, 0 };
                op.set_bits(size == 64 ? 0x80400000 : 0, 0x80400000);
                if (immr_known) op.set_bits(static_cast<uint32_t>(immr), 0x3F, 16);
                if (imms_known) op.set_bits(static_cast<uint32_t>(imms), 0x3F, 10);
                return op;
            };

            // A valid encoding always has sf/N in its mask; mask 0 means the size doesn't fit
            const ArmOpcode e = width < 0 ? either(encode(32), encode(64)) : encode(width == 0 ? 32 : 64);
            if (!e.mask) return { 0, 0 };
            base.set_bits(e.pattern, e.mask);
            return base;
        }

        // LSL/LSR/ASR/ROR: by an immediate a bitfield (EXTR for ROR) alias, by a register LSLV/LSRV/ASRV/RORV (op2 at
        // bits 10-11)
        template <BitfieldKind kind, uint32_t op2>
        constexpr ArmOpcode parse_shift(const char* instr, ArmOpcode base) {
            const size_t i = skip_whitespace(instr, skip_past(instr, skip_past(instr, 0, ','), ','));
            if (instr[i] == '#') return parse_bitfield<kind>(instr, base);
            return parse_regs<31, 7, 0, 5, 16>(instr, { 0x1AC02000 | op2 << 10, 0x7FE0FC00 });
        }

        // LSE atomics and CAS, from the mnemonic: LD<op>{A}{L}{B|H} Rs, Rt, [Rn]; ST<op>{L}{B|H} Rs, [Rn] (LD<op> into
        // ZR); SWP{A}{L}{B|H} and CAS{A}{L}{B|H} Rs, Rt, [Rn]. op is ADD, CLR, EOR, SET, SMAX, SMIN, UMAX or UMIN.
        // size (bits 30-31) from the B/H suffix, else W or X from Rs/Rt
        constexpr ArmOpcode parse_atomic(const char* m, const char* instr) {
            constexpr const char* ops[] = { "ADD", "CLR", "EOR", "SET", "SMAX", "SMIN", "UMAX", "UMIN" };
            ArmOpcode base{ 0x38200000, 0x3F200C00 };
            uint32_t a_bit = 23, l_bit = 22;   // acquire, release
            size_t j = 0;
            const bool store = starts_with(m, "ST");
            if (starts_with(m, "CAS")) { base = { 0x08A07C00, 0x3FA07C00 }; a_bit = 22; l_bit = 15; j = 3; }
            else if (starts_with(m, "SWP")) { base.set_bits(8, 0xF, 12); j = 3; }
            else if (starts_with(m, "LD") || store) {
                for (uint32_t k = 0; k < 8 && !j; ++k)
                    if (starts_with(m + 2, ops[k])) { base.set_bits(k, 0xF, 12); j = k < 4 ? 5 : 6; }
            }
            if (!j) return { 0, 0 };
            const bool acquire = m[j] == 'A' && !store;
            if (acquire) ++j;
            const bool release = m[j] == 'L';
            if (release) ++j;
            const int size = m[j] == 'B' ? 0 : m[j] == 'H' ? 1 : -1;
            if (size >= 0) ++j;
            if (m[j]) return { 0, 0 };
            base.set_bits(acquire ? 1 : 0, 1, a_bit);
            base.set_bits(release ? 1 : 0, 1, l_bit);
            base.set_bits(size >= 0 ? static_cast<uint32_t>(size) : 2, size >= 0 ? 3 : 2, 30);

            constexpr int load_shifts[] = { 16, 0, 5 }, store_shifts[] = { 16, 5 };
            int w[3] = { -1, -1, -1 }, ws[2] = {};
            if (store) {
                parse_reg_list(instr, skip_mnemonic(instr), store_shifts, base, ws);
                base.set_bits(31, 0x1F);
                w[0] = ws[0];
            } else {
                parse_reg_list(instr, skip_mnemonic(instr), load_shifts, base, w);
            }
            const int width = w[0] >= 0 ? w[0] : w[1];
            if (size < 0 && width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 30);
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
            { "TST",  parse_zr<parse_orr> },
            { "CMP",  parse_zr<parse_arithmetic> },
            { "CMN",  parse_zr<parse_arithmetic> },
            { "LDP",  parse_ldp },
            { "STP",  parse_ldp },
            { "LDPSW", parse_ldp<1> },
            { "LDNP", parse_ldp<-1, true> },
            { "STNP", parse_ldp<-1, true> },
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
            { "TBZ",  parse_tbz },
            { "TBNZ", parse_tbz },
            { "SVC",  parse_imm16<5> },
            { "HVC",  parse_imm16<5> },
            { "SMC",  parse_imm16<5> },
            { "BRK",  parse_imm16<5> },
            { "HLT",  parse_imm16<5> },
            { "UDF",  parse_imm16<0> },
            { "BTI",  parse_bti },
            { "BRAA",  parse_regs<-1, 0, 5, 0> },
            { "BRAB",  parse_regs<-1, 0, 5, 0> },
            { "BLRAA", parse_regs<-1, 0, 5, 0> },
            { "BLRAB", parse_regs<-1, 0, 5, 0> },
            { "BRAAZ",  parse_branch_reg },
            { "BRABZ",  parse_branch_reg },
            { "BLRAAZ", parse_branch_reg },
            { "BLRABZ", parse_branch_reg },
            { "LDRAA", parse_ldraa },
            { "LDRAB", parse_ldraa },
            { "PACIA", parse_regs<-1, 0, 0, 5> },
            { "PACIB", parse_regs<-1, 0, 0, 5> },
            { "PACDA", parse_regs<-1, 0, 0, 5> },
            { "PACDB", parse_regs<-1, 0, 0, 5> },
            { "AUTIA", parse_regs<-1, 0, 0, 5> },
            { "AUTIB", parse_regs<-1, 0, 0, 5> },
            { "AUTDA", parse_regs<-1, 0, 0, 5> },
            { "AUTDB", parse_regs<-1, 0, 0, 5> },
            { "PACIZA", parse_regs<-1, 0, 0> },
            { "PACIZB", parse_regs<-1, 0, 0> },
            { "PACDZA", parse_regs<-1, 0, 0> },
            { "PACDZB", parse_regs<-1, 0, 0> },
            { "AUTIZA", parse_regs<-1, 0, 0> },
            { "AUTIZB", parse_regs<-1, 0, 0> },
            { "AUTDZA", parse_regs<-1, 0, 0> },
            { "AUTDZB", parse_regs<-1, 0, 0> },
            { "XPACI", parse_regs<-1, 0, 0> },
            { "XPACD", parse_regs<-1, 0, 0> },
            { "PACGA", parse_regs<-1, 0, 0, 5, 16> },
            { "LDRSB",  parse_load_store<0x39800000, 0, false, true> },
            { "LDRSH",  parse_load_store<0x79800000, 1, false, true> },
            { "LDURSB", parse_load_store<0x39800000, 0, true, true> },
            { "LDURSH", parse_load_store<0x79800000, 1, true, true> },
            { "LDXR",   parse_regs<30, 1, 0, 5> },
            { "LDAXR",  parse_regs<30, 1, 0, 5> },
            { "LDAR",   parse_regs<30, 1, 0, 5> },
            { "LDAPR",  parse_regs<30, 1, 0, 5> },
            { "STLR",   parse_regs<30, 1, 0, 5> },
            { "STXR",   parse_regs<30, 2, 16, 0, 5> },
            { "STLXR",  parse_regs<30, 2, 16, 0, 5> },
            { "LDXRB",  parse_regs<-1, 0, 0, 5> },
            { "LDXRH",  parse_regs<-1, 0, 0, 5> },
            { "LDAXRB", parse_regs<-1, 0, 0, 5> },
            { "LDAXRH", parse_regs<-1, 0, 0, 5> },
            { "LDARB",  parse_regs<-1, 0, 0, 5> },
            { "LDARH",  parse_regs<-1, 0, 0, 5> },
            { "LDAPRB", parse_regs<-1, 0, 0, 5> },
            { "LDAPRH", parse_regs<-1, 0, 0, 5> },
            { "STLRB",  parse_regs<-1, 0, 0, 5> },
            { "STLRH",  parse_regs<-1, 0, 0, 5> },
            { "STXRB",  parse_regs<-1, 0, 16, 0, 5> },
            { "STXRH",  parse_regs<-1, 0, 16, 0, 5> },
            { "STLXRB", parse_regs<-1, 0, 16, 0, 5> },
            { "STLXRH", parse_regs<-1, 0, 16, 0, 5> },
            { "LDXP",   parse_regs<30, 3, 0, 10, 5> },
            { "LDAXP",  parse_regs<30, 3, 0, 10, 5> },
            { "STXP",   parse_regs<30, 6, 16, 0, 10, 5> },
            { "STLXP",  parse_regs<30, 6, 16, 0, 10, 5> },
            { "FMOV",  parse_fmov },
            { "CSEL",  parse_csel<3> },
            { "CSINC", parse_csel<3> },
            { "CSINV", parse_csel<3> },
            { "CSNEG", parse_csel<3> },
            { "CSET",  parse_csel<1> },
            { "CSETM", parse_csel<1> },
            { "CINC",  parse_csel<2> },
            { "CINV",  parse_csel<2> },
            { "CNEG",  parse_csel<2> },
            { "CCMP",  parse_ccmp },
            { "CCMN",  parse_ccmp },
            { "MADD",  parse_regs<31, 15, 0, 5, 16, 10> },
            { "MSUB",  parse_regs<31, 15, 0, 5, 16, 10> },
            { "MUL",   parse_regs<31, 7, 0, 5, 16> },
            { "MNEG",  parse_regs<31, 7, 0, 5, 16> },
            { "SMADDL", parse_regs<-1, 0, 0, 5, 16, 10> },
            { "SMSUBL", parse_regs<-1, 0, 0, 5, 16, 10> },
            { "UMADDL", parse_regs<-1, 0, 0, 5, 16, 10> },
            { "UMSUBL", parse_regs<-1, 0, 0, 5, 16, 10> },
            { "SMULL",  parse_regs<-1, 0, 0, 5, 16> },
            { "SMNEGL", parse_regs<-1, 0, 0, 5, 16> },
            { "UMULL",  parse_regs<-1, 0, 0, 5, 16> },
            { "UMNEGL", parse_regs<-1, 0, 0, 5, 16> },
            { "SMULH",  parse_regs<-1, 0, 0, 5, 16> },
            { "UMULH",  parse_regs<-1, 0, 0, 5, 16> },
            { "UDIV",  parse_regs<31, 7, 0, 5, 16> },
            { "SDIV",  parse_regs<31, 7, 0, 5, 16> },
            { "LSLV",  parse_regs<31, 7, 0, 5, 16> },
            { "LSRV",  parse_regs<31, 7, 0, 5, 16> },
            { "ASRV",  parse_regs<31, 7, 0, 5, 16> },
            { "RORV",  parse_regs<31, 7, 0, 5, 16> },
            { "ADC",   parse_regs<31, 7, 0, 5, 16> },
            { "ADCS",  parse_regs<31, 7, 0, 5, 16> },
            { "SBC",   parse_regs<31, 7, 0, 5, 16> },
            { "SBCS",  parse_regs<31, 7, 0, 5, 16> },
            { "NGC",   parse_zr<parse_regs<31, 7, 0, 5, 16>, 1> },
            { "NGCS",  parse_zr<parse_regs<31, 7, 0, 5, 16>, 1> },
            { "BIC",   parse_orr },
            { "BICS",  parse_orr },
            { "ORN",   parse_orr },
            { "EON",   parse_orr },
            { "MVN",   parse_zr<parse_orr, 1> },
            { "NEG",   parse_zr<parse_arithmetic, 1> },
            { "NEGS",  parse_zr<parse_arithmetic, 1> },
            { "SBFM",  parse_bitfield<bf_raw> },
            { "BFM",   parse_bitfield<bf_raw> },
            { "UBFM",  parse_bitfield<bf_raw> },
            { "EXTR",  parse_bitfield<bf_extr> },
            { "LSL",   parse_shift<bf_lsl, 0> },
            { "LSR",   parse_shift<bf_lsr, 1> },
            { "ASR",   parse_shift<bf_lsr, 2> },
            { "ROR",   parse_shift<bf_ror, 3> },
            { "UBFX",  parse_bitfield<bf_extract> },
            { "SBFX",  parse_bitfield<bf_extract> },
            { "BFXIL", parse_bitfield<bf_extract> },
            { "UBFIZ", parse_bitfield<bf_insert> },
            { "SBFIZ", parse_bitfield<bf_insert> },
            { "BFI",   parse_bitfield<bf_insert> },
            { "SXTB",  parse_bitfield<bf_extend, 7> },
            { "SXTH",  parse_bitfield<bf_extend, 15> },
            { "SXTW",  parse_bitfield<bf_extend, 31> },
            { "UXTB",  parse_bitfield<bf_extend, 7> },
            { "UXTH",  parse_bitfield<bf_extend, 15> },
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
            { "PACIAZ",  { 0xD503231F, 0xFFFFFFFF } },
            { "PACIBZ",  { 0xD503235F, 0xFFFFFFFF } },
            { "AUTIAZ",  { 0xD503239F, 0xFFFFFFFF } },
            { "AUTIBZ",  { 0xD50323DF, 0xFFFFFFFF } },
            { "PACIA1716", { 0xD503211F, 0xFFFFFFFF } },
            { "PACIB1716", { 0xD503215F, 0xFFFFFFFF } },
            { "AUTIA1716", { 0xD503219F, 0xFFFFFFFF } },
            { "AUTIB1716", { 0xD50321DF, 0xFFFFFFFF } },
            { "XPACLRI", { 0xD50320FF, 0xFFFFFFFF } },
            { "BTI",     { 0xD503241F, 0xFFFFFFFF } },
            { "TBZ",  { 0x36000000, 0x7F000000 } },
            { "TBNZ", { 0x37000000, 0x7F000000 } },
            { "SVC",  { 0xD4000001, 0xFFE0001F } },
            { "HVC",  { 0xD4000002, 0xFFE0001F } },
            { "SMC",  { 0xD4000003, 0xFFE0001F } },
            { "BRK",  { 0xD4200000, 0xFFE0001F } },
            { "HLT",  { 0xD4400000, 0xFFE0001F } },
            { "UDF",  { 0x00000000, 0xFFFF0000 } },
            { "BRAA",   { 0xD71F0800, 0xFFFFFC00 } },
            { "BRAB",   { 0xD71F0C00, 0xFFFFFC00 } },
            { "BLRAA",  { 0xD73F0800, 0xFFFFFC00 } },
            { "BLRAB",  { 0xD73F0C00, 0xFFFFFC00 } },
            { "BRAAZ",  { 0xD61F081F, 0xFFFFFC1F } },
            { "BRABZ",  { 0xD61F0C1F, 0xFFFFFC1F } },
            { "BLRAAZ", { 0xD63F081F, 0xFFFFFC1F } },
            { "BLRABZ", { 0xD63F0C1F, 0xFFFFFC1F } },
            { "LDRAA",  { 0xF8200400, 0xFFA00400 } },
            { "LDRAB",  { 0xF8A00400, 0xFFA00400 } },
            { "PACIA",  { 0xDAC10000, 0xFFFFFC00 } },
            { "PACIB",  { 0xDAC10400, 0xFFFFFC00 } },
            { "PACDA",  { 0xDAC10800, 0xFFFFFC00 } },
            { "PACDB",  { 0xDAC10C00, 0xFFFFFC00 } },
            { "AUTIA",  { 0xDAC11000, 0xFFFFFC00 } },
            { "AUTIB",  { 0xDAC11400, 0xFFFFFC00 } },
            { "AUTDA",  { 0xDAC11800, 0xFFFFFC00 } },
            { "AUTDB",  { 0xDAC11C00, 0xFFFFFC00 } },
            { "PACIZA", { 0xDAC123E0, 0xFFFFFFE0 } },
            { "PACIZB", { 0xDAC127E0, 0xFFFFFFE0 } },
            { "PACDZA", { 0xDAC12BE0, 0xFFFFFFE0 } },
            { "PACDZB", { 0xDAC12FE0, 0xFFFFFFE0 } },
            { "AUTIZA", { 0xDAC133E0, 0xFFFFFFE0 } },
            { "AUTIZB", { 0xDAC137E0, 0xFFFFFFE0 } },
            { "AUTDZA", { 0xDAC13BE0, 0xFFFFFFE0 } },
            { "AUTDZB", { 0xDAC13FE0, 0xFFFFFFE0 } },
            { "XPACI",  { 0xDAC143E0, 0xFFFFFFE0 } },
            { "XPACD",  { 0xDAC147E0, 0xFFFFFFE0 } },
            { "PACGA",  { 0x9AC03000, 0xFFE0FC00 } },
            { "LDXR",   { 0x885F7C00, 0xBFFFFC00 } },
            { "LDAXR",  { 0x885FFC00, 0xBFFFFC00 } },
            { "LDAR",   { 0x88DFFC00, 0xBFFFFC00 } },
            { "LDAPR",  { 0xB8BFC000, 0xBFFFFC00 } },
            { "STLR",   { 0x889FFC00, 0xBFFFFC00 } },
            { "STXR",   { 0x88007C00, 0xBFE0FC00 } },
            { "STLXR",  { 0x8800FC00, 0xBFE0FC00 } },
            { "LDXRB",  { 0x085F7C00, 0xFFFFFC00 } },
            { "LDXRH",  { 0x485F7C00, 0xFFFFFC00 } },
            { "LDAXRB", { 0x085FFC00, 0xFFFFFC00 } },
            { "LDAXRH", { 0x485FFC00, 0xFFFFFC00 } },
            { "LDARB",  { 0x08DFFC00, 0xFFFFFC00 } },
            { "LDARH",  { 0x48DFFC00, 0xFFFFFC00 } },
            { "LDAPRB", { 0x38BFC000, 0xFFFFFC00 } },
            { "LDAPRH", { 0x78BFC000, 0xFFFFFC00 } },
            { "STLRB",  { 0x089FFC00, 0xFFFFFC00 } },
            { "STLRH",  { 0x489FFC00, 0xFFFFFC00 } },
            { "STXRB",  { 0x08007C00, 0xFFE0FC00 } },
            { "STXRH",  { 0x48007C00, 0xFFE0FC00 } },
            { "STLXRB", { 0x0800FC00, 0xFFE0FC00 } },
            { "STLXRH", { 0x4800FC00, 0xFFE0FC00 } },
            { "LDXP",   { 0x887F0000, 0xBFFF8000 } },
            { "LDAXP",  { 0x887F8000, 0xBFFF8000 } },
            { "STXP",   { 0x88200000, 0xBFE08000 } },
            { "STLXP",  { 0x88208000, 0xBFE08000 } },
            { "LDPSW", { 0x28400000, 0x7E400000 } },
            { "LDNP",  { 0x28400000, 0x7E400000 } },
            { "STNP",  { 0x28000000, 0x7E400000 } },
            { "CSEL",  { 0x1A800000, 0x7FE00C00 } },
            { "CSINC", { 0x1A800400, 0x7FE00C00 } },
            { "CSINV", { 0x5A800000, 0x7FE00C00 } },
            { "CSNEG", { 0x5A800400, 0x7FE00C00 } },
            { "CSET",  { 0x1A800400, 0x7FE00C00 } },   // CSINC Rd, ZR, ZR
            { "CSETM", { 0x5A800000, 0x7FE00C00 } },   // CSINV Rd, ZR, ZR
            { "CINC",  { 0x1A800400, 0x7FE00C00 } },   // CSINC Rd, Rn, Rn
            { "CINV",  { 0x5A800000, 0x7FE00C00 } },   // CSINV Rd, Rn, Rn
            { "CNEG",  { 0x5A800400, 0x7FE00C00 } },   // CSNEG Rd, Rn, Rn
            { "CCMP",  { 0x7A400000, 0x7FE00410 } },
            { "CCMN",  { 0x3A400000, 0x7FE00410 } },
            { "MADD",  { 0x1B000000, 0x7FE08000 } },
            { "MSUB",  { 0x1B008000, 0x7FE08000 } },
            { "MUL",   { 0x1B007C00, 0x7FE0FC00 } },   // MADD Ra = ZR
            { "MNEG",  { 0x1B00FC00, 0x7FE0FC00 } },   // MSUB Ra = ZR
            { "SMADDL", { 0x9B200000, 0xFFE08000 } },
            { "SMSUBL", { 0x9B208000, 0xFFE08000 } },
            { "UMADDL", { 0x9BA00000, 0xFFE08000 } },
            { "UMSUBL", { 0x9BA08000, 0xFFE08000 } },
            { "SMULL",  { 0x9B207C00, 0xFFE0FC00 } },
            { "SMNEGL", { 0x9B20FC00, 0xFFE0FC00 } },
            { "UMULL",  { 0x9BA07C00, 0xFFE0FC00 } },
            { "UMNEGL", { 0x9BA0FC00, 0xFFE0FC00 } },
            { "SMULH",  { 0x9B407C00, 0xFFE0FC00 } },
            { "UMULH",  { 0x9BC07C00, 0xFFE0FC00 } },
            { "UDIV",  { 0x1AC00800, 0x7FE0FC00 } },
            { "SDIV",  { 0x1AC00C00, 0x7FE0FC00 } },
            { "LSLV",  { 0x1AC02000, 0x7FE0FC00 } },
            { "LSRV",  { 0x1AC02400, 0x7FE0FC00 } },
            { "ASRV",  { 0x1AC02800, 0x7FE0FC00 } },
            { "RORV",  { 0x1AC02C00, 0x7FE0FC00 } },
            { "ADC",   { 0x1A000000, 0x7FE0FC00 } },
            { "ADCS",  { 0x3A000000, 0x7FE0FC00 } },
            { "SBC",   { 0x5A000000, 0x7FE0FC00 } },
            { "SBCS",  { 0x7A000000, 0x7FE0FC00 } },
            { "NGC",   { 0x5A000000, 0x7FE0FC00 } },   // SBC Rd, ZR, Rm
            { "NGCS",  { 0x7A000000, 0x7FE0FC00 } },   // SBCS Rd, ZR, Rm
            { "BIC",   { 0x02200000, 0x67200000 } },
            { "BICS",  { 0x62200000, 0x67200000 } },
            { "ORN",   { 0x22200000, 0x67200000 } },
            { "EON",   { 0x42200000, 0x67200000 } },
            { "MVN",   { 0x22200000, 0x67200000 } },   // ORN Rd, ZR, Rm
            { "NEG",   { 0x41000000, 0x65000000 } },   // SUB Rd, ZR, Rm
            { "NEGS",  { 0x61000000, 0x65000000 } },   // SUBS Rd, ZR, Rm
            { "SBFM",  { 0x13000000, 0x7F800000 } },
            { "BFM",   { 0x33000000, 0x7F800000 } },
            { "UBFM",  { 0x53000000, 0x7F800000 } },
            { "EXTR",  { 0x13800000, 0x7FA00000 } },
            { "LSL",   { 0x53000000, 0x7F800000 } },   // UBFM
            { "LSR",   { 0x53000000, 0x7F800000 } },   // UBFM
            { "ASR",   { 0x13000000, 0x7F800000 } },   // SBFM
            { "ROR",   { 0x13800000, 0x7FA00000 } },   // EXTR Rd, Rn, Rn
            { "UBFX",  { 0x53000000, 0x7F800000 } },
            { "SBFX",  { 0x13000000, 0x7F800000 } },
            { "BFXIL", { 0x33000000, 0x7F800000 } },
            { "UBFIZ", { 0x53000000, 0x7F800000 } },
            { "SBFIZ", { 0x13000000, 0x7F800000 } },
            { "BFI",   { 0x33000000, 0x7F800000 } },
            { "SXTB",  { 0x13000000, 0x7F800000 } },
            { "SXTH",  { 0x13000000, 0x7F800000 } },
            { "SXTW",  { 0x13000000, 0x7F800000 } },
            { "UXTB",  { 0x53000000, 0x7F800000 } },
            { "UXTH",  { 0x53000000, 0x7F800000 } },
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
            char mnemonic[16] = {};
            size_t i = 0;
            while (instr[i] && !isspace(instr[i]) && i < 15) {
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

            return base.mask ? base : parse_atomic(mnemonic, instr);
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