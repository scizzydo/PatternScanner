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

        constexpr bool starts_with(const char* a, const char* prefix) {
            while (*prefix) {
                if (*a != *prefix) return false;
                ++a; ++prefix;
            }
            return true;
        }

        // Operand errors (a typo, a value out of range, a missing or extra operand) fail: a compile error for
        // compile-time patterns. Only an unknown mnemonic becomes a wildcard

        // An operand up to the next separator; fails if it doesn't fit out (no operand is that long)
        template <size_t N>
        constexpr size_t parse_token(const char* str, size_t i, char (&out)[N]) {
            size_t j = 0;
            while (str[i] && str[i] != ',' && str[i] != ']' && !isspace(str[i])) {
                if (j + 1 >= N) PATTERNS_FAIL("Invalid operand!");
                out[j++] = str[i++];
            }
            out[j] = '\0';
            return i;
        }

        // Decimal or 0x hex, optionally negative, nothing else, within 64 bits (-2^63 for negatives)
        constexpr bool is_number(const char* s) {
            const bool negative = *s == '-';
            if (negative) ++s;
            const bool hex = s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
            if (hex) s += 2;
            const uint64_t base = hex ? 16 : 10;
            uint64_t v = 0;
            size_t digits = 0;
            for (; hex ? is_hex_digit(*s) : is_digit(*s); ++s, ++digits) {
                const uint64_t d = static_cast<uint64_t>(get_bits(*s));
                if (v > (~0ULL - d) / base) return false;
                v = v * base + d;
            }
            return digits && !*s && (!negative || v <= 1ULL << 63);
        }

        // An immediate ('#' optional): a number or "?". numeric false leaves the text to the caller (FMOV's decimals)
        template <bool numeric = true, size_t N>
        constexpr size_t parse_imm_token(const char* str, size_t i, char (&out)[N]) {
            i = skip_whitespace(str, i);
            if (str[i] == '#') ++i;
            i = parse_token(str, i, out);
            if (numeric && !str_eq(out, "?") && !is_number(out)) PATTERNS_FAIL("Invalid immediate!");
            return i;
        }

        // A known immediate (checked by parse_imm_token) as signed: fails past INT64_MAX, which would wrap negative
        constexpr int64_t signed_imm(const char* token) {
            const int64_t v = stoi<int64_t>(token);
            if (v < 0 && token[0] != '-') PATTERNS_FAIL("Immediate out of range!");
            return v;
        }

        // A known immediate (checked by parse_imm_token) in [lo, hi] and a multiple of align
        constexpr int64_t imm_in(const char* token, int64_t lo, int64_t hi, int64_t align = 1) {
            const int64_t v = signed_imm(token);
            if (v < lo || v > hi || v % align) PATTERNS_FAIL("Immediate out of range!");
            return v;
        }

        // Past ch and the whitespace around it; fails if ch isn't next (a missing operand or bracket)
        constexpr size_t expect(const char* instr, size_t i, char ch) {
            i = skip_whitespace(instr, i);
            if (instr[i] != ch) PATTERNS_FAIL("Malformed operands!");
            return skip_whitespace(instr, i + 1);
        }

        // Past ch and the whitespace around it, if ch is next
        constexpr bool accept(const char* instr, size_t& i, char ch) {
            const size_t j = skip_whitespace(instr, i);
            if (instr[j] != ch) return false;
            i = skip_whitespace(instr, j + 1);
            return true;
        }

        // Past word (a shift or extend) and the whitespace around it, if word is next
        constexpr bool keyword(const char* instr, size_t& i, const char* word) {
            const size_t j = skip_whitespace(instr, i);
            if (!starts_with(&instr[j], word)) return false;
            size_t n = 0;
            while (word[n]) ++n;
            i = skip_whitespace(instr, j + n);
            return true;
        }


        constexpr size_t max_line = 128;

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

        // After the last operand: anything left is a typo or an operand the instruction doesn't take. op by reference:
        // callers pass base next to a call that fills it in, and argument order is unspecified (MSVC copies first)
        constexpr ArmOpcode done(const char* instr, size_t i, const ArmOpcode& op) {
            if (instr[skip_whitespace(instr, i)]) PATTERNS_FAIL("Unexpected text after the operands!");
            return op;
        }

        struct InstructionDescriptor {
            const char* mnemonic;
            ArmOpcode opcode;
        };

        // What a register operand may be, as a mask: a general-purpose register where the encoding reads 31 as the
        // zero register, one where it reads 31 as SP (bases, ADD/SUB and logical immediate Rd), or floating-point/SIMD
        enum RegKind : unsigned { reg_zr = 1, reg_sp = 2, reg_fp = 4 };

        // The number of the register in token, or 0xFFFFFFFF for a wildcard ("?", or "X?", "W?", "D?"... of an
        // allowed kind). Fails on anything else: not a register, out of range (X31, D32) or a kind not allowed
        constexpr uint32_t parse_register(const char* token, unsigned kinds) {
            if (str_eq(token, "?")) return 0xFFFFFFFF;
            const char c = token[0];
            const bool gp = c == 'W' || c == 'X';
            const bool fp = c == 'B' || c == 'H' || c == 'S' || c == 'D' || c == 'Q';
            if ((gp && (kinds & (reg_zr | reg_sp))) || (fp && (kinds & reg_fp))) {
                if (token[1] == '?' && !token[2]) return 0xFFFFFFFF;
                uint32_t val = 0;
                size_t i = 1;
                for (; i < 3 && token[i] >= '0' && token[i] <= '9'; ++i) val = val * 10 + static_cast<uint32_t>(token[i] - '0');
                if (i > 1 && !token[i] && val < (gp ? 31u : 32u)) return val;
            }
            if (((kinds & reg_zr) && (str_eq(token, "XZR") || str_eq(token, "WZR"))) ||
                ((kinds & reg_sp) && (str_eq(token, "SP") || str_eq(token, "WSP"))))
                return 31;
            PATTERNS_FAIL("Invalid register!");
        }

        // 1 for a 64-bit register (X, SP, XZR), 0 for 32-bit (W, WSP, WZR), -1 when unknown ("?")
        constexpr int register_width(const char* token) {
            return token[0] == 'X' || str_eq(token, "SP") ? 1 : token[0] == 'W' ? 0 : -1;
        }

        constexpr bool is_sp(const char* token) {
            return str_eq(token, "SP") || str_eq(token, "WSP");
        }

        // Two register sizes that must match (register_width): fails on W with X. Returns the known one, or -1
        constexpr int same_width(int a, int b) {
            if (a >= 0 && b >= 0 && a != b) PATTERNS_FAIL("Register size doesn't fit the instruction!");
            return a >= 0 ? a : b;
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

        // A register operand of the allowed kinds into the 5-bit field at shift, its text into out. Returns past it
        template <size_t N>
        constexpr size_t read_register(const char* instr, size_t i, char (&out)[N], unsigned kinds, uint32_t shift, ArmOpcode& base) {
            i = parse_token(instr, skip_whitespace(instr, i), out);
            if (const uint32_t r = parse_register(out, kinds); r != 0xFFFFFFFF) base.set_bits(r, 0x1F, shift);
            return i;
        }

        // parse_reg_list operands: the field's shift, plus what the register may be. Without r_w or r_x it's W or X,
        // the same size as the other such operands
        constexpr int r_w = 1 << 8;      // always W
        constexpr int r_x = 1 << 9;      // always X
        constexpr int r_sp = 1 << 10;    // 31 is SP, not the zero register
        constexpr int r_mem = 1 << 11;   // in brackets
        constexpr int r_base = r_x | r_sp | r_mem;   // [Xn|SP]

        // Comma-separated registers as specs say. width gets the size of the ones without r_w or r_x (-1 if
        // unknown). Returns past them
        template <size_t N>
        constexpr size_t parse_reg_list(const char* instr, size_t i, const int (&specs)[N], ArmOpcode& base, int& width) {
            width = -1;
            for (size_t k = 0; k < N; ++k) {
                const int s = specs[k];
                if (k) i = expect(instr, i, ',');
                if (s & r_mem) i = expect(instr, i, '[');
                char token[5] = {};
                i = read_register(instr, i, token, s & r_sp ? reg_sp : reg_zr, static_cast<uint32_t>(s & 0x1F), base);
                if (s & (r_w | r_x)) same_width(register_width(token), s & r_x ? 1 : 0);
                else width = same_width(width, register_width(token));
                if (s & r_mem) i = expect(instr, i, ']');
            }
            return i;
        }

        // Instructions that are only registers (specs as parse_reg_list). width_bit (sf at 31, or size bit 30 for
        // loads/stores) is set from the registers without r_w or r_x
        template <int width_bit, int... specs>
        constexpr ArmOpcode parse_regs(const char* instr, ArmOpcode base) {
            constexpr int s[] = { specs... };
            int width = -1;
            const size_t i = parse_reg_list(instr, skip_mnemonic(instr), s, base, width);
            if (width_bit >= 0 && width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, width_bit);
            return done(instr, i, base);
        }

        inline constexpr const char* conditions[] = { "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV" };

        // Condition code: 0-15 (HS and LO too), 16 for "?", 17 if unknown
        constexpr uint32_t parse_cond(const char* c) {
            if (c[0] == '?' && !c[1]) return 16;
            if (str_eq(c, "HS")) return 2;
            if (str_eq(c, "LO")) return 3;
            for (uint32_t k = 0; k < 16; ++k)
                if (str_eq(c, conditions[k])) return k;
            return 17;
        }

        using ParseFunc = ArmOpcode(*)(const char* instr, ArmOpcode base);

        // Passthrough parser (no field parsing)
        constexpr ArmOpcode parse_passthrough(const char*, ArmOpcode base) {
            return base;
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
            char rd[5] = {}, imm[24] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rd, reg_zr, 0, base);
            const int width = register_width(rd);
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
            i = parse_imm_token(instr, expect(instr, i, ','), imm);
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(imm, 0, 0xFFFF)), 0xFFFF, 5);
            // LSL #0, #16, #32 or #48 (#0 or #16 for W); #0 when not written
            int64_t hw = 0;
            if (accept(instr, i, ',')) {
                if (!keyword(instr, i, "LSL")) PATTERNS_FAIL("Invalid shift or extend!");
                char amount[24] = {};
                i = parse_imm_token(instr, i, amount);
                hw = amount[0] == '?' ? -1 : imm_in(amount, 0, width == 0 ? 16 : 48, 16) / 16;
            }
            if (hw >= 0) base.set_bits(static_cast<uint32_t>(hw), 3, 21);
            return done(instr, i, base);
        }

        constexpr ArmOpcode parse_branch_imm26(const char* instr, ArmOpcode base) {
            char imm[24] = {};
            const size_t i = parse_imm_token(instr, skip_mnemonic(instr), imm);
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(imm, -(1 << 27), (1 << 27) - 4, 4) / 4), 0x3FFFFFF);
            return done(instr, i, base);
        }

        // BR/BLR/RET Xn and the PAC forms with one register (a bare RET returns through X30)
        constexpr ArmOpcode parse_branch_reg(const char* instr, ArmOpcode base) {
            if (base.pattern == 0xD65F0000 && !instr[skip_whitespace(instr, skip_mnemonic(instr))]) {
                base.set_bits(30, 0x1F, 5);
                return base;
            }
            return parse_regs<-1, 5 | r_x>(instr, base);
        }

        constexpr ArmOpcode parse_adr(const char* instr, ArmOpcode base) {
            char rd[5] = {}, imm[24] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rd, reg_zr, 0, base);
            same_width(register_width(rd), 1);
            i = parse_imm_token(instr, expect(instr, i, ','), imm);
            if (imm[0] != '?') {
                // ADR: +-1MB. ADRP: the distance to the target's 4KB page (a multiple of 0x1000), +-4GB
                const bool page = (base.pattern >> 31) & 1;
                const int64_t range = int64_t(1) << (page ? 32 : 20), unit = page ? 0x1000 : 1;
                int64_t offset = imm_in(imm, -range, range - unit, unit);
                if (page) offset >>= 12;
                base.set_bits(static_cast<uint32_t>((static_cast<uint64_t>(offset) << 24) | ((offset >> 2) & 0x7FFFF)), (3 << 24 | 0x7FFFF), 5);
            }
            return done(instr, i, base);
        }

        // A PC-relative word offset at bit 5 from a byte offset: imm19 for CBZ/CBNZ, B.cond and LDR (literal), imm14 for
        // TBZ/TBNZ. Returns past it
        template <int bits = 19>
        constexpr size_t parse_branch_imm(const char* instr, size_t i, ArmOpcode& base) {
            char imm[24] = {};
            i = parse_imm_token(instr, i, imm);
            constexpr int64_t range = int64_t(1) << (bits + 1);   // in bytes
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(imm, -range, range - 4, 4) / 4), (1u << bits) - 1, 5);
            return i;
        }

        // Single-register loads/stores. op is the unsigned offset form; the unscaled (LDUR), pre/post-index and
        // register offset forms differ from it in fixed bits. scale is log2 of the access size, or -1 to take it
        // from Rt: W or X (bit 30), or a floating-point/SIMD register B/H/S/D/Q (size, V bit 26, opc bit 23).
        // sign_extend (LDRSB/LDRSH): opc is 11 for a W Rt and 10 for X, so bit 22 comes from Rt. An offset the
        // unsigned form can't hold (negative, unaligned) is encoded unscaled, the way assemblers pick LDUR/STUR. Mask 0
        // if the offset or shift doesn't fit Rt's size, so parse_load_store can try W and X for a bare "?" Rt
        template <uint32_t op_int, int scale, bool unscaled, bool sign_extend>
        constexpr ArmOpcode encode_load_store(const char* instr) {
            ArmOpcode base{ 0, 0 };
            char rt[5] = {}, rn[5] = {}, imm[24] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rt, scale < 0 ? reg_zr | reg_fp : reg_zr, 0, base);
            const int fp = fp_size(rt), rw = register_width(rt);
            int size = scale;
            uint32_t op = op_int, width_mask = ~0u;   // width_mask: Rt's width bit, set below when known
            if (fp >= 0) {
                size = fp;
                op = (op & 0x3FFFFFFF) | static_cast<uint32_t>(fp & 3) << 30 | 1u << 26 | static_cast<uint32_t>(fp >> 2) << 23;
            } else if (scale < 0) {
                width_mask = ~(1u << 30);
                if (rw >= 0) {
                    size = 2 + rw;
                    base.set_bits(static_cast<uint32_t>(rw), 1, 30);
                }
            } else if (sign_extend) {
                width_mask = ~(1u << 22);
                if (rw >= 0) base.set_bits(rw == 0 ? 1 : 0, 1, 22);
            } else {
                same_width(rw, scale == 2 ? 1 : 0);   // LDRSW loads into X; the byte and halfword ones use W
            }

            // [Rn
            i = read_register(instr, expect(instr, expect(instr, i, ','), '['), rn, reg_sp, 5, base);
            same_width(register_width(rn), 1);

            bool is_register_offset = false, is_pre_index = false, is_post_index = false, has_offset = false;
            uint32_t option_val = 0b011, option_mask = 0b111, s_val = 0, s_mask = 1;
            if (accept(instr, i, ',')) {
                if (instr[i] == '#') {
                    i = parse_imm_token(instr, i, imm);
                    has_offset = true;
                } else {
                    // Rm, then LSL #amount, UXTW, SXTW or SXTX (amount optional), or "?" for any extend and amount
                    char rm[5] = {};
                    i = read_register(instr, i, rm, reg_zr, 16, base);
                    is_register_offset = true;
                    if (accept(instr, i, ',')) {
                        bool shift = false;
                        if      (accept(instr, i, '?'))        { option_mask = 0; s_mask = 0; }
                        else if (keyword(instr, i, "LSL"))     { option_val = 0b011; shift = true; }
                        else if (keyword(instr, i, "UXTW"))    option_val = 0b010;
                        else if (keyword(instr, i, "SXTW"))    option_val = 0b110;
                        else if (keyword(instr, i, "SXTX"))    option_val = 0b111;
                        else PATTERNS_FAIL("Invalid shift or extend!");
                        if (shift || instr[i] == '#') {
                            char amount[24] = {};
                            i = parse_imm_token(instr, i, amount);
                            s_mask = 1;
                            if (amount[0] == '?') s_mask = 0;
                            else {
                                // 0 or log2 of the access size; for bytes an explicit #0 is the shifted form
                                const int64_t a = signed_imm(amount);
                                if (a != 0 && a != size) return { 0, 0 };
                                s_val = (size == 0 || a != 0) ? 1 : 0;
                            }
                        }
                    }
                    // X for LSL and SXTX, W for UXTW and SXTW
                    if (option_mask) same_width(register_width(rm), static_cast<int>(option_val & 1));
                }
            }
            i = expect(instr, i, ']');
            if (accept(instr, i, '!')) is_pre_index = true;
            else if (accept(instr, i, ',')) {
                i = parse_imm_token(instr, i, imm);
                is_post_index = true;
            }
            if ((is_pre_index && !has_offset) || (is_post_index && (has_offset || is_register_offset)) ||
                (unscaled && (is_register_offset || is_pre_index || is_post_index)))
                PATTERNS_FAIL("Malformed operands!");

            const bool known_imm = imm[0] != '?';
            const int64_t val = known_imm && imm[0] ? signed_imm(imm) : 0;
            bool is_unsigned_offset = !unscaled && !is_register_offset && !is_pre_index && !is_post_index;
            if (is_unsigned_offset && known_imm && (val < 0 || (size > 0 && (val & ((1 << size) - 1)))))
                is_unsigned_offset = false;

            if (is_unsigned_offset) {
                base.set_bits(op, 0xFFC00000 & width_mask);
                if (known_imm && size >= 0) {
                    if ((val >> size) > 0xFFF) return { 0, 0 };
                    base.set_bits(static_cast<uint32_t>(val >> size), 0xFFF, 10);
                }
                return done(instr, i, base);
            }

            const uint32_t form = is_register_offset ? 0x00200800 : is_pre_index ? 0xC00 : is_post_index ? 0x400 : 0;
            base.set_bits((op & ~0x01000000u) | form, 0xFFE00C00 & width_mask);
            if (is_register_offset) {
                base.set_bits(option_val << 1 | s_val, option_mask << 1 | s_mask, 12);
            } else if (known_imm) {
                if (val < -256 || val > 255) return { 0, 0 };
                base.set_bits(static_cast<uint32_t>(val), 0x1FF, 12);
            }
            return done(instr, i, base);
        }

        // encode_load_store, failing on an offset or shift that doesn't fit. A bare "?" Rt is W or X
        template <uint32_t op_int, int scale, bool unscaled = false, bool sign_extend = false>
        constexpr ArmOpcode parse_load_store(const char* instr, ArmOpcode) {
            const size_t at = skip_whitespace(instr, skip_mnemonic(instr));
            char rt[5] = {};
            parse_token(instr, at, rt);
            ArmOpcode e{ 0, 0 };
            if (scale < 0 && str_eq(rt, "?")) {
                // W or X: the offset's scaling and form (LDR or LDUR) depend on which, so encode both
                char w[max_line + 8] = {}, x[max_line + 8] = {};
                for (size_t s = 0, j = 0; instr[s]; ++s, ++j) {
                    w[j] = x[j] = instr[s];
                    if (s == at) { w[j] = 'W'; x[j] = 'X'; ++j; w[j] = x[j] = '0'; }
                }
                e = either(encode_load_store<op_int, scale, unscaled, sign_extend>(w),
                           encode_load_store<op_int, scale, unscaled, sign_extend>(x));
                e.pattern &= ~0x1Fu;
                e.mask &= ~0x1Fu;
            } else {
                e = encode_load_store<op_int, scale, unscaled, sign_extend>(instr);
            }
            if (!e.mask) PATTERNS_FAIL("Immediate out of range!");
            return e;
        }

        // LDR is a load/store, or a PC-relative literal load (LDR Rt, #offset)
        constexpr ArmOpcode parse_ldr(const char* instr, ArmOpcode base) {
            char rt[5] = {};
            const size_t i = expect(instr, read_register(instr, skip_mnemonic(instr), rt, reg_zr | reg_fp, 0, base), ',');
            if (instr[i] == '[') return parse_load_store<0xB9400000, -1>(instr, base);
            // opc (bits 30-31) is 00 for W, 01 for X; with V (bit 26) 00 for S, 01 for D, 10 for Q
            if (const int fp = fp_size(rt); fp >= 2) base.set_bits(static_cast<uint32_t>(fp - 2) << 4 | 1, 0x31, 26);
            else if (fp >= 0) PATTERNS_FAIL("Invalid register!");
            else if (register_width(rt) >= 0) base.set_bits(static_cast<uint32_t>(register_width(rt)), 1, 30);
            return done(instr, parse_branch_imm(instr, i, base), base);
        }

        constexpr ArmOpcode parse_orr(const char* instr, ArmOpcode base) {
            char rd[5] = {}, rn[5] = {}, rm[5] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rd, reg_zr | reg_sp, 0, base);
            i = expect(instr, read_register(instr, expect(instr, i, ','), rn, reg_zr, 5, base), ',');
            int width = same_width(register_width(rd), register_width(rn));

            if (instr[i] == '#') {
                // BIC/BICS/ORN/EON (N set) have no immediate form: as assemblers do, AND/ANDS/ORR/EOR the inverse
                const bool invert = base.pattern >> 21 & 1;
                base.pattern &= ~(1u << 21);
                base.mask &= ~(1u << 21);   // immr's top bit here, set by the immediate
                parse_register(rd, (base.pattern >> 29 & 3) == 3 ? reg_zr : reg_sp);   // Rd 31 is SP, ZR for ANDS
                if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
                base.set_bits((2 << 4), (3 << 4 | 1), 23);

                char imm[24] = {};
                i = parse_imm_token(instr, i, imm);
                if (imm[0] != '?') {
                    const uint64_t immVal = stoi<uint64_t>(imm);
                    // sf, N, immr and imms for one width; mask 0 if the value doesn't fit it. W also takes negative
                    // values that sign-extend from 32 bits
                    auto encode = [&](bool is64) -> ArmOpcode {
                        const uint64_t ones = is64 ? ~0ULL : 0xFFFFFFFFULL;
                        uint64_t v = !is64 && immVal >= 0xFFFFFFFF80000000ULL ? immVal & ones : immVal;
                        if (invert && v <= ones) v = ~v & ones;
                        auto [ ok, N, imms, immr ] = encode_bitmask_immediate(v, is64);
                        if (!ok) return { 0, 0 };
                        ArmOpcode e{ 0, 0 };
                        e.set_bits((is64 ? 1u : 0u) << 21 | N << 12 | immr << 6 | imms, 1u << 21 | 1 << 12 | 0x3F << 6 | 0x3F, 10);
                        return e;
                    };
                    // Unknown width (Rd and Rn "?"): either, keeping the bits both encodings share
                    const ArmOpcode e = width >= 0 ? encode(width == 1) : either(encode(false), encode(true));
                    if (!e.mask) PATTERNS_FAIL("Operands can't be encoded!");
                    base.set_bits(e.pattern, e.mask);
                }
                return done(instr, i, base);
            }
            // Shifted register; N (bit 21) comes from the table: set for BIC/ORN/EON
            parse_register(rd, reg_zr);
            i = read_register(instr, i, rm, reg_zr, 16, base);
            width = same_width(width, register_width(rm));
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
            base.set_bits((1 << 6), (3 << 6), 21);
            base.set_mask(1, 21);

            if (accept(instr, i, ',')) {
                const bool any = accept(instr, i, '?');   // any shift: type and amount
                if (!any) {
                    uint32_t type = 0;
                    if      (keyword(instr, i, "LSL")) type = 0;
                    else if (keyword(instr, i, "LSR")) type = 1;
                    else if (keyword(instr, i, "ASR")) type = 2;
                    else if (keyword(instr, i, "ROR")) type = 3;
                    else PATTERNS_FAIL("Invalid shift or extend!");
                    base.set_bits(type, 3, 22);
                }
                if (!any || instr[i]) {
                    char amount[24] = {};
                    i = parse_imm_token(instr, i, amount);
                    if (amount[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(amount, 0, width == 0 ? 31 : 63)), 0x3F, 10);
                }
            } else {
                base.set_mask((3 << 12 | 0x3F), 10);
            }
            return done(instr, i, base);
        }

        constexpr ArmOpcode parse_arithmetic(const char* instr, ArmOpcode base) {
            char rd[5] = {}, rn[5] = {}, rm[5] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rd, reg_zr | reg_sp, 0, base);
            i = expect(instr, read_register(instr, expect(instr, i, ','), rn, reg_zr | reg_sp, 5, base), ',');
            int width = same_width(register_width(rd), register_width(rn));
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
            // The immediate and extended register forms read Rn 31 as SP, and Rd 31 as SP too unless setting flags;
            // the shifted register form reads both as ZR
            const unsigned rd_kind = (base.pattern >> 29 & 1) ? reg_zr : reg_sp;

            if (instr[i] == '#') {
                parse_register(rd, rd_kind);
                parse_register(rn, reg_sp);
                base.set_bits((2 << 4 | 2), (3 << 4 | 7), 23);
                char imm[24] = {};
                i = parse_imm_token(instr, i, imm);
                int sh = -1;   // LSL #12 (1) or #0 (0) when written, -1 if not or #?
                bool sh_any = false;   // LSL #?: either, so the immediate is the field as written
                if (accept(instr, i, ',')) {
                    if (!keyword(instr, i, "LSL")) PATTERNS_FAIL("Invalid shift or extend!");
                    char amount[24] = {};
                    i = parse_imm_token(instr, i, amount);
                    if (amount[0] == '?') sh_any = true;
                    else sh = imm_in(amount, 0, 12, 12) ? 1 : 0;
                }
                if (imm[0] != '?') {
                    int64_t val = imm_in(imm, -0xFFF000, 0xFFF000);
                    // As assemblers do: a negative immediate is the opposite operation (ADD #-8 is SUB #8, CMP #-1
                    // is CMN #1), and a multiple of 0x1000 the shifted form (#0x1000 is #1, LSL #12)
                    if (val < 0) { base.pattern ^= 1u << 30; val = -val; }
                    if (sh < 0 && !sh_any && val > 0xFFF && !(val & 0xFFF)) { sh = 1; val >>= 12; }
                    if (val > 0xFFF) PATTERNS_FAIL("Immediate out of range!");
                    base.set_bits(static_cast<uint32_t>(val), 0xFFF, 10);
                    if (sh < 0 && !sh_any) sh = 0;
                }
                if (sh >= 0) base.set_bits(static_cast<uint32_t>(sh), 1, 22);
                return done(instr, i, base);
            }

            // With SP as Rd or Rn only the extended register form exists: assemblers write LSL as UXTX (UXTW for W)
            const bool sp = is_sp(rd) || is_sp(rn);
            const uint32_t sp_extend = str_eq(rd, "WSP") || str_eq(rn, "WSP") ? 2 : 3;

            base.set_bits(5, 0xF, 25);
            i = read_register(instr, i, rm, reg_zr, 16, base);

            // Shifted (LSL, LSR, ASR, by an amount), extended (UXTB...SXTX, optional amount), or "?" for any
            enum { any, shifted, extended } form = sp ? extended : shifted;
            uint32_t type = sp ? sp_extend : 0;   // shift type, or extend option
            char amount[24] = {};
            if (accept(instr, i, ',')) {
                constexpr const char* extends[] = { "UXTB", "UXTH", "UXTW", "UXTX", "SXTB", "SXTH", "SXTW", "SXTX" };
                bool shift = true;
                if (accept(instr, i, '?')) { form = any; shift = false; }
                else if (keyword(instr, i, "LSL")) {}
                else if (!sp && keyword(instr, i, "LSR")) type = 1;
                else if (!sp && keyword(instr, i, "ASR")) type = 2;
                else {
                    for (type = 0; type < 8 && !keyword(instr, i, extends[type]);) ++type;
                    if (type == 8) PATTERNS_FAIL("Invalid shift or extend!");
                    form = extended;
                    shift = false;
                }
                if (shift || (form == extended && instr[i])) i = parse_imm_token(instr, i, amount);
            }

            if (form == any) {
                // Any shift or extend: they share bits 10-15 and 21-23 (the table pins bit 23, which only ASR sets)
                base.pattern &= ~(7u << 21 | 0x3Fu << 10);
                base.mask    &= ~(7u << 21 | 0x3Fu << 10);
            } else if (form == shifted) {
                parse_register(rd, reg_zr);
                parse_register(rn, reg_zr);
                width = same_width(width, register_width(rm));
                if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
                base.set_bits(type << 1, 7, 21);
                if (amount[0] != '?') base.set_bits(static_cast<uint32_t>(amount[0] ? imm_in(amount, 0, width == 0 ? 31 : 63) : 0), 0x3F, 10);
            } else {
                parse_register(rd, rd_kind);
                parse_register(rn, reg_sp);
                // Rm is X for UXTX/SXTX in an X instruction, else W
                if ((type & 3) == 3) same_width(width, register_width(rm));
                else same_width(register_width(rm), 0);
                base.set_bits(type, 7, 13);
                base.set_bits(1, 7, 21);
                if (amount[0] != '?') base.set_bits(static_cast<uint32_t>(amount[0] ? imm_in(amount, 0, 4) : 0), 7, 10);
            }
            return done(instr, i, base);
        }

        // LDP/STP and the forms sharing their layout; the table gives the load bit (22). opc (bits 30-31) is 00 for W
        // and 10 for X, or with V (bit 26) 00 for S, 01 for D, 10 for Q; LDPSW passes it (01). no_allocate: LDNP/STNP,
        // which only have the signed offset form
        template <int opc = -1, bool no_allocate = false>
        constexpr ArmOpcode parse_ldp(const char* instr, ArmOpcode base) {
            char rt1[5] = {}, rt2[5] = {}, rn[5] = {}, imm[24] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rt1, reg_zr | reg_fp, 0, base);
            i = read_register(instr, expect(instr, i, ','), rt2, reg_zr | reg_fp, 10, base);
            const int width = same_width(register_width(rt1), register_width(rt2));
            // Both general-purpose, or floating-point of one size
            const int f1 = fp_size(rt1), f2 = fp_size(rt2);
            if ((f1 >= 0 && register_width(rt2) >= 0) || (f2 >= 0 && register_width(rt1) >= 0) || (f1 >= 0 && f2 >= 0 && f1 != f2))
                PATTERNS_FAIL("Invalid register!");
            const int fp = f1 >= 0 ? f1 : f2;
            int scale = -1;   // log2 of one register's size, when known
            if (fp >= 0) {
                if (fp < 2 || opc >= 0) PATTERNS_FAIL("Invalid register!");   // S, D or Q; LDPSW loads into X
                base.set_bits(static_cast<uint32_t>(fp - 2) << 4 | 1, 0x31, 26);
                scale = fp;
            } else if (opc >= 0) {
                same_width(width, 1);
                base.set_bits(static_cast<uint32_t>(opc), 3, 30);
                scale = 2;
            } else if (width >= 0) {
                base.set_bits(static_cast<uint32_t>(width), 1, 31);
                scale = 2 + width;
            }

            // [Rn{, #imm}]{!} or [Rn], #imm. [Rn] alone is the signed offset form with offset 0
            i = read_register(instr, expect(instr, expect(instr, i, ','), '['), rn, reg_sp, 5, base);
            same_width(register_width(rn), 1);
            const bool offset = accept(instr, i, ',');
            if (offset) i = parse_imm_token(instr, i, imm);
            i = expect(instr, i, ']');
            bool post_index = false, pre_index = false;
            if (offset && accept(instr, i, '!')) {
                pre_index = true;
            } else if (!offset && accept(instr, i, ',')) {
                post_index = true;
                i = parse_imm_token(instr, i, imm);
            }
            if (no_allocate && (pre_index || post_index)) PATTERNS_FAIL("Malformed operands!");
            // Bits 23-25: post-index 001, signed offset 010, pre-index 011, no-allocate offset 000
            base.set_bits(post_index ? 1 : pre_index ? 3 : no_allocate ? 0 : 2, 7, 23);
            if (imm[0] != '?') {
                // imm7, scaled by the register size. With the size unknown ("?" registers) the field stays open, but
                // the offset must fit one of W and X
                const int64_t v = imm[0] ? signed_imm(imm) : 0;
                auto fits = [&](int s) { return v % (1 << s) == 0 && v / (1 << s) >= -64 && v / (1 << s) <= 63; };
                if (scale >= 0 ? !fits(scale) : !fits(2) && !fits(3)) PATTERNS_FAIL("Immediate out of range!");
                if (scale >= 0) base.set_bits(static_cast<uint32_t>(v / (1 << scale)), 0x7F, 15);
            }
            return done(instr, i, base);
        }

        // MOV is an alias; encoded the way assemblers pick: ADD #0 when SP is involved, ORR from the zero register for
        // registers, and MOVZ, then MOVN, then ORR (bitmask) for immediates. MOV Rd, #? matches MOVZ or MOVN
        constexpr ArmOpcode parse_mov(const char* instr, ArmOpcode) {
            char rd[5] = {}, rm[5] = {};
            ArmOpcode op{ 0, 0 };
            size_t i = expect(instr, read_register(instr, skip_mnemonic(instr), rd, reg_zr | reg_sp, 0, op), ',');
            const bool rd_sp = is_sp(rd), rd_zr = str_eq(rd, "XZR") || str_eq(rd, "WZR");
            const bool known_width = register_width(rd) >= 0;
            const bool is64 = register_width(rd) == 1;
            if (known_width) op.set_bits(is64 ? 1 : 0, 1, 31);

            if (instr[i] == '#') {
                char imm[24] = {};
                i = parse_imm_token(instr, i, imm);
                if (imm[0] == '?') {
                    parse_register(rd, reg_zr);   // MOVZ and MOVN can't write SP
                    op.set_bits(0x12800000, 0x3F800000);   // MOVZ or MOVN: bit 30 of opc left open, bit 29 clear (not MOVK)
                    return done(instr, i, op);
                }
                const uint64_t raw = stoi<uint64_t>(imm);   // unsigned: 64-bit hex fits, and negatives wrap
                // The encoding for one width, sf included; mask 0 if the value doesn't fit it. MOVZ and MOVN read Rd
                // 31 as ZR, ORR as SP
                auto encode = [&](bool wide) -> ArmOpcode {
                    const unsigned width = wide ? 64 : 32;
                    const uint64_t ones = wide ? ~0ULL : 0xFFFFFFFFULL;
                    // W takes 32-bit values, or negative ones that sign-extend from 32 bits
                    if (!wide && raw > ones && raw < 0xFFFFFFFF80000000ULL) return { 0, 0 };
                    const uint64_t v = raw & ones;
                    const uint32_t sf = wide ? 1u << 31 : 0;
                    ArmOpcode e{ 0, 0 };
                    for (uint32_t hw = 0; hw < width / 16 && !rd_sp; ++hw) {
                        if ((v & ~(0xFFFFULL << (hw * 16))) == 0) {
                            e.set_bits(sf | 0x52800000 | hw << 21 | static_cast<uint32_t>(v >> (hw * 16)) << 5, 0xFFFFFFE0);
                            return e;
                        }
                    }
                    for (uint32_t hw = 0; hw < width / 16 && !rd_sp; ++hw) {
                        if ((~v & ones & ~(0xFFFFULL << (hw * 16))) == 0) {
                            e.set_bits(sf | 0x12800000 | hw << 21 | static_cast<uint32_t>((~v & ones) >> (hw * 16)) << 5, 0xFFFFFFE0);
                            return e;
                        }
                    }
                    auto [ ok, N, imms, immr ] = encode_bitmask_immediate(v, wide);
                    if (!ok || rd_zr) return { 0, 0 };
                    e.set_bits(sf | 0x320003E0 | N << 22 | immr << 16 | imms << 10, 0xFFFFFFE0);
                    return e;
                };
                // A bare "?" Rd: W or X, keeping the bits both encodings share
                const ArmOpcode e = known_width ? encode(is64) : either(encode(false), encode(true));
                if (!e.mask) PATTERNS_FAIL("Operands can't be encoded!");
                op.set_bits(e.pattern, e.mask);
                return done(instr, i, op);
            }

            i = parse_token(instr, i, rm);
            const auto rm_val = parse_register(rm, reg_zr | reg_sp);
            same_width(register_width(rd), register_width(rm));
            if (rd_sp || is_sp(rm)) {
                // ADD Rd, Rn, #0: 31 is SP in both
                parse_register(rd, reg_sp);
                parse_register(rm, reg_sp);
                op.set_bits(0x11000000, 0x7FFFFC00);
                if (rm_val != 0xFFFFFFFF) op.set_bits(rm_val, 0x1F, 5);
            } else {
                op.set_bits(0x2A0003E0, 0x7FE0FFE0);   // ORR Rd, ZR, Rm
                if (rm_val != 0xFFFFFFFF) op.set_bits(rm_val, 0x1F, 16);
            }
            return done(instr, i, op);
        }

        constexpr ArmOpcode parse_cbz(const char* instr, ArmOpcode base) {
            char rt[5] = {};
            const size_t i = read_register(instr, skip_mnemonic(instr), rt, reg_zr, 0, base);
            if (register_width(rt) >= 0) base.set_bits(static_cast<uint32_t>(register_width(rt)), 1, 31);
            return done(instr, parse_branch_imm(instr, expect(instr, i, ','), base), base);
        }

        // Aliases that write the zero register (of the first operand's width) as operand pos, parsed as the full form:
        // CMP/CMN/TST Rn, ... are SUBS/ADDS/ANDS ZR, Rn, ... (pos 0); MVN/NEG(S)/NGC(S) Rd, ... are
        // ORN/SUB(S)/SBC(S) Rd, ZR, ... (pos 1)
        template <ParseFunc parse, int pos = 0>
        constexpr ArmOpcode parse_zr(const char* instr, ArmOpcode base) {
            size_t i = skip_whitespace(instr, skip_mnemonic(instr));
            char first[5] = {};
            parse_token(instr, i, first);
            const int width = register_width(first);
            const char* zr = width == 0 ? "WZR, " : width == 1 ? "XZR, " : "?, ";
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
            if (c == 17) PATTERNS_FAIL("Invalid condition!");
            if (c < 16) base.set_bits(c, 0xF);
            return done(instr, parse_branch_imm(instr, skip_mnemonic(instr), base), base);
        }

        // TBZ/TBNZ Rt, #bit, #offset: b5 (bit 31) is the bit number's top bit, b40 (bits 19-23) the rest. A W register
        // (or a bit number below 32) means b5 is 0
        constexpr ArmOpcode parse_tbz(const char* instr, ArmOpcode base) {
            char rt[5] = {}, bit[24] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rt, reg_zr, 0, base);
            i = parse_imm_token(instr, expect(instr, i, ','), bit);
            const int width = register_width(rt);
            if (bit[0] == '?') {
                if (width == 0) base.set_bits(0, 1, 31);
            } else {
                const uint32_t b = static_cast<uint32_t>(imm_in(bit, 0, width == 0 ? 31 : 63));
                base.set_bits(b, 0x1F, 19);
                base.set_bits(b >> 5, 1, 31);
            }
            return done(instr, parse_branch_imm<14>(instr, expect(instr, i, ','), base), base);
        }

        // SVC/HVC/SMC/BRK/HLT #imm16 (bit 5), UDF #imm16 (bit 0)
        template <int shift>
        constexpr ArmOpcode parse_imm16(const char* instr, ArmOpcode base) {
            char imm[24] = {};
            const size_t i = parse_imm_token(instr, skip_mnemonic(instr), imm);
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(imm, 0, 0xFFFF)), 0xFFFF, shift);
            return done(instr, i, base);
        }

        // BTI {C|J|JC}: the targets at bits 6-7, BTI ? for any
        constexpr ArmOpcode parse_bti(const char* instr, ArmOpcode base) {
            const char* t = &instr[skip_whitespace(instr, skip_mnemonic(instr))];
            const uint32_t targets = !*t ? 0 : str_eq(t, "C") ? 1 : str_eq(t, "J") ? 2 : str_eq(t, "JC") ? 3 : 4;
            if (str_eq(t, "?")) base.mask &= ~(3u << 6);
            else if (targets == 4) PATTERNS_FAIL("Invalid operand!");
            else base.set_bits(targets, 3, 6);
            return base;
        }

        // LDRAA/LDRAB Xt, [Xn{,#imm}]{!}: imm10 scaled by 8 (sign at bit 22, the rest at 12-20), writeback at bit 11
        constexpr ArmOpcode parse_ldraa(const char* instr, ArmOpcode base) {
            char rt[5] = {}, rn[5] = {}, imm[24] = {};
            size_t i = read_register(instr, skip_mnemonic(instr), rt, reg_zr, 0, base);
            same_width(register_width(rt), 1);
            i = read_register(instr, expect(instr, expect(instr, i, ','), '['), rn, reg_sp, 5, base);
            same_width(register_width(rn), 1);
            if (accept(instr, i, ',')) i = parse_imm_token(instr, i, imm);
            i = expect(instr, i, ']');
            base.set_bits(accept(instr, i, '!') ? 1 : 0, 1, 11);
            if (imm[0] != '?') {
                const uint32_t enc = static_cast<uint32_t>((imm[0] ? imm_in(imm, -4096, 4088, 8) : 0) / 8) & 0x3FF;
                base.set_bits(enc, 0x1FF, 12);
                base.set_bits(enc >> 9, 1, 22);
            }
            return done(instr, i, base);
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
            char rd[5] = {}, rn[5] = {}, imm[24] = {};
            constexpr uint32_t ftype[] = { 4, 3, 0, 1, 4 };   // by fp_size: H 11, S 00, D 01 (B and Q: none)
            ArmOpcode op{ 0, 0 };
            size_t i = expect(instr, read_register(instr, skip_mnemonic(instr), rd, reg_zr | reg_fp, 0, op), ',');
            const int fd = fp_size(rd);

            if (instr[i] == '#') {
                i = parse_imm_token<false>(instr, i, imm);
                if (fd < 0 || ftype[fd] > 3) PATTERNS_FAIL("Invalid register!");
                bool negative = false;
                uint64_t num = 0, den = 1;
                if (imm[0] != '?' && !parse_decimal(imm, negative, num, den)) PATTERNS_FAIL("Invalid immediate!");
                if (imm[0] != '?' && num == 0) {
                    if (negative) PATTERNS_FAIL("Operands can't be encoded!");
                    rn[0] = fd == 3 ? 'X' : 'W'; rn[1] = 'Z'; rn[2] = 'R';   // FMOV Rd, ZR
                } else {
                    op.set_bits(0x1E201000 | ftype[fd] << 22, 0xFFE01FE0);
                    if (imm[0] == '?') return done(instr, i, op);
                    for (uint32_t imm8 = 0; imm8 < 256; ++imm8) {
                        // (16 + n) / 16 * 2^e == num / den
                        const int e = (imm8 >> 6 & 1) ? static_cast<int>(imm8 >> 4 & 3) - 3 : static_cast<int>(imm8 >> 4 & 3) + 1;
                        const uint64_t m = 16 + (imm8 & 15);
                        const bool eq = e >= 0 ? m * den << e == num * 16 : m * den == num * 16 << -e;
                        if (eq && (imm8 >> 7) == (negative ? 1u : 0u)) {
                            op.set_bits(imm8, 0xFF, 13);
                            return done(instr, i, op);
                        }
                    }
                    PATTERNS_FAIL("Operands can't be encoded!");
                }
            } else {
                i = parse_token(instr, i, rn);
            }
            if (auto r = parse_register(rn, reg_zr | reg_fp); r != 0xFFFFFFFF) op.set_bits(r, 0x1F, 5);
            const int fn = fp_size(rn);
            const int gd = register_width(rd), gn = register_width(rn);
            const bool qd = str_eq(rd, "?"), qn = str_eq(rn, "?");
            if ((fd >= 0 || qd) && (fn >= 0 || qn)) {
                // Between floating-point registers
                const int f = fd >= 0 ? fd : fn;
                if (f >= 0 && (ftype[f] > 3 || (fd >= 0 && fn >= 0 && fd != fn))) PATTERNS_FAIL("Invalid register!");
                op.set_bits(0x1E204000, 0xFF3FFC00);
                if (f >= 0) op.set_bits(ftype[f], 3, 22);
                return done(instr, i, op);
            }
            // General-purpose <-> floating-point: sf, type, then rmode 00 and opcode 110 (to general) or 111 (from it)
            const bool to_fp = fd >= 0;
            const int f = to_fp ? fd : fn, g = to_fp ? gn : gd;
            if (f < 0 || g < 0 || ftype[f] > 3 || (f == 2 && g != 0) || (f == 3 && g != 1)) PATTERNS_FAIL("Invalid register!");
            op.set_bits(0x1E260000 | static_cast<uint32_t>(g) << 31 | ftype[f] << 22 | (to_fp ? 1u : 0u) << 16, 0xFFFFFC00);
            return done(instr, i, op);
        }

        // CSEL/CSINC/CSINV/CSNEG Rd, Rn, Rm, cond. regs is how many registers are written: 1 for CSET/CSETM (Rn = Rm =
        // ZR), 2 for CINC/CINV/CNEG (Rm = Rn). The aliases store the inverted condition, and can't take AL or NV
        template <size_t regs>
        constexpr ArmOpcode parse_csel(const char* instr, ArmOpcode base) {
            constexpr int all[] = { 0, 5, 16 };
            int specs[regs] = {};
            for (size_t k = 0; k < regs; ++k) specs[k] = all[k];
            int width = -1;
            size_t i = parse_reg_list(instr, skip_mnemonic(instr), specs, base, width);
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
            if (regs == 1) base.set_bits(31 << 11 | 31, 0x1F << 11 | 0x1F, 5);
            if (regs == 2 && (base.mask >> 5 & 0x1F)) base.set_bits(base.pattern >> 5, 0x1F, 16);
            char cond[4] = {};
            i = parse_token(instr, expect(instr, i, ','), cond);
            const uint32_t c = parse_cond(cond);
            if (c == 17 || (regs < 3 && c >= 14 && c < 16)) PATTERNS_FAIL("Invalid condition!");
            if (c < 16) base.set_bits(regs < 3 ? c ^ 1 : c, 0xF, 12);
            return done(instr, i, base);
        }

        // CCMP/CCMN Rn, Rm|#imm5, #nzcv, cond: the immediate form sets bit 11
        constexpr ArmOpcode parse_ccmp(const char* instr, ArmOpcode base) {
            char rn[5] = {}, rm[5] = {}, imm[24] = {}, cond[4] = {};
            size_t i = expect(instr, read_register(instr, skip_mnemonic(instr), rn, reg_zr, 5, base), ',');
            int width = register_width(rn);
            if (instr[i] == '#') {
                i = parse_imm_token(instr, i, imm);
                base.set_bits(1, 1, 11);
                if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(imm, 0, 31)), 0x1F, 16);
            } else {
                i = read_register(instr, i, rm, reg_zr, 16, base);
                width = same_width(width, register_width(rm));
                base.set_bits(0, 1, 11);
            }
            if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 31);
            i = parse_imm_token(instr, expect(instr, i, ','), imm);
            if (imm[0] != '?') base.set_bits(static_cast<uint32_t>(imm_in(imm, 0, 15)), 0xF);
            i = parse_token(instr, expect(instr, i, ','), cond);
            const uint32_t c = parse_cond(cond);
            if (c == 17) PATTERNS_FAIL("Invalid condition!");
            if (c < 16) base.set_bits(c, 0xF, 12);
            return done(instr, i, base);
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
            int specs[nregs] = {};
            for (size_t k = 0; k < nregs; ++k) specs[k] = all[k];
            if (kind == bf_extend) specs[1] |= r_w;   // SXT*/UXT* sources are always W, so only Rd gives the width
            int width = -1;
            size_t i = parse_reg_list(instr, skip_mnemonic(instr), specs, base, width);
            if (kind == bf_ror && (base.mask >> 5 & 0x1F)) base.set_bits(base.pattern >> 5, 0x1F, 16);

            // No immediates for the extends, two for the raw, extract and insert forms, else one
            constexpr int nimm = kind == bf_extend ? 0 : kind == bf_raw || kind == bf_extract || kind == bf_insert ? 2 : 1;
            char a_text[24] = {}, b_text[24] = {};
            if (nimm >= 1) i = parse_imm_token(instr, expect(instr, i, ','), a_text);
            if (nimm >= 2) i = parse_imm_token(instr, expect(instr, i, ','), b_text);
            const bool ak = a_text[0] != '?', bk = b_text[0] != '?';
            const int64_t a = ak && a_text[0] ? signed_imm(a_text) : 0, b = bk && b_text[0] ? signed_imm(b_text) : 1;
            const bool ubfm = (base.pattern >> 29 & 3) == 2 && kind != bf_ror && kind != bf_extr;

            // Only known values are checked; a field depending on a "?" is left open
            auto encode = [&](int64_t size) -> ArmOpcode {
                if (kind == bf_extend ? (ubfm && size == 64) || (size == 32 && extend_imms == 31) : ak && (a < 0 || a >= size))
                    return { 0, 0 };
                if ((kind == bf_raw && bk && (b < 0 || b >= size)) ||
                    ((kind == bf_extract || kind == bf_insert) && bk && (b < 1 || b > size - (ak ? a : 0))))
                    return { 0, 0 };
                int64_t immr = 0, imms = 0;
                bool immr_known = true, imms_known = true;
                switch (kind) {
                    case bf_raw:     immr = a; imms = b; immr_known = ak; imms_known = bk; break;
                    case bf_lsl:     immr = (size - a) & (size - 1); imms = size - 1 - a; immr_known = imms_known = ak; break;
                    case bf_lsr:     immr = a; imms = size - 1; immr_known = ak; break;
                    case bf_extract: immr = a; imms = a + b - 1; immr_known = ak; imms_known = ak && bk; break;
                    case bf_insert:  immr = (size - a) & (size - 1); imms = b - 1; immr_known = ak; imms_known = bk; break;
                    case bf_extend:  imms = static_cast<int64_t>(extend_imms); break;
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
            if (!e.mask) PATTERNS_FAIL("Operands can't be encoded!");
            base.set_bits(e.pattern, e.mask);
            return done(instr, i, base);
        }

        // LSL/LSR/ASR/ROR: by an immediate a bitfield (EXTR for ROR) alias, by a register LSLV/LSRV/ASRV/RORV (op2 at
        // bits 10-11)
        template <BitfieldKind kind, uint32_t op2>
        constexpr ArmOpcode parse_shift(const char* instr, ArmOpcode base) {
            const size_t i = skip_whitespace(instr, skip_past(instr, skip_past(instr, 0, ','), ','));
            if (instr[i] == '#') return parse_bitfield<kind>(instr, base);
            return parse_regs<31, 0, 5, 16>(instr, { 0x1AC02000 | op2 << 10, 0x7FE0FC00 });
        }

        // LSE atomics and CAS, from the mnemonic: LD<op>{A}{L}{B|H} Rs, Rt, [Rn]; ST<op>{L}{B|H} Rs, [Rn] (LD<op> into
        // ZR); SWP{A}{L}{B|H} and CAS{A}{L}{B|H} Rs, Rt, [Rn]. op is ADD, CLR, EOR, SET, SMAX, SMIN, UMAX or UMIN.
        // size (bits 30-31) from the B/H suffix (W registers), else W or X from Rs/Rt. Mask 0 for an unknown mnemonic
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

            constexpr int load_specs[] = { 16, 0, 5 | r_base }, store_specs[] = { 16, 5 | r_base };
            int width = -1;
            size_t i = 0;
            if (store) {
                i = parse_reg_list(instr, skip_mnemonic(instr), store_specs, base, width);
                base.set_bits(31, 0x1F);
            } else {
                i = parse_reg_list(instr, skip_mnemonic(instr), load_specs, base, width);
            }
            if (size >= 0) same_width(width, 0);
            else if (width >= 0) base.set_bits(static_cast<uint32_t>(width), 1, 30);
            return done(instr, i, base);
        }

        struct ParseDescriptor {
            const char* mnemonic;
            ParseFunc func;
        };

        // The tables are inline: a namespace-scope constant is emitted unreferenced at GCC -O0 (-fkeep-static-consts),
        // which would put every parser and mnemonic in binaries that only use compile-time patterns
        inline constexpr ParseDescriptor parseTable[] = {
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
            { "BRAA",  parse_regs<-1, 5 | r_x, 0 | r_x | r_sp> },
            { "BRAB",  parse_regs<-1, 5 | r_x, 0 | r_x | r_sp> },
            { "BLRAA", parse_regs<-1, 5 | r_x, 0 | r_x | r_sp> },
            { "BLRAB", parse_regs<-1, 5 | r_x, 0 | r_x | r_sp> },
            { "BRAAZ",  parse_branch_reg },
            { "BRABZ",  parse_branch_reg },
            { "BLRAAZ", parse_branch_reg },
            { "BLRABZ", parse_branch_reg },
            { "LDRAA", parse_ldraa },
            { "LDRAB", parse_ldraa },
            { "PACIA", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "PACIB", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "PACDA", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "PACDB", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "AUTIA", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "AUTIB", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "AUTDA", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "AUTDB", parse_regs<-1, 0 | r_x, 5 | r_x | r_sp> },
            { "PACIZA", parse_regs<-1, 0 | r_x> },
            { "PACIZB", parse_regs<-1, 0 | r_x> },
            { "PACDZA", parse_regs<-1, 0 | r_x> },
            { "PACDZB", parse_regs<-1, 0 | r_x> },
            { "AUTIZA", parse_regs<-1, 0 | r_x> },
            { "AUTIZB", parse_regs<-1, 0 | r_x> },
            { "AUTDZA", parse_regs<-1, 0 | r_x> },
            { "AUTDZB", parse_regs<-1, 0 | r_x> },
            { "XPACI", parse_regs<-1, 0 | r_x> },
            { "XPACD", parse_regs<-1, 0 | r_x> },
            { "PACGA", parse_regs<-1, 0 | r_x, 5 | r_x, 16 | r_x | r_sp> },
            { "LDRSB",  parse_load_store<0x39800000, 0, false, true> },
            { "LDRSH",  parse_load_store<0x79800000, 1, false, true> },
            { "LDURSB", parse_load_store<0x39800000, 0, true, true> },
            { "LDURSH", parse_load_store<0x79800000, 1, true, true> },
            { "LDXR",   parse_regs<30, 0, 5 | r_base> },
            { "LDAXR",  parse_regs<30, 0, 5 | r_base> },
            { "LDAR",   parse_regs<30, 0, 5 | r_base> },
            { "LDAPR",  parse_regs<30, 0, 5 | r_base> },
            { "STLR",   parse_regs<30, 0, 5 | r_base> },
            { "STXR",   parse_regs<30, 16 | r_w, 0, 5 | r_base> },
            { "STLXR",  parse_regs<30, 16 | r_w, 0, 5 | r_base> },
            { "LDXRB",  parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDXRH",  parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDAXRB", parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDAXRH", parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDARB",  parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDARH",  parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDAPRB", parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "LDAPRH", parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "STLRB",  parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "STLRH",  parse_regs<-1, 0 | r_w, 5 | r_base> },
            { "STXRB",  parse_regs<-1, 16 | r_w, 0 | r_w, 5 | r_base> },
            { "STXRH",  parse_regs<-1, 16 | r_w, 0 | r_w, 5 | r_base> },
            { "STLXRB", parse_regs<-1, 16 | r_w, 0 | r_w, 5 | r_base> },
            { "STLXRH", parse_regs<-1, 16 | r_w, 0 | r_w, 5 | r_base> },
            { "LDXP",   parse_regs<30, 0, 10, 5 | r_base> },
            { "LDAXP",  parse_regs<30, 0, 10, 5 | r_base> },
            { "STXP",   parse_regs<30, 16 | r_w, 0, 10, 5 | r_base> },
            { "STLXP",  parse_regs<30, 16 | r_w, 0, 10, 5 | r_base> },
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
            { "MADD",  parse_regs<31, 0, 5, 16, 10> },
            { "MSUB",  parse_regs<31, 0, 5, 16, 10> },
            { "MUL",   parse_regs<31, 0, 5, 16> },
            { "MNEG",  parse_regs<31, 0, 5, 16> },
            { "SMADDL", parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w, 10 | r_x> },
            { "SMSUBL", parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w, 10 | r_x> },
            { "UMADDL", parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w, 10 | r_x> },
            { "UMSUBL", parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w, 10 | r_x> },
            { "SMULL",  parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w> },
            { "SMNEGL", parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w> },
            { "UMULL",  parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w> },
            { "UMNEGL", parse_regs<-1, 0 | r_x, 5 | r_w, 16 | r_w> },
            { "SMULH",  parse_regs<-1, 0 | r_x, 5 | r_x, 16 | r_x> },
            { "UMULH",  parse_regs<-1, 0 | r_x, 5 | r_x, 16 | r_x> },
            { "UDIV",  parse_regs<31, 0, 5, 16> },
            { "SDIV",  parse_regs<31, 0, 5, 16> },
            { "LSLV",  parse_regs<31, 0, 5, 16> },
            { "LSRV",  parse_regs<31, 0, 5, 16> },
            { "ASRV",  parse_regs<31, 0, 5, 16> },
            { "RORV",  parse_regs<31, 0, 5, 16> },
            { "ADC",   parse_regs<31, 0, 5, 16> },
            { "ADCS",  parse_regs<31, 0, 5, 16> },
            { "SBC",   parse_regs<31, 0, 5, 16> },
            { "SBCS",  parse_regs<31, 0, 5, 16> },
            { "NGC",   parse_zr<parse_regs<31, 0, 5, 16>, 1> },
            { "NGCS",  parse_zr<parse_regs<31, 0, 5, 16>, 1> },
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

        inline constexpr InstructionDescriptor instructions[] = {
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

            // Instructions without operands, else an atomic or an unknown mnemonic
            return base.mask ? done(instr, i, base) : parse_atomic(mnemonic, instr);
        }
        
        // Copies the line at str[i] into out, trimmed and uppercased (lldb/objdump print lowercase), so each
        // instruction is parsed on its own and can't run into the next line. A comment (';', as IDA and lldb print
        // them) is left out. Returns where the next line starts
        template <size_t N>
        constexpr size_t read_line(const char* str, size_t i, char (&out)[N]) {
            while (str[i] == ' ' || str[i] == '\t') ++i;
            size_t j = 0;
            bool comment = false;
            for (; str[i] && str[i] != '\n'; ++i) {
                comment = comment || str[i] == ';';
                if (comment) continue;
                if (j + 1 >= N) PATTERNS_FAIL("Instruction line is too long!");
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
            size_t count = 0;
            for (size_t i = 0; i < n && p[i];) {
                char text[max_line] = {};
                const size_t line_start = i;
                i = read_line(p, i, text);
                // Flags start the last line; a '/' anywhere else (a ; comment) isn't one
                if (text[0] == '/') { flags(&p[skip_past(p, line_start, '/')]); break; }
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