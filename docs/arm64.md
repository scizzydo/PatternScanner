# arm64 assembly patterns

`ArmPattern`, `ArmXORPattern` and `RuntimeArmPattern` build the pattern & mask from arm64 assembly, with wildcard support. The class is constexpr, so the assembly is not in the final product (if the pattern is declared constexpr).

## Writing patterns

One instruction per line; case, indentation and spacing don't matter, so lines pasted from IDA (`LDR W8, [X8,#0x18]`) or lldb (`ldr    w8, [x8, #0x18]`) both work. lldb prints ADRP operands as page counts and branch targets as absolute addresses, so wildcard those (`#?`).

## Wildcards

`?` works for any operand: a register (`?`, or `X?`/`W?`/`D?`/`Q?`... to keep its kind), an immediate (`#?`), a shift or extend (`LSL #?`, `?`), a condition (`B.?`, `CSEL X0, X1, X2, ?`), BTI targets (`BTI ?`) or a whole instruction line.

- A `?` leaves open exactly the bits that operand decides. A field computed from a `?` and a known operand is left open too (`UBFX X0, X1, #?, #8`: imms is lsb + 7).
- A register letter pins the width; a bare `?` leaves it open, along with what depends on it (scaled offsets, bitfield immr/imms, TBZ's bit 5). Where only one width fits the other operands (`LSL ?, ?, #40`), that one is used.
- In loads and stores a bare `?` register is W or X; write `B?`/`H?`/`S?`/`D?`/`Q?` for floating-point/SIMD ones.
- Some wildcards can't be expressed with a mask and match more than the alias: `LSL Rd, Rn, #?` matches any `UBFM` (also `LSR`, `UBFX`...), and aliases that repeat a register (`CINC X?, X?, cond`, `ROR X?, X?, #n`) can't require the two to be the same.
- An operand that can't be encoded (out of range, the wrong register kind, an unknown condition) makes the line a wildcard for those 4 bytes, matching any instruction (the IDA plugin asks before searching with one). It never makes a pattern that can't match. Write `?` for a deliberate one.

## Supported instructions

- Branches: `B`, `BL`, `B.cond`, `BR`, `BLR`, `RET`, `CBZ`, `CBNZ`, `TBZ`, `TBNZ`
- Exceptions and hints: `SVC`, `HVC`, `SMC`, `BRK`, `HLT`, `UDF`, `NOP`, `BTI`
- Pointer authentication: `PACIASP`/`PACIBSP`/`AUTIASP`/`AUTIBSP` (and the `Z`/`1716` forms), `RETAA`, `RETAB`, `BRAA`/`BRAB`/`BLRAA`/`BLRAB` (and `Z` forms), `LDRAA`, `LDRAB`, `PACIA`/`PACIB`/`PACDA`/`PACDB`/`AUTIA`/`AUTIB`/`AUTDA`/`AUTDB` (and `Z` forms), `XPACI`, `XPACD`, `XPACLRI`, `PACGA`
- Addresses and moves: `ADR`, `ADRP`, `MOV`, `MOVZ`, `MOVN`, `MOVK`, `MVN`
- Arithmetic: `ADD(S)`, `SUB(S)`, `CMP`, `CMN`, `NEG(S)`, `ADC(S)`, `SBC(S)`, `NGC(S)`, `MADD`, `MSUB`, `MUL`, `MNEG`, `SMADDL`, `SMSUBL`, `UMADDL`, `UMSUBL`, `SMULL`, `UMULL`, `SMNEGL`, `UMNEGL`, `SMULH`, `UMULH`, `SDIV`, `UDIV`
- Logical: `AND(S)`, `ORR`, `EOR`, `TST`, `BIC(S)`, `ORN`, `EON`
- Shifts and bitfields: `LSL`, `LSR`, `ASR`, `ROR` (immediate or register), `LSLV`, `LSRV`, `ASRV`, `RORV`, `UBFM`, `SBFM`, `BFM`, `UBFX`, `SBFX`, `BFXIL`, `UBFIZ`, `SBFIZ`, `BFI`, `EXTR`, `SXTB`, `SXTH`, `SXTW`, `UXTB`, `UXTH`
- Conditionals: `CSEL`, `CSINC`, `CSINV`, `CSNEG`, `CSET`, `CSETM`, `CINC`, `CINV`, `CNEG`, `CCMP`, `CCMN`
- Loads and stores: `LDR`, `STR`, `LDUR`, `STUR` (W/X and B/H/S/D/Q registers), `LDRB`, `LDRH`, `LDRSB`, `LDRSH`, `LDRSW`, `STRB`, `STRH` and their `LDUR`/`STUR` forms, `LDP`, `STP` (W/X and S/D/Q), `LDPSW`, `LDNP`, `STNP`
- Exclusive and acquire/release: `LDXR`, `STXR`, `LDAXR`, `STLXR`, `LDAR`, `STLR`, `LDAPR` (and their `B`/`H` forms), `LDXP`, `STXP`, `LDAXP`, `STLXP`
- Atomics: `CAS`, `SWP`, `LD<op>`, `ST<op>` with `<op>` `ADD`, `CLR`, `EOR`, `SET`, `SMAX`, `SMIN`, `UMAX`, `UMIN`, each with the `A`/`L`/`AL` and `B`/`H` suffixes
- Floating point: `FMOV` (register, to/from W/X, and immediates like `#1.0`)

Any other instruction becomes a wildcard for those 4 bytes.

## Aliases

Encoded the way assemblers pick them:
- `MOV`: register, SP, or immediate via `MOVZ`/`MOVN`/`ORR`; `MOV Rd, #?` matches `MOVZ` or `MOVN`.
- `CMP`/`CMN`/`TST`: `SUBS`/`ADDS`/`ANDS` to the zero register; `MVN`/`NEG(S)`/`NGC(S)`: `ORN`/`SUB(S)`/`SBC(S)` from it.
- `LDR`/`STR` offsets the scaled form can't hold (negative, unaligned): `LDUR`/`STUR`.
- `ADD`/`SUB`/`CMP` immediates that are negative or multiples of 0x1000: the opposite operation or `LSL #12`.
- Register `ADD`/`SUB` with `SP`: the extended (`UXTX`) form.
- `CSET`/`CSETM`/`CINC`/`CINV`/`CNEG`: `CSINC`/`CSINV`/`CSNEG` with the inverted condition.
- `LSL`/`LSR`/`ASR` by an immediate, `UBFX`/`UBFIZ`/`BFI`/`SXTB`...: `UBFM`/`SBFM`/`BFM`; `ROR` by an immediate: `EXTR`.
- `MUL`/`MNEG`/`SMULL`...: the multiply-add forms with the zero register; `ST<op>`: `LD<op>` into the zero register.
- `FMOV Rd, #0.0`: `FMOV` from the zero register.

## `/d` resolution

At the `X` instruction:
- `B`/`BL`, `B.cond`, `CBZ`/`CBNZ`, `TBZ`/`TBNZ`, `LDR` (literal) and `ADR` give their target.
- `ADRP` gives the page plus the `ADD`/`SUB` and load/store offset (including floating-point loads like `LDR D0`) that follow it through the same register (skipping NOPs and instructions that leave the register alone).
- `MOVZ`/`MOVN`, `ADD`/`SUB` immediates and load/store offsets give the value.

`/r` is not used on arm64.
