# arm64 assembly patterns

`ArmPattern`, `ArmXORPattern` and `RuntimeArmPattern` build the pattern & mask from arm64 assembly, with wildcard support. The class is constexpr, so the assembly is not in the final product (if the pattern is declared constexpr).

## Writing patterns

One instruction per line; case, indentation and spacing don't matter, so lines pasted from IDA (`LDR W8, [X8,#0x18]`) or lldb (`ldr    w8, [x8, #0x18]`) both work. lldb prints ADRP operands as page counts and branch targets as absolute addresses, so wildcard those (`#?`).

Wildcards: `?` for a register (`X?`), immediate (`#?`), shift (`LSL #?`), condition (`B.?`) or a whole instruction line.

## Supported instructions

`B`, `BL`, `B.cond` (`B.?` for any condition), `BR`, `BLR`, `RET`, `RETAA`, `RETAB`, `CBZ`, `CBNZ`, `ADR`, `ADRP`, `ADD(S)`, `SUB(S)`, `CMP`, `CMN`, `AND(S)`, `ORR`, `EOR`, `TST`, `LDR`, `LDRB`, `LDRH`, `LDRSW`, `STR`, `STRB`, `STRH`, `LDUR`/`STUR` (and their `B`/`H`/`SW` forms), `LDP`, `STP`, `MOV`, `MOVZ`, `MOVN`, `MOVK`, `NOP`, `PACIASP`, `PACIBSP`, `AUTIASP`, `AUTIBSP`.

- Loads and stores take W/X registers only; floating-point/SIMD ones (`LDR Q0, ...`, `STP D9, D8, ...`) are wildcards.
- Any other instruction becomes a wildcard for those 4 bytes, matching any instruction (the IDA plugin asks before searching with one); write `?` for a deliberate one.

## Aliases

Encoded the way assemblers pick them:
- `MOV`: register, SP, or immediate via `MOVZ`/`MOVN`/`ORR`; `MOV Rd, #?` matches `MOVZ` or `MOVN`.
- `CMP`/`CMN`/`TST`: `SUBS`/`ADDS`/`ANDS` to the zero register.
- `LDR`/`STR` offsets the scaled form can't hold (negative, unaligned): `LDUR`/`STUR`.
- `ADD`/`SUB`/`CMP` immediates that are negative or multiples of 0x1000: the opposite operation or `LSL #12`.
- Register `ADD`/`SUB` with `SP`: the extended (`UXTX`) form.

Other aliases aren't implemented.

## `/d` resolution

At the `X` instruction:
- `B`/`BL`, `B.cond`, `CBZ`/`CBNZ`, `LDR` (literal) and `ADR` give their target.
- `ADRP` gives the page plus the `ADD`/`SUB` and load/store offset that follow it through the same register (skipping NOPs and instructions that leave the register alone).
- `MOVZ`/`MOVN`, `ADD`/`SUB` immediates and load/store offsets give the value.

`/r` is not used on arm64.
