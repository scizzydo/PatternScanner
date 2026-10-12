# Pattern Scanning

Header-only. Add `include/` to your include path and include the headers you need:
```c++
#include <PatternScanner/CompileTimePattern.hpp>
#include <PatternScanner/XORPattern.hpp>
```
With CMake (C++17 or newer):
```cmake
add_subdirectory(path/to/PatternScanner)   # or FetchContent_Declare + FetchContent_MakeAvailable(PatternScanner)
target_link_libraries(app PRIVATE PatternScanner::PatternScanner)
```

#### Classes
- Pattern (base class)
- RuntimePattern
- CompileTimePattern
- XORPattern
- ArmPattern
- ArmXORPattern
- RuntimeArmPattern

RuntimePattern will allocate the pattern & mask with std::vectors default allocator along with leaving the pattern string in the binary.

CompileTimePattern creates the pattern & mask during compile time and stored in a std::array. This means the data is in the binaries module, and no pattern string left.

XORPattern creates the pattern & mask along with two keys arrays during compile time. Pattern and mask are both stored XOR'd (with separate keys), otherwise it acts just the same as the CompileTimePattern. (the pattern() and mask() methods however return the XOR'd bytes; access the original pattern bytes with the [] operator and the original mask bytes with unmask())

ArmPattern creates the pattern & mask from the arm64 assembly, with wildcard support. Supported: `B`, `BL`, `B.cond` (`B.?` for any condition), `BR`, `BLR`, `RET`, `RETAA`, `RETAB`, `CBZ`, `CBNZ`, `ADR`, `ADRP`, `ADD(S)`, `SUB(S)`, `CMP`, `CMN`, `AND(S)`, `ORR`, `EOR`, `TST`, `LDR`, `LDRB`, `LDRH`, `LDRSW`, `STR`, `STRB`, `STRH`, `LDUR`/`STUR` (and their `B`/`H`/`SW` forms), `LDP`, `STP`, `MOV`, `MOVZ`, `MOVN`, `MOVK`, `NOP`, `PACIASP`, `PACIBSP`, `AUTIASP`, `AUTIBSP`. Loads and stores take W/X registers only; floating-point/SIMD ones (`LDR Q0, ...`, `STP D9, D8, ...`) are wildcards. Any other instruction becomes a wildcard for those 4 bytes, matching any instruction (the IDA plugin asks before searching with one); write `?` for a deliberate one. The class is constexpr also, so the assembly is not in the final product (if declaring the pattern with constexpr). One instruction per line; case, indentation and spacing don't matter, so lines pasted from IDA (`LDR W8, [X8,#0x18]`) or lldb (`ldr    w8, [x8, #0x18]`) both work. lldb prints ADRP operands as page counts and branch targets as absolute addresses, so wildcard those (`#?`). `MOV` is encoded the way assemblers pick it (register, SP, or immediate via `MOVZ`/`MOVN`/`ORR`); `MOV Rd, #?` matches `MOVZ` or `MOVN`. `CMP`/`CMN`/`TST` are encoded as `SUBS`/`ADDS`/`ANDS` to the zero register, and an `LDR`/`STR` offset the scaled form can't hold (negative, unaligned) as `LDUR`/`STUR`, `ADD`/`SUB`/`CMP` immediates that are negative or multiples of 0x1000 as the opposite operation or `LSL #12`, and register `ADD`/`SUB` with `SP` in the extended (`UXTX`) form, as assemblers do. Other aliases aren't implemented.

ArmXORPattern (`PatternScanner/ArmXORPattern.hpp`) is ArmPattern with the instruction words and masks stored XOR'd, the way XORPattern stores them. Same syntax, flags and results, plus `[]` and unmask() for the originals. Decoded on the stack only while scanning.

Every pattern type has a string literal: `_rtpattern` (any standard), and with C++20 `_ctpattern`, `_xorpattern`, `_armpattern`, `_armxorpattern`. Each `_xorpattern` and `_armxorpattern` gets its own random keys from where it's written (file, line, column) and the build time, so the same pattern written twice is stored differently. Before C++20, use the `COMPILETIME_PATTERN`, `XOR_PATTERN`, `ARM_PATTERN` and `ARM_XOR_PATTERN` macros (`XOR_PATTERN` and `ARM_XOR_PATTERN` get per-definition keys from `__FILE__`/`__LINE__`/`__COUNTER__`).

Compile-time patterns (`_ctpattern`, `_xorpattern`, `_armpattern`, `_armxorpattern` and their macros) are always built at compile time, so the pattern text never ends up in the binary. The class names still do, through RTTI, because `Pattern` is polymorphic. Build with `/GR-` (MSVC) or `-fno-rtti` (clang/gcc) to strip them.

RuntimeArmPattern (`PatternScanner/RuntimeArmPattern.hpp`) is ArmPattern built at runtime, for assembly only known then (user input, config files).

#### Target architecture
/d, /r, `X<len>` and /a depend on the architecture of the code being scanned (`patterns::arch::x86`, `x64` or `arm64`). By default that's the one you compile for (`patterns::host_arch`); ArmPattern, ArmXORPattern and RuntimeArmPattern are always arm64. To scan code of another architecture, e.g. from a disassembler plugin, pass it to RuntimePattern: `patterns::RuntimePattern("E8 X4 ? ? ? ? /d", patterns::arch::x86)`. `resolve(match, end, &is_value)` reports whether the result is an address or a value read from the code (/r; arm64 /d on MOVZ/MOVN, ADD, or a lone load/store offset).

arm64 /d at the X instruction: `B`/`BL`, `B.cond`, `CBZ`/`CBNZ`, `LDR` (literal) and `ADR` give their target; `ADRP` gives the page plus the `ADD`/`SUB` and load/store offset that follow it through the same register (skipping NOPs and instructions that leave the register alone); `MOVZ`/`MOVN`, `ADD`/`SUB` immediates and load/store offsets give the value.

Scanning uses SSE2 (x86/x64) or NEON (arm64) when available. Define `PATTERNS_NO_SIMD` before including to use a portable 64-bit integer scan instead (e.g. kernel code).

#### Wildcards:
- `?` or `??`: any byte
- `4?` / `?8`: a nibble wildcard (high nibble 4, any low nibble / any high nibble, low nibble 8)
- ArmPattern: `?` for a register (`X?`), immediate (`#?`), shift (`LSL #?`), condition (`B.?`) or a whole instruction line

#### Pattern Flags:
- d: Dereference from the found address, or found address + offset ( addr + size + relative address )
- r: Read the relative value at the address, or at the address + offset (not used on arm64)
- a: Only match at aligned addresses. 4 byte alignment x86 & arm64, 8 byte alignment x64
- x: This one is used inside of the pattern itself, to show where the offset is at (start address of what we want to capture). This can be followed by a 1/2/4 or 8 for the size of the operand when doing /r or /d


#### Examples:
```c++
// Scan will read the relative value from the X offset as 4 bytes
constexpr auto compiletime_pattern = "AB CC 11 22 33 44 AB 6D X4 EF BE AD DE /r"_ctpattern;
// Scan will read the address from where the marked X is pointed to (defaults as a relative address), and perform the scan byte aligned (4 - 32bit, 8 - 64bit)
// This also uses the instruction len (notice 4 after X). This tells it during the dereference to start the RIP after the E8 instruction
constexpr auto xor_pattern = "FE ED FA CE E8 X4 ? ? ? ? EF BE AD DE /da"_xorpattern;
// Scan will read the address from where the marked X is pointed to (as a single byte; i.e. short jump)
auto runtime_pattern = "BA BE CA FE 72 X1 ? 11 22 /d"_rtpattern;
// Scan will find the value in ADRP, and add the next ADD instruction to it (like ADRL pseudocode). Without the dereference option, this would return the address of that ADRP instruction
constexpr auto arm_pattern =
    "LDR W?, [X?,#0x18]\n"
    "X ADRP X?, #?\n"
    "ADD X?, X?, #?\n"
    "STR W?, [SP,#?]\n"
    "/d"_armpattern;
```

#### Usage
All of these are in `tests/example_usage.cpp` (styles 3-5) and `tests/test_tls.cpp` (style 6), built and checked by the tests.

**1. One pattern, one scan**
```c++
constexpr auto p = "48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_ctpattern;
auto ctx = p.find<lua_State**>(start, size);
```

**2. Many patterns, one pass: `patterns::find_all`**
The range is walked in 1 MB chunks with every pattern run over a chunk while it's in cache, so memory is read once instead of once per pattern (~3.5x faster than a `find()` per pattern). It allocates nothing, starts no threads and needs no CRT state, so it's safe anywhere, including TLS callbacks and DllMain.
```c++
inline constexpr auto lua_context = "48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_xorpattern;
inline constexpr auto lua_thread = "8B 0D X4 ? ? ? ? 85 C9 /d"_ctpattern;
inline constexpr const patterns::Pattern* list[] = { &lua_context, &lua_thread };   // constant-initialized

void* out[2];   // out[i] = list[i]->find(start, size)
size_t found = patterns::find_all(start, size, list, 2, out);
```

**Where the module comes from.** For globals resolved at static init (3, 4), every scan gets its range from one function whose setup runs once, on first use, from whichever initializer gets there first. That's also the place to decrypt the module, or wait for it. A plain global holding the range doesn't work: the initialization order of globals across files is unspecified.
```c++
inline std::pair<const uint8_t*, size_t> game_module() {
    static const auto range = [] { /* find the module, decrypt it... */ return std::pair{ base, size }; }();
    return range;
}
```

**3. Per global, at static init.** Simplest; one full pass over the module per global.
```c++
// Takes the exact pattern type: MSVC rejects a compile-time-only derived temporary bound to const Pattern& (C7595)
template <class T = void*, class P> T scan(const P& p) {
    const auto [start, size] = game_module();
    return p.template find<T>(start, size);
}
inline lua_State** g_lua_context = scan<lua_State**>("48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_ctpattern);
```

**4. Batched, at static init.** One list (X-macro); the first of its globals to initialize runs `find_all` for all of them, one pass total. Each global is still one line: `inline T name = static_cast<T>(resolved()[name_index]);`

**5. Explicit call.** Same list, globals start as `nullptr` and `resolve_pointers(start, size)` fills them when you choose: after decryption, from main, DllMain...

**6. TLS callback.** Style 5 called from a TLS callback, as the module loads and before the CRT is initialized. The list, patterns and `find_all` need no runtime initialization, so they work there.

Static init, TLS callbacks and DllMain of a DLL run under the loader lock: never start threads and wait on them there (deadlock). Outside of it, `match()` (raw match address) and `resolve()` (apply the X offset and /d /r) are public for building your own strategies, e.g. spreading chunks over threads (`tests/multi_scan.hpp`, ~10x faster again on 24 threads).

#### Tests & benchmarks
`tests/` is a separate CMake project (the library itself stays header-only):
```sh
cmake -S tests -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
./build/bench_scan  [module file]   # single-pattern speed; with a file, 40 real signatures sampled from it
./build/bench_multi [module file]   # many patterns: find() per pattern vs find_all vs threaded
```
- `test_patterns`: edge cases, fuzzing against a naive scanner, per-definition XOR keys. Also built with `PATTERNS_NO_SIMD`.
- `test_artifacts_*`: every compile-time pattern type (macros, and C++20 literals) must leave no pattern text in its binary, and the XOR ones no plaintext bytes, words or masks. All patterns are scanned from one function, as in a project's signature file, and built at each optimization level (`-O0`..`-O3`, `-Os`; MSVC `/Od /O1 /O2`) plus LTO, with debug info, as C++17 and C++20: optimizers fold constants differently at each.
- `test_cpp17`: the macro path.
- `test_arm`: ArmPattern encodings checked against clang's assembler (concrete instructions must encode exactly, wildcard patterns must match / not match), line formats, RuntimeArmPattern parsing the same, and `/d` resolution. On Apple arm64 it also re-assembles its tables and resolves `/d` on linker-relocated ADRP/ADD/LDR/BL code.
- `example_usage`: usage styles 3-5 above against a module that has to be decrypted first, logging each result as `[count] name address (rebased address)`.
- `test_tls` (Windows): style 6, `find_all` run from a TLS callback over the executable's own image.
- `multi_scan.hpp`: other multi-pattern strategies (per-pattern threads, chunks over threads) for the benchmark.

#### Plugins
- [`plugins/ida`](plugins/ida/README.md): search IDA databases with these patterns (IDA 9.x, Windows/macOS/Linux).
