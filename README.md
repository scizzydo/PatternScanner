# Pattern Scanning

#### Classes
- Pattern (base class)
- RuntimePattern
- CompileTimePattern
- XORPattern
- ArmPattern

RuntimePattern will allocate the pattern & mask with std::vectors default allocator along with leaving the pattern string in the binary.

CompileTimePattern creates the pattern & mask during compile time and stored in a std::array. This means the data is in the binaries module, and no pattern string left.

XORPattern creates the pattern & mask along with a keys array during compile time. Pattern stored is XOR'd bytes, otherwise it acts just the same as the CompileTimePattern. (the pattern() method however will return the XOR'd pattern, access the original bytes with the [] operator)

ArmPattern creates the pattern & mask from the arm64 assembly, with wildcard support. Instructions not implemented would result in a wildcard portion for those 4 bytes. The class is constexpr also, so the assembly is not in the final product (if declaring the pattern with constexpr). One instruction per line; case, indentation and spacing don't matter, so lines pasted from IDA (`LDR W8, [X8,#0x18]`) or lldb (`ldr    w8, [x8, #0x18]`) both work. lldb prints ADRP operands as page counts and branch targets as absolute addresses, so wildcard those (`#?`). Aliases such as `MOV` aren't implemented (they become wildcards); write the underlying `MOVZ`/`ORR` instead.

Every pattern type has a string literal: `_rtpattern` (any standard), and with C++20 `_ctpattern`, `_xorpattern`, `_armpattern`. Each `_xorpattern` gets its own random keys from where it's written (file, line, column) and the build time, so the same pattern written twice is stored differently. Before C++20, use the `COMPILETIME_PATTERN`, `XOR_PATTERN` and `ARM_PATTERN` macros (`XOR_PATTERN` gets per-definition keys from `__FILE__`/`__LINE__`/`__COUNTER__`).

Compile-time patterns (`_ctpattern`, `_xorpattern`, `_armpattern` and their macros) are always built at compile time, so the pattern text never ends up in the binary. The class names still do, through RTTI, because `Pattern` is polymorphic. Build with `/GR-` (MSVC) or `-fno-rtti` (clang/gcc) to strip them.

Scanning uses SSE2 (x86/x64) or NEON (arm64) when available. Define `PATTERNS_NO_SIMD` before including to use a portable 64-bit integer scan instead (e.g. kernel code).

#### Pattern Flags:
- d: Dereference from the found address, or found address + offset ( addr + size + relative address )
- r: Read the relative value at the address, or at the address + offset (not used on arm)
- a: Only match at aligned addresses. 4 byte alignment x32 & arm64, 8 byte alignment x64
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

#### Tests & benchmarks
`tests/` is a separate CMake project (the library itself stays header-only):
```sh
cmake -S tests -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
./build/bench_scan  [module file]   # single-pattern speed; with a file, 40 real signatures sampled from it
./build/bench_multi [module file]   # many patterns: sequential vs parallel vs cache-chunked
```
- `test_patterns`: edge cases, fuzzing against a naive scanner, per-definition XOR keys, and a check that its own binary contains no pattern plaintext. Also built with `PATTERNS_NO_SIMD`.
- `test_cpp17`: the macro path.
- `test_arm`: ArmPattern encodings checked against clang's assembler (concrete instructions must encode exactly, wildcard patterns must match / not match), line formats, and `/d` resolution. On Apple arm64 it also re-assembles its tables and resolves `/d` on linker-relocated ADRP/ADD/LDR/BL code.
- `example_pointer_table`: globals resolved from one pattern list (X-macro) with a single chunked, multi-threaded scan. See the notes at the top of the file.
- `multi_scan.hpp`: the multi-pattern strategies used by the above.
