# PatternScanner

A header-only C++17 library for finding byte patterns (signatures) in memory, e.g. locating functions and globals inside a loaded module.

- **Fast**: SSE2 / NEON scanning, plus a single-pass scan for many patterns at once.
- **Hidden**: compile-time patterns leave no pattern text in your binary; XOR variants don't even leave the bytes.
- **Resolves for you**: mark the operand with `X` and get back the address it points to, not just where the pattern matched.
- **arm64 assembly patterns**: write patterns as instructions (`ADRP X?, #?`) instead of hex.
- **Safe anywhere**: no allocation, threads or CRT needed, so it works in TLS callbacks and DllMain.

## Setup

Add `include/` to your include path, or with CMake:
```cmake
add_subdirectory(path/to/PatternScanner)   # or FetchContent
target_link_libraries(app PRIVATE PatternScanner::PatternScanner)
```

## Quick start

```c++
#include <PatternScanner/CompileTimePattern.hpp>

// Find "mov rax, [rip+X]; test rax, rax" and follow the RIP-relative operand
constexpr auto p = "48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_ctpattern;
auto ctx = p.find<lua_State**>(module_start, module_size);
```

## Pattern types

| Type | Literal (C++20) | Macro (C++17) | Use when |
|------|-----------------|---------------|----------|
| `RuntimePattern` | `_rtpattern` | — | The pattern is only known at runtime (config, user input) |
| `CompileTimePattern` | `_ctpattern` | `COMPILETIME_PATTERN` | Default choice; pattern text never ends up in the binary |
| `XORPattern` | `_xorpattern` | `XOR_PATTERN` | You also want the pattern bytes hidden (XOR'd, per-pattern random keys) |
| `ArmPattern` | `_armpattern` | `ARM_PATTERN` | Writing arm64 patterns as assembly |
| `ArmXORPattern` | `_armxorpattern` | `ARM_XOR_PATTERN` | arm64 assembly, hidden like `XORPattern` |
| `RuntimeArmPattern` | — | — | arm64 assembly only known at runtime |

Include the header with the same name, e.g. `<PatternScanner/XORPattern.hpp>`.

## Pattern syntax

**Bytes**: hex bytes separated by spaces, e.g. `48 8B 05`.

**Wildcards**
- `?` or `??`: any byte
- `4?` / `?8`: any low / high nibble
- arm64: `?` for a register (`X?`), immediate (`#?`), shift (`LSL #?`), condition (`B.?`) or a whole instruction

**Capture marker**: `X` marks the operand you care about; `X1`/`X2`/`X4`/`X8` give its size.

**Flags** (at the end of the pattern)
- `/d`: dereference: return the address the operand points to (e.g. a call or RIP-relative target)
- `/r`: read the value at the operand
- `/a`: only match at aligned addresses (4 bytes on x86/arm64, 8 on x64)

## Examples

```c++
// Read the 4-byte value at X
constexpr auto a = "AB CC 11 22 33 44 AB 6D X4 EF BE AD DE /r"_ctpattern;

// Follow the call target (E8 rel32), aligned matches only, pattern hidden in the binary
constexpr auto b = "FE ED FA CE E8 X4 ? ? ? ? EF BE AD DE /da"_xorpattern;

// Follow a short jump (1-byte operand), pattern built at runtime
auto c = "BA BE CA FE 72 X1 ? 11 22 /d"_rtpattern;

// arm64: resolve ADRP + ADD to the full address
constexpr auto d =
    "LDR W?, [X?,#0x18]\n"
    "X ADRP X?, #?\n"
    "ADD X?, X?, #?\n"
    "STR W?, [SP,#?]\n"
    "/d"_armpattern;
```

## Use cases

**Scan for one pattern**
```c++
auto ptr = pattern.find<T>(start, size);
```

**Scan for many patterns in one pass**: reads memory once instead of once per pattern (~3.5x faster):
```c++
inline constexpr const patterns::Pattern* list[] = { &lua_context, &lua_thread };
void* out[2];
size_t found = patterns::find_all(start, size, list, 2, out);
```

**Resolve globals at startup, from a TLS callback or DllMain, after decrypting a module, or across threads**: see [docs/usage.md](docs/usage.md).

**Patterns for arm64 binaries (iOS, macOS, Android)**: write them as assembly; pasted IDA or lldb lines work as-is. See [docs/arm64.md](docs/arm64.md).

**Scanning code of another architecture** (e.g. from a disassembler plugin): `patterns::RuntimePattern("E8 X4 ? ? ? ? /d", patterns::arch::x86)`.

**Searching in IDA**: the [IDA plugin](plugins/ida/README.md) searches databases with these patterns (IDA 9.x).

## More

- [docs/usage.md](docs/usage.md): usage strategies, target architecture, SIMD, keeping strings out of the binary
- [docs/arm64.md](docs/arm64.md): supported instructions and `/d` resolution on arm64
- [docs/testing.md](docs/testing.md): tests and benchmarks
