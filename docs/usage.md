# Usage

All of these are in `tests/example_usage.cpp` (styles 3-5) and `tests/test_tls.cpp` (style 6), built and checked by the tests.

## 1. One pattern, one scan
```c++
constexpr auto p = "48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_ctpattern;
auto ctx = p.find<lua_State**>(start, size);
```

## 2. Many patterns, one pass: `patterns::find_all`
The range is walked in 1 MB chunks with every pattern run over a chunk while it's in cache, so memory is read once instead of once per pattern (~3.5x faster than a `find()` per pattern). It allocates nothing, starts no threads and needs no CRT state, so it's safe anywhere, including TLS callbacks and DllMain.
```c++
inline constexpr auto lua_context = "48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_xorpattern;
inline constexpr auto lua_thread = "8B 0D X4 ? ? ? ? 85 C9 /d"_ctpattern;
inline constexpr const patterns::Pattern* list[] = { &lua_context, &lua_thread };   // constant-initialized

void* out[2];   // out[i] = list[i]->find(start, size)
size_t found = patterns::find_all(start, size, list, 2, out);
```

## Where the module comes from
For globals resolved at static init (3, 4), every scan gets its range from one function whose setup runs once, on first use, from whichever initializer gets there first. That's also the place to decrypt the module, or wait for it. A plain global holding the range doesn't work: the initialization order of globals across files is unspecified.
```c++
inline std::pair<const uint8_t*, size_t> game_module() {
    static const auto range = [] { /* find the module, decrypt it... */ return std::pair{ base, size }; }();
    return range;
}
```

## 3. Per global, at static init
Simplest; one full pass over the module per global.
```c++
// Takes the exact pattern type: MSVC rejects a compile-time-only derived temporary bound to const Pattern& (C7595)
template <class T = void*, class P> T scan(const P& p) {
    const auto [start, size] = game_module();
    return p.template find<T>(start, size);
}
inline lua_State** g_lua_context = scan<lua_State**>("48 8B 05 X4 ? ? ? ? 48 85 C0 /d"_ctpattern);
```

## 4. Batched, at static init
One list (X-macro); the first of its globals to initialize runs `find_all` for all of them, one pass total. Each global is still one line: `inline T name = static_cast<T>(resolved()[name_index]);`

## 5. Explicit call
Same list, globals start as `nullptr` and `resolve_pointers(start, size)` fills them when you choose: after decryption, from main, DllMain...

## 6. TLS callback
Style 5 called from a TLS callback, as the module loads and before the CRT is initialized. The list, patterns and `find_all` need no runtime initialization, so they work there.

## Threads and custom strategies
Static init, TLS callbacks and DllMain of a DLL run under the loader lock: never start threads and wait on them there (deadlock). Outside of it, `match()` (raw match address) and `resolve()` (apply the X offset and /d /r) are public for building your own strategies, e.g. spreading chunks over threads (`tests/multi_scan.hpp`, ~10x faster again on 24 threads).

## Pattern types in detail

`RuntimePattern` allocates the pattern & mask with `std::vector`'s default allocator and leaves the pattern string in the binary.

`CompileTimePattern` creates the pattern & mask at compile time and stores them in a `std::array`. The data is in the binary's module, and no pattern string is left.

`XORPattern` creates the pattern & mask along with two key arrays at compile time. Pattern and mask are both stored XOR'd (with separate keys); otherwise it acts the same as `CompileTimePattern`. `pattern()` and `mask()` return the XOR'd bytes; access the original pattern bytes with `[]` and the original mask bytes with `unmask()`.

`ArmXORPattern` is `ArmPattern` with the instruction words and masks stored XOR'd, the way `XORPattern` stores them. Same syntax, flags and results, plus `[]` and `unmask()` for the originals. Decoded on the stack only while scanning.

`RuntimeArmPattern` is `ArmPattern` built at runtime, for assembly only known then (user input, config files).

## Keeping pattern text out of the binary

Compile-time patterns (`_ctpattern`, `_xorpattern`, `_armpattern`, `_armxorpattern` and their macros) are always built at compile time, so the pattern text never ends up in the binary. The class names still do, through RTTI, because `Pattern` is polymorphic. Build with `/GR-` (MSVC) or `-fno-rtti` (clang/gcc) to strip them.

Each `_xorpattern` and `_armxorpattern` gets its own random keys from where it's written (file, line, column) and the build time, so the same pattern written twice is stored differently. `XOR_PATTERN` and `ARM_XOR_PATTERN` get per-definition keys from `__FILE__`/`__LINE__`/`__COUNTER__`.

## Target architecture

`/d`, `/r`, `X<len>` and `/a` depend on the architecture of the code being scanned (`patterns::arch::x86`, `x64` or `arm64`). By default that's the one you compile for (`patterns::host_arch`); `ArmPattern`, `ArmXORPattern` and `RuntimeArmPattern` are always arm64. To scan code of another architecture, e.g. from a disassembler plugin, pass it to `RuntimePattern`: `patterns::RuntimePattern("E8 X4 ? ? ? ? /d", patterns::arch::x86)`.

`resolve(match, end, &is_value)` reports whether the result is an address or a value read from the code (`/r`; arm64 `/d` on MOVZ/MOVN, ADD, or a lone load/store offset).

## SIMD

Scanning uses SSE2 (x86/x64) or NEON (arm64) when available. Define `PATTERNS_NO_SIMD` before including to use a portable 64-bit integer scan instead (e.g. kernel code).

## Without exceptions

Pattern errors (bad hex, `/d` with `/r`...) throw `std::logic_error`, a compile error for compile-time patterns. Built without exceptions (`-fno-exceptions`, kernel code) they are still compile errors there, and trap at runtime (`RuntimePattern` with bad text).
