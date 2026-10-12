// Every way to fill pattern-resolved globals, against a synthetic "module" that must be decrypted before it can be
// scanned. Each result is logged as [count] name address (address rebased to the disassembler's image base).
//
//  1. Per global, at static init: inline T name = scan<T>("name", "..."_ctpattern);
//     Simplest. One full pass over the module per global.
//  2. Batched, at static init:    one list; the first of its globals to initialize runs find_all for all of them.
//     One pass for the whole list.
//  3. Explicit call:              same list; resolve_pointers(start, size) whenever the module is ready (main, a TLS
//     callback, DllMain, after decryption...). test_tls.cpp runs find_all from a real TLS callback.
//
// The module and anything that must happen before scanning (decryption) live in game_module(), which runs once on
// first use, from whichever initializer gets there first; the initialization order of globals across files is
// unspecified, so a plain global holding the range could still be unset.
// In a DLL, static init, TLS callbacks and DllMain run under the loader lock: don't wait on other threads there.
#include "CompileTimePattern.hpp"
#include "XORPattern.hpp"
#include <array>
#include <atomic>
#include <cstdio>
#include <random>
#include <utility>
#include <vector>

#ifdef __APPLE__
#define BASEADDR 0x100000000
#else
#define BASEADDR 0x140000000
#endif

// ---- the module ------------------------------------------------------------------------------------------------
// Where the code sequences the patterns look for are planted
constexpr size_t at_one = 0x012340, at_two = 0x0ABCD0, at_four = 0x5F0010, at_five = 0xC00050;
constexpr uint8_t module_key = 0x5A;

static std::vector<uint8_t> load_encrypted_module() {
    std::vector<uint8_t> m(16 << 20);
    std::mt19937 rng(9);
    for (auto& b : m) b = static_cast<uint8_t>(rng());
    auto plant = [&](size_t at, std::initializer_list<uint8_t> bytes) { std::copy(bytes.begin(), bytes.end(), m.begin() + at); };
    plant(at_one, { 0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0x48, 0x85, 0xC0, 0x74, 0x05, 0xE8 });
    plant(at_two, { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0x0D, 1, 2, 3, 4, 0x85, 0xC9, 0x0F, 0x84 });
    plant(at_four, { 0x4C, 0x8D, 0x05, 9, 8, 7, 6, 0x48, 0x8B, 0xD3, 0x48, 0x8B, 0xCF, 0xE8 });
    plant(at_five, { 0xF3, 0x0F, 0x10, 0x05, 5, 6, 7, 8, 0x0F, 0x2F, 0xC1, 0x76 });
    for (auto& b : m) b ^= module_key;
    return m;
}

// Every scan gets its range from here. A real one would find the module (GetModuleHandle, dlopen, dyld...) and
// decrypt it or wait until it's decrypted
inline std::pair<const uint8_t*, size_t> game_module() {
    static const std::vector<uint8_t> image = [] {
        auto m = load_encrypted_module();
        for (auto& b : m) b ^= module_key;
        return m;
    }();
    return { image.data(), image.size() };
}

// ---- logging ---------------------------------------------------------------------------------------------------
inline std::atomic<int> g_scan_count{0}, g_found_count{0};

inline void log_result(const char* name, const void* p) {
    const int n = ++g_scan_count;
    if (!p) {
        printf("[%2d]\t%40s\tnot found\n", n, name);
        return;
    }
    ++g_found_count;
    const auto rebased = reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(game_module().first) + BASEADDR;
    printf("[%2d]\t%40s\t%p (%p)\n", n, name, p, reinterpret_cast<void*>(rebased));
}

// ---- 1. per global, at static init -----------------------------------------------------------------------------
// Takes the exact pattern type: MSVC rejects a compile-time-only derived temporary bound to const Pattern& (C7595)
template <class T = void*, class P> T scan(const char* name, const P& pattern) {
    const auto [start, size] = game_module();
    const T result = pattern.template find<T>(start, size);
    log_result(name, reinterpret_cast<const void*>(result));
    return result;
}

inline void*     g_one   = scan("g_one", "48 8B 05 X ? ? ? ? 48 85 C0 74 ? E8"_ctpattern);
inline uint32_t* g_two   = scan<uint32_t*>("g_two", "40 53 48 83 EC 20 8B 0D X ? ? ? ? 85 C9 0F 84"_xorpattern);
inline void*     g_three = scan("g_three", "DE AD BE EF 13 37 C0 DE 00 11"_ctpattern);

// ---- one list for 2 and 3 --------------------------------------------------------------------------------------
#define POINTERS(X) \
    X(void*,  g_four,    "4C 8D 05 X ? ? ? ? 48 8B D3 48 8B CF E8") \
    X(float*, g_five,    "F3 0F 10 05 X ? ? ? ? 0F 2F C1 76") \
    X(void*,  g_missing, "DE AD BE EF 13 37 C0 DE 00 11 22")

// All built at compile time (no initializer code), so usable before static init too, e.g. from a TLS callback
#define PATTERN_OF(type, name, sig) inline constexpr auto name##_pattern = sig##_ctpattern;
POINTERS(PATTERN_OF)
#define INDEX_OF(type, name, sig) name##_index,
enum : size_t { POINTERS(INDEX_OF) pointer_count };
#define ADDRESS_OF(type, name, sig) &name##_pattern,
inline constexpr const patterns::Pattern* pointer_patterns[] = { POINTERS(ADDRESS_OF) };
#define NAME_OF(type, name, sig) #name,   // drop in release builds if the names shouldn't be in the binary
inline constexpr const char* pointer_names[] = { POINTERS(NAME_OF) };

// ---- 2. batched, at static init --------------------------------------------------------------------------------
inline void* const* resolved() {
    static const auto out = [] {
        std::array<void*, pointer_count> r{};
        const auto [start, size] = game_module();
        patterns::find_all(start, size, pointer_patterns, pointer_count, r.data());
        for (size_t i = 0; i < pointer_count; ++i) log_result(pointer_names[i], r[i]);
        return r;
    }();
    return out.data();
}
#define BATCHED_GLOBAL(type, name, sig) inline type name = static_cast<type>(resolved()[name##_index]);
POINTERS(BATCHED_GLOBAL)

// ---- 3. explicit call ------------------------------------------------------------------------------------------
#define LATE_GLOBAL(type, name, sig) inline type late_##name = nullptr;
POINTERS(LATE_GLOBAL)
#define SETTER_OF(type, name, sig) [](void* p) { late_##name = static_cast<type>(p); },
inline constexpr void (*pointer_setters[])(void*) = { POINTERS(SETTER_OF) };

// No allocation or threads: safe under the loader lock. Returns how many resolved
inline size_t resolve_pointers(const uint8_t* start, size_t size) {
    void* out[pointer_count];
    const size_t found = patterns::find_all(start, size, pointer_patterns, pointer_count, out);
    for (size_t i = 0; i < pointer_count; ++i) {
        pointer_setters[i](out[i]);
        log_result(pointer_names[i], out[i]);
    }
    return found;
}

// Proves the list needs no runtime initialization
constinit const patterns::Pattern* const* patterns_are_constant = pointer_patterns;
constinit void (* const* setters_are_constant)(void*) = pointer_setters;

int main() {
    puts("-- main: explicit resolve_pointers --");
    const auto [base, size] = game_module();
    const size_t late_found = resolve_pointers(base, size);
    printf("%d of %d found\n", g_found_count.load(), g_scan_count.load());

    const bool ok = g_one == base + at_one + 3
        && g_two == reinterpret_cast<const uint32_t*>(base + at_two + 8)
        && !g_three
        && g_four == base + at_four + 3
        && g_five == reinterpret_cast<const float*>(base + at_five + 4)
        && !g_missing
        && late_found == 2 && late_g_four == g_four && late_g_five == g_five && !late_g_missing
        && g_scan_count == 9 && g_found_count == 6;
    puts(ok ? "usage ok" : "FAIL usage");
    return !ok;
}
