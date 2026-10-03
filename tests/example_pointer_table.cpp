// Pattern-resolved globals declared in one list, resolved later with one call.
//
// - The list lives in a header next to the globals it fills.
// - Everything generated from it is built at compile time (no static-initializer code), so the table is usable
//   from a TLS callback, before the CRT has run any constructors.
// - The module range is only needed at resolve time, so it can run after decryption.
// - Patterns live in read-only data instead of being re-materialized on a function's stack.
//
// Threads: don't start threads and wait on them under the loader lock (DllMain, TLS callbacks, static
// initializers of a DLL). New threads can't start until the lock is released, so waiting on them deadlocks.
// There, resolve with threads = 1 (still ~2x faster than sequential find() calls via chunking), or resolve
// from a thread you start and don't wait on.
#include "CompileTimePattern.hpp"
#include "multi_scan.hpp"
#include <cstdio>
#include <random>

// ---- pointers.hpp ---------------------------------------------------------------------------------------------
#define GAME_POINTERS(X) \
    X(void*, luaO_nilobject_,   "48 83 EC ? E8 ? ? ? ? 48 8D 0D X4 ? ? ? ? 48 3B C1 75 /d") \
    X(void*, dummynode_,        "44 8B C3 48 89 47 20 48 8B D7 89 47 40 48 8B CD 48 8D 05 X4 ? /d") \
    X(int*,  s_errorHandlerRef, "48 8B CB E8 ? ? ? ? 44 8B 05 X4 ? ? ? ? BA F0 D8 FF FF 48 8B CF E8 /d")

#define DECLARE_POINTER(type, name, sig) \
    inline type name = nullptr; \
    inline constexpr auto name##_pattern = sig##_ctpattern;
GAME_POINTERS(DECLARE_POINTER)

struct PointerEntry {
    const patterns::Pattern* pattern;
    void (*set)(void*);
    const char* name;   // drop in release builds if the names shouldn't be in the binary
};
#define POINTER_ENTRY(type, name, sig) { &name##_pattern, [](void* p) { name = static_cast<type>(p); }, #name },
inline constexpr PointerEntry g_pointers[] = { GAME_POINTERS(POINTER_ENTRY) };

// Returns how many resolved
inline size_t resolve_pointers(const uint8_t* start, size_t size, unsigned threads) {
    std::vector<const patterns::Pattern*> pats;
    for (auto& e : g_pointers) pats.push_back(e.pattern);
    std::vector<void*> out;
    multi::chunked(start, size, pats, out, threads);
    size_t found = 0;
    for (size_t i = 0; i < out.size(); ++i) {
        g_pointers[i].set(out[i]);
        found += out[i] != nullptr;
    }
    return found;
}
// ---------------------------------------------------------------------------------------------------------------

// Proves the table needs no runtime initialization
constinit const PointerEntry* table_is_constant = g_pointers;

int main() {
#ifdef __arm64__
    puts("x86 signatures with x86 /d semantics; skipped on arm64");
    return 0;
#endif
    // Synthetic 32 MB "module" with the three code sequences planted at known places
    std::vector<uint8_t> mod(32 << 20);
    std::mt19937 rng(9);
    for (auto& b : mod) b = static_cast<uint8_t>(rng());
    auto plant = [&](size_t at, std::initializer_list<uint8_t> bytes) { std::copy(bytes.begin(), bytes.end(), mod.begin() + at); };
    plant(0x0123450, { 0x48, 0x83, 0xEC, 0x28, 0xE8, 1, 2, 3, 4, 0x48, 0x8D, 0x0D, 0x00, 0x10, 0x00, 0x00, 0x48, 0x3B, 0xC1, 0x75 });
    plant(0x0ABCDE0, { 0x44, 0x8B, 0xC3, 0x48, 0x89, 0x47, 0x20, 0x48, 0x8B, 0xD7, 0x89, 0x47, 0x40, 0x48, 0x8B, 0xCD, 0x48, 0x8D, 0x05,
                       0x00, 0x20, 0x00, 0x00 });
    plant(0x1F00010, { 0x48, 0x8B, 0xCB, 0xE8, 1, 2, 3, 4, 0x44, 0x8B, 0x05, 0xF0, 0xFF, 0xFF, 0xFF, 0xBA, 0xF0, 0xD8, 0xFF, 0xFF, 0x48, 0x8B, 0xCF, 0xE8 });
    const uint8_t* base = mod.data();

    const size_t found = resolve_pointers(base, mod.size(), std::thread::hardware_concurrency());
    // /d result = match + X offset + 4 (rel32 size) + rel32
    const bool ok = found == 3
        && luaO_nilobject_ == base + 0x0123450 + 12 + 4 + 0x1000
        && dummynode_ == base + 0x0ABCDE0 + 19 + 4 + 0x2000
        && reinterpret_cast<uint8_t*>(s_errorHandlerRef) == base + 0x1F00010 + 11 + 4 - 0x10;
    printf("%-20s %p\n%-20s %p\n%-20s %p\n", "luaO_nilobject_", luaO_nilobject_, "dummynode_", dummynode_,
           "s_errorHandlerRef", static_cast<void*>(s_errorHandlerRef));
    puts(ok ? "pointer table ok" : "FAIL pointer table");
    return !ok;
}
