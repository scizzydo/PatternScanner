// patterns::find_all from a TLS callback: runs as the module is loaded, before the CRT is initialized and before any
// static constructor or main. Scans this executable's own image. Windows only.
#include "XORPattern.hpp"
#include <cstdio>
#ifdef _MSC_VER
#include <windows.h>

// Data to find in our own image. The patterns are XOR'd, so their stored bytes can't match themselves
extern "C" const uint8_t tls_target[] = { 0x5E, 0xC7, 0x13, 0x9A, 0x40, 0xD2, 0x7B, 0xE1, 0x36, 0xAF, 0x08, 0x95 };

inline constexpr auto whole = "5E C7 13 9A 40 D2 7B E1 36 AF 08 95"_xorpattern;
inline constexpr auto with_offset = "5E C7 ? 9A X 40 D2 7B E1"_xorpattern;
inline constexpr auto absent = "5E C7 13 9A 40 D2 7B E1 36 AF 08 96"_xorpattern;
inline constexpr const patterns::Pattern* tls_patterns[] = { &whole, &with_offset, &absent };

static void* tls_results[3];
static size_t tls_found;
static bool callback_ran, callback_saw_crt;

// Dynamic initializer (a call the compiler can't fold into static data): nonzero once the CRT is up
static const DWORD crt_initialized = GetCurrentProcessId();

static void NTAPI on_tls(PVOID module, DWORD reason, PVOID) {
    if (reason != DLL_PROCESS_ATTACH) return;
    callback_ran = true;
    callback_saw_crt = crt_initialized != 0;
    const auto base = static_cast<const uint8_t*>(module);
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    tls_found = patterns::find_all(base, nt->OptionalHeader.SizeOfImage, tls_patterns, 3, tls_results);
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback")
#endif
#pragma section(".CRT$XLB", read)
extern "C" __declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK tls_callback = on_tls;

int main() {
    const bool ok = callback_ran && !callback_saw_crt && crt_initialized && tls_found == 2
        && tls_results[0] == tls_target && tls_results[1] == tls_target + 4 && !tls_results[2];
    printf("callback ran: %d, before CRT init: %d, found: %zu\n", callback_ran, !callback_saw_crt, tls_found);
    puts(ok ? "tls ok" : "FAIL tls");
    return !ok;
}
#else
int main() { puts("TLS callbacks registered via MSVC sections; skipped"); }
#endif
