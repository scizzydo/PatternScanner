// Runs the plugin's search (search.hpp) through idalib on the fixture binaries. Exit code 0 = pass.
// Usage: test_search <x64.elf> <x86.elf> <arm64.elf>
#include "../search.hpp"
#include <cstdio>
#include <cstdlib>

#include <auto.hpp>
#include <idalib.hpp>
#include <name.hpp>

#define CHECK(x) do { if (!(x)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static ea_t sym(const char* name) {
    const ea_t ea = get_name_ea(BADADDR, name);
    if (ea == BADADDR) { printf("FAIL: no symbol %s\n", name); exit(1); }
    return ea;
}

static pscan::hit_t next(const char* text, pscan::kind_t kind, ea_t from, bool up, bool* found = nullptr) {
    const auto p = pscan::parse(text, kind);
    pscan::hit_t h;
    const bool f = pscan::find_next(pscan::base(p), from, up, &h);
    if (found) *found = f;
    else CHECK(f);
    return h;
}

static std::vector<pscan::hit_t> all(const char* text, pscan::kind_t kind = pscan::bytes_pattern) {
    return pscan::find_all(pscan::base(pscan::parse(text, kind)));
}

static void open(const char* path) {
    if (open_database(path, true) != 0) { printf("FAIL: can't open %s\n", path); exit(1); }
    auto_wait();
}

// x86 and x64: find next/previous, find all, /d /r, uninitialized bytes, /a by the database's pointer size
static void x86_family(const char* path, bool x64) {
    open(path);
    CHECK(pscan::db_arch() == (x64 ? patterns::arch::x64 : patterns::arch::x86));
    const ea_t m1 = sym("marker1"), m2 = sym("marker2"), m3 = sym("marker3");
    const char* marker = "DE AD BE EF 11 22";

    const auto hits = all(marker);
    CHECK(hits.size() == 3 && hits[0].match == m1 && hits[1].match == m2 && hits[2].match == m3);
    CHECK(hits[0].resolved && !hits[0].is_value && hits[0].result == m1);
    CHECK(next(marker, pscan::bytes_pattern, m1, false).match == m1);       // down: from is included
    CHECK(next(marker, pscan::bytes_pattern, m1 + 1, false).match == m2);
    CHECK(next(marker, pscan::bytes_pattern, m2, true).match == m1);        // up: before from
    CHECK(next(marker, pscan::bytes_pattern, inf_get_max_ea(), true).match == m3);
    bool found = true;
    next(marker, pscan::bytes_pattern, m1, true, &found);
    CHECK(!found);
    next(marker, pscan::bytes_pattern, m3 + 1, false, &found);
    CHECK(!found);

    const ea_t call = sym("code_call"), func = sym("target_func");
    const auto d = next("E8 X4 ? ? ? ? A3 B4 /d", pscan::bytes_pattern, 0, false);
    CHECK(d.match == call && d.result == func && !d.is_value);
    const auto r = next("E8 X4 ? ? ? ? A3 B4 /r", pscan::bytes_pattern, 0, false);
    CHECK(r.is_value && r.result == ((func - (call + 5)) & (x64 ? ~0ull : 0xFFFFFFFFull)));
    if (x64) {
        const auto lea = next("48 8D 05 X4 ? ? ? ? CC CC A1 B2 /d", pscan::bytes_pattern, 0, false);
        CHECK(lea.match == sym("code_lea") && lea.result == sym("target_data"));
    }

    const ea_t zeros = sym("zeros");
    for (const auto& h : all("00 00 00 00 00 00 00 00"))
        CHECK(h.match + 8 <= zeros || h.match >= zeros + 64);

    const auto aligned = all("C7 C8 C9 CA /a");
    CHECK(aligned.size() == (x64 ? 0u : 1u));
    CHECK(all("C7 C8 C9 CA").size() == 1);

    close_database(false);
    printf("  %s ok\n", x64 ? "x64" : "x86");
}

// arm64: ADRP page math against database addresses, BL, values, byte patterns with arm64 semantics
static void arm64(const char* path) {
    open(path);
    CHECK(pscan::db_arch() == patterns::arch::arm64);
    const ea_t data = sym("target_data"), func = sym("target_func");
    CHECK((data & 0xFFF) != 0);   // the fixture puts it mid-page, so a page-misaligned buffer would show

    const auto adrl = next("MOVZ W9, #0x7777\nX ADRP X?, #?\nADD X?, X?, #?\n/d", pscan::arm64_pattern, 0, false);
    CHECK(adrl.match == sym("code_adrp") && adrl.result == data && !adrl.is_value);
    const auto bl = next("MOVZ W9, #0x6666\nX BL ?\n/d", pscan::arm64_pattern, 0, false);
    CHECK(bl.match == sym("code_bl") && bl.result == func);
    const auto movz = next("X MOVZ W9, #0x7777\n/d", pscan::arm64_pattern, 0, false);
    CHECK(movz.is_value && movz.result == 0x7777);
    // A byte pattern in an arm64 database: /d decodes the ADRP and follows the ADD
    const auto bytes = next("E9 EE 8E 52 X ? ? ? ? /d", pscan::bytes_pattern, 0, false);
    CHECK(bytes.match == sym("code_adrp") && bytes.result == data);
    CHECK(all("NOP\nRET", pscan::arm64_pattern).empty());

    // A prologue as IDA prints it (STP, MOV): the first hit must be the function that has it, not a near miss
    const char* prologue = "STP             X20, X19, [SP,#?]!\n"
                           "STP             X29, X30, [SP,#?]\n"
                           "ADD             X29, SP, #0x10\n"
                           "MOV             X19, X1\n"
                           "MOV             X0, X30";
    CHECK(pscan::unsupported_lines(prologue).empty());
    const auto fn = all(prologue, pscan::arm64_pattern);
    CHECK(fn.size() == 1 && fn[0].match == sym("wanted"));

    // Unknown instructions are reported (they'd match anything); a deliberate "?" line isn't
    CHECK(pscan::unsupported_lines("NOP\nFOO X1, X2\n  ?  \nstp x29, x30, [sp,#?]\nBAR\n/d") == "FOO X1, X2\nBAR\n");

    bool threw = false;
    try { pscan::parse("48 8G", pscan::bytes_pattern); } catch (const std::logic_error&) { threw = true; }
    CHECK(threw);

    close_database(false);
    puts("  arm64 ok");
}

int main(int argc, char** argv) {
    if (argc != 4) { puts("usage: test_search <x64.elf> <x86.elf> <arm64.elf>"); return 2; }
    if (init_library() != 0) { puts("FAIL: init_library (idalib missing or no license?)"); return 1; }
    x86_family(argv[1], true);
    x86_family(argv[2], false);
    arm64(argv[3]);
    puts("all search tests passed");
}
