#pragma once
// Database search with PatternScanner patterns. No UI, so the idalib test runs the same code as the plugin.
// The library headers go first: the SDK's pro.h redefines some C functions the standard headers use.
#include <PatternScanner/RuntimePattern.hpp>
#include <PatternScanner/RuntimeArmPattern.hpp>
#include <variant>
#include <vector>

#include <ida.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <segment.hpp>

namespace pscan {
    enum kind_t : ushort { bytes_pattern, arm64_pattern };

    // Architecture of the database being searched, not of the IDA running the plugin: decides /d /r, X<len> and /a
    inline patterns::arch db_arch() {
        if (inf_is_64bit())
            return inf_get_procname() == "ARM" ? patterns::arch::arm64 : patterns::arch::x64;
        return patterns::arch::x86;
    }

    // Pattern has no virtual destructor (patterns aren't deleted through it), so the concrete type is kept
    using pattern_t = std::variant<patterns::RuntimePattern, patterns::RuntimeArmPattern>;

    inline const patterns::Pattern& base(const pattern_t& p) {
        return std::visit([](const auto& x) -> const patterns::Pattern& { return x; }, p);
    }

    // Throws std::logic_error on invalid text
    inline pattern_t parse(qstring text, kind_t kind) {
        if (kind == arm64_pattern)
            return patterns::RuntimeArmPattern(text.c_str(), text.length());
        // Byte patterns pasted over several lines
        for (auto& c : text)
            if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        return patterns::RuntimePattern(text.c_str(), text.length(), db_arch());
    }

    // arm64 lines the encoder doesn't know, one per line: they become wildcards matching any instruction. A line that
    // is just "?" is a deliberate wildcard and isn't listed
    inline qstring unsupported_lines(const qstring& text) {
        qstring out;
        patterns::detail::parse_arm(text.c_str(), text.length(),
            [&](size_t, const char* instruction) {
                if (!(instruction[0] == '?' && !instruction[1]) && !patterns::detail::a64_encode_instruction(instruction).mask)
                    out.cat_sprnt("%s\n", instruction);
            },
            [](size_t) {}, [](const char*) {});
        return out;
    }

    struct hit_t {
        ea_t match = BADADDR;    // where the pattern matched
        ea_t result = BADADDR;   // what find() gives: the X offset and /d /r applied
        bool is_value = false;   // result is a value read from the code (/r, arm64 /d on MOVZ/ADD/LDR offsets)
        bool resolved = false;   // false when /d couldn't decode the instruction at X
    };

    // Calls cb(hit) for every match starting in [start, end), in address order, until cb returns false.
    // Matches don't span segments or uninitialized bytes. Returns false if the user cancelled.
    template <class F>
    bool for_each_match(const patterns::Pattern& p, ea_t start, ea_t end, F&& cb) {
        segment_t* s = getseg(start);
        if (!s) s = get_next_seg(start);
        for (; s && s->start_ea < end; s = get_next_seg(s->start_ea)) {
            if (user_cancelled()) return false;
            const ea_t lo = s->start_ea > start ? s->start_ea : start;
            const size_t n = s->end_ea - lo;
            // The buffer sits at the same offset in a 4KB page as lo: /a and arm64 ADRP page math use its address
            std::vector<uint8_t> raw(n + 0x1000);
            uint8_t* buf = raw.data() + ((lo - reinterpret_cast<uintptr_t>(raw.data())) & 0xFFF);
            bytevec_t loaded;
            loaded.resize((n + 7) / 8);
            if (get_bytes(buf, n, lo, GMB_READALL, loaded.begin()) < 0) return false;
            // Scan each run of initialized bytes on its own
            for (size_t a = 0; a < n;) {
                if (!loaded.test_bit(a)) { ++a; continue; }
                size_t b = a;
                while (b < n && loaded.test_bit(b)) ++b;
                const uint8_t* run_end = buf + b;
                for (const uint8_t* cur = buf + a; cur < run_end;) {
                    const uint8_t* m = p.match(cur, run_end - cur);
                    if (!m) break;
                    hit_t h;
                    h.match = lo + (m - buf);
                    if (h.match >= end) return true;
                    try {
                        const auto r = reinterpret_cast<uintptr_t>(p.resolve(m, run_end, &h.is_value));
                        // Addresses come back in buffer terms; the arithmetic wraps, so targets outside it work too
                        h.result = h.is_value ? ea_t(r) : ea_t(lo + (r - reinterpret_cast<uintptr_t>(buf)));
                        if (!inf_is_64bit()) h.result &= 0xFFFFFFFF;
                        h.resolved = true;
                    }
                    catch (const std::logic_error&) {}
                    if (!cb(h)) return true;
                    cur = m + 1;
                }
                a = b;
            }
        }
        return true;
    }

    // Down: the first match at or after from. Up: the last match before from
    inline bool find_next(const patterns::Pattern& p, ea_t from, bool up, hit_t* out) {
        bool found = false;
        if (up)
            for_each_match(p, inf_get_min_ea(), from, [&](const hit_t& h) { *out = h; found = true; return true; });
        else
            for_each_match(p, from, BADADDR, [&](const hit_t& h) { *out = h; found = true; return false; });
        return found;
    }

    // Empty if cancelled
    inline std::vector<hit_t> find_all(const patterns::Pattern& p) {
        std::vector<hit_t> hits;
        if (!for_each_match(p, inf_get_min_ea(), BADADDR, [&](const hit_t& h) { hits.push_back(h); return true; }))
            hits.clear();
        return hits;
    }
}
