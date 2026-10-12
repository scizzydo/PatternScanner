// PatternScanner for IDA: search the database with PatternScanner byte or arm64 patterns, like Search > Sequence of
// bytes. Find the next/previous match from the cursor, or list every match with what /d /r resolve it to.
#include "search.hpp"
#include <optional>

#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <name.hpp>

namespace {
    // Find all: one row per match. Enter / double-click jumps to the match
    struct hits_chooser_t : public chooser_t {
        static constexpr int widths_[] = { CHCOL_HEX | 16, CHCOL_PLAIN | 32, 8, 24, 48 };
        static constexpr const char* const header_[] = { "Match", "Result", "Segment", "Function", "Instruction" };
        std::vector<pscan::hit_t> hits;
        qstring title_;

        hits_chooser_t(qstring t, std::vector<pscan::hit_t> h) :
            chooser_t(0, qnumber(widths_), widths_, header_), hits(std::move(h)), title_(std::move(t)) {
            title = title_.c_str();
        }
        size_t idaapi get_count() const override { return hits.size(); }
        ea_t idaapi get_ea(size_t n) const override { return hits[n].match; }
        cbret_t idaapi enter(size_t n) override {
            jumpto(hits[n].match);
            return cbret_t();
        }
        void idaapi get_row(qstrvec_t* cols, int*, chooser_item_attrs_t*, size_t n) const override {
            const auto& h = hits[n];
            (*cols)[0].sprnt("%" FMT_EA "X", h.match);
            if (!h.resolved)
                (*cols)[1] = "can't decode the instruction at X";
            else if (h.is_value)
                (*cols)[1].sprnt("value 0x%llX", static_cast<uint64>(h.result));
            else {
                (*cols)[1].sprnt("%" FMT_EA "X", h.result);
                qstring name = get_name(h.result);
                if (!name.empty()) (*cols)[1].cat_sprnt(" %s", name.c_str());
            }
            get_segm_name(&(*cols)[2], getseg(h.match));
            if (func_t* f = get_func(h.match)) get_func_name(&(*cols)[3], f->start_ea);
            generate_disasm_line(&(*cols)[4], h.match, GENDSM_REMOVE_TAGS);
        }
    };

    struct plugin_ctx_t;

    struct handler_t : public action_handler_t {
        plugin_ctx_t& ctx;
        bool repeat;
        handler_t(plugin_ctx_t& c, bool r) : ctx(c), repeat(r) {}
        int idaapi activate(action_activation_ctx_t*) override;
        action_state_t idaapi update(action_update_ctx_t*) override { return AST_ENABLE_ALWAYS; }
    };

    constexpr const char search_action[] = "patternscanner:search";
    constexpr const char next_action[] = "patternscanner:next";

    struct plugin_ctx_t : public plugmod_t {
        handler_t search_handler{ *this, false };
        handler_t next_handler{ *this, true };
        // Dialog state, kept between searches
        qstring text;
        ushort kind = pscan::db_arch() == patterns::arch::arm64 ? pscan::arm64_pattern : pscan::bytes_pattern;
        enum : ushort { opt_all = 1, opt_up = 2, opt_cursor = 4 };
        ushort opts = opt_cursor;
        // The last pattern, for Search next
        std::optional<pscan::pattern_t> last;

        plugin_ctx_t() {
            register_action(ACTION_DESC_LITERAL_PLUGMOD(search_action, "PatternScanner pattern...", &search_handler,
                this, "Shift-Alt-B", "Search with a PatternScanner byte or arm64 pattern", -1));
            register_action(ACTION_DESC_LITERAL_PLUGMOD(next_action, "PatternScanner next", &next_handler,
                this, "Ctrl-Shift-B", "Repeat the last PatternScanner search from the cursor", -1));
            attach_action_to_menu("Search/", search_action, SETMENU_APP);
            attach_action_to_menu("Search/", next_action, SETMENU_APP);
        }

        bool idaapi run(size_t) override {
            search();
            return true;
        }

        void search() {
            static const char form[] =
                "STARTITEM 0\n"
                "BUTTON YES* Search\n"
                "PatternScanner\n"
                "\n"
                "Bytes: 48 8B 05 X4 ? ? ? ? 48 85 C0 /d\n"
                "arm64: one instruction per line, X before the one to resolve, flags last (e.g. /d)\n"
                "<~P~attern:t:0:64:::>\n"
                "<~B~ytes:R>\n"
                "<~A~RM64 assembly:R>>\n"
                "<~F~ind all occurrences:C>\n"
                "<Search ~u~p:C>\n"
                "<From ~c~ursor:C>>\n";
            textctrl_info_t ti;
            ti.text = text;
            if (ask_form(form, &ti, &kind, &opts) != ASKBTN_YES) return;
            text = ti.text;
            // Parsed before listing unsupported lines: both throw on a line too long, and an exception escaping
            // into IDA would take it down
            std::optional<pscan::pattern_t> parsed;
            try {
                parsed = pscan::parse(text, static_cast<pscan::kind_t>(kind));
            }
            catch (const std::logic_error& e) {
                last.reset();
                warning("PatternScanner: %s", e.what());
                return;
            }
            if (kind == pscan::arm64_pattern) {
                const qstring unknown = pscan::unsupported_lines(text);
                if (!unknown.empty() && ask_yn(ASKBTN_NO, "HIDECANCEL\nPatternScanner doesn't support these instructions, "
                        "so they would match any instruction:\n\n%s\nSearch anyway?", unknown.c_str()) != ASKBTN_YES)
                    return;
            }
            last = std::move(parsed);
            const auto& p = pscan::base(*last);
            if (!p.length()) {
                last.reset();
                warning("PatternScanner: the pattern is empty");
                return;
            }
            if (opts & opt_all) {
                show_wait_box("PatternScanner: searching...");
                auto hits = pscan::find_all(p);
                hide_wait_box();
                if (hits.empty()) {
                    msg("PatternScanner: no matches\n");
                    return;
                }
                qstring title;
                title.sprnt("PatternScanner: %" FMT_Z " matches for %s", hits.size(), first_line().c_str());
                msg("%s\n", title.c_str());
                (new hits_chooser_t(title, std::move(hits)))->choose();
                return;
            }
            const bool up = opts & opt_up;
            ea_t from = up ? inf_get_max_ea() : inf_get_min_ea();
            if (opts & opt_cursor) from = get_screen_ea();
            next(from);
        }

        // Search next: from just past the cursor, in the last direction
        void repeat() {
            if (!last) {
                search();
                return;
            }
            const ea_t here = get_screen_ea();
            next(opts & opt_up ? here : here + 1);
        }

        void next(ea_t from) {
            const bool up = opts & opt_up;
            pscan::hit_t h;
            show_wait_box("PatternScanner: searching...");
            const bool found = pscan::find_next(pscan::base(*last), from, up, &h);
            hide_wait_box();
            if (!found) {
                msg("PatternScanner: no match %s %" FMT_EA "X\n", up ? "before" : "from", from);
                return;
            }
            jumpto(h.match);
            if (!h.resolved)
                msg("PatternScanner: match at %" FMT_EA "X, can't decode the instruction at X\n", h.match);
            else if (h.is_value)
                msg("PatternScanner: match at %" FMT_EA "X, value 0x%llX\n", h.match, static_cast<uint64>(h.result));
            else
                msg("PatternScanner: match at %" FMT_EA "X -> %" FMT_EA "X\n", h.match, h.result);
        }

        qstring first_line() const {
            qstring s = text;
            const size_t nl = s.find('\n');
            if (nl != qstring::npos) s.resize(nl);
            return s;
        }
    };

    int idaapi handler_t::activate(action_activation_ctx_t*) {
        if (repeat) ctx.repeat();
        else ctx.search();
        return 1;
    }

    plugmod_t* idaapi init() {
        return new plugin_ctx_t;
    }
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Search the database with PatternScanner patterns",
    "Shift-Alt-B: search (next/previous from the cursor, or find all)\nCtrl-Shift-B: search next",
    "PatternScanner",
    nullptr,
};
