// Resolving many patterns over one module: sequential vs parallel per pattern vs cache-chunked.
//   bench_multi                 synthetic 96 MB module with 60 planted signatures
//   bench_multi <module file>   60 unique signatures sampled from that file
#include "RuntimePattern.hpp"
#include "multi_scan.hpp"
#include <chrono>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

template <class F> static double ms(F f) {
    const auto t = std::chrono::steady_clock::now();
    f();
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t).count();
}

static std::vector<uint8_t> load(const char* path) {
    std::vector<uint8_t> v;
    if (FILE* f = fopen(path, "rb")) {
        uint8_t chunk[65536];
        for (size_t n; (n = fread(chunk, 1, sizeof chunk, f)) > 0;) v.insert(v.end(), chunk, chunk + n);
        fclose(f);
    }
    return v;
}

int main(int argc, char** argv) {
    std::mt19937 rng(5);
    std::vector<uint8_t> mod;
    if (argc > 1) {
        mod = load(argv[1]);
        if (mod.size() < 1 << 16) { printf("can't read %s\n", argv[1]); return 1; }
    } else {
        mod.resize(96 << 20);
        for (auto& b : mod) b = static_cast<uint8_t>(rng());
    }

    // Signatures from the back 3/4 of the module, kept only if unique, so every scan is a long one
    std::vector<patterns::RuntimePattern> owned;
    while (owned.size() < 60) {
        const size_t off = mod.size() / 4 + rng() % (mod.size() * 3 / 4 - 64);
        std::string s;
        char hex[4];
        for (int k = 0; k < 16; ++k) {
            if (k >= 3 && k <= 6) s += "? ";
            else { snprintf(hex, sizeof hex, "%02X ", mod[off + k]); s += hex; }
        }
        patterns::RuntimePattern p(s.c_str());
        if (p.find<const uint8_t*>(mod.data(), mod.size()) == mod.data() + off) owned.push_back(std::move(p));
    }
    std::vector<const patterns::Pattern*> pats;
    for (auto& p : owned) pats.push_back(&p);

    const unsigned threads = std::thread::hardware_concurrency();
    printf("%zu signatures, %.0f MB module, %u hardware threads\n", pats.size(), mod.size() / 1048576.0, threads);
    std::vector<void*> want, got;
    const auto run = [&](const char* name, auto&& f) {
        double best = 1e9;
        for (int r = 0; r < 3; ++r) best = std::min(best, ms([&] { f(); }));
        printf("  %-34s %8.1f ms  %s\n", name, best, got == want ? "" : "RESULTS DIFFER");
    };
    run("sequential (find() per pattern)", [&] { multi::sequential(mod.data(), mod.size(), pats, want); got = want; });
    run("chunked, 1 thread", [&] { multi::chunked(mod.data(), mod.size(), pats, got, 1); });
    run("parallel per pattern", [&] { multi::per_pattern(mod.data(), mod.size(), pats, got, threads); });
    run("chunked, all threads", [&] { multi::chunked(mod.data(), mod.size(), pats, got, threads); });
}
