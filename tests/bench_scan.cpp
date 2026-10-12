// Single-pattern scan speed.
//   bench_scan                 synthetic 64 MB of random bytes
//   bench_scan <module file>   also 40 real signatures sampled from that file (e.g. a game exe or dylib)
#include <PatternScanner/RuntimePattern.hpp>
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

// 16 bytes from the module with a rel32 wildcarded, like "48 8B 05 ? ? ? ? 48 85 C0 ..."
static std::string signature_at(const std::vector<uint8_t>& d, size_t off) {
    std::string s;
    char hex[4];
    for (int k = 0; k < 16; ++k) {
        if (k >= 3 && k <= 6) s += "? ";
        else { snprintf(hex, sizeof hex, "%02X ", d[off + k]); s += hex; }
    }
    return s;
}

int main(int argc, char** argv) {
    {
        std::vector<uint8_t> buf(64 << 20);
        std::mt19937 rng(1);
        for (auto& b : buf) b = static_cast<uint8_t>(rng());
        const uint8_t sig[] = { 0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48, 0x85, 0xC0, 0x74, 0x10 };
        memcpy(&buf[buf.size() - 4096], sig, sizeof sig);
        auto p = "48 8B 05 ? ? ? ? 48 85 C0 74 10"_rtpattern;
        double best = 1e9;
        for (int r = 0; r < 5; ++r) best = std::min(best, ms([&] { p.find<void*>(buf.data(), buf.size()); }));
        printf("synthetic: 64 MB random, match at end      %7.2f ms  (%.1f GB/s)\n", best, 64 / 1024.0 / (best / 1000));
    }
    if (argc > 1) {
        const auto d = load(argv[1]);
        if (d.size() < 1024) { printf("can't read %s\n", argv[1]); return 1; }
        std::mt19937 rng(42);
        double total = 0;
        size_t scanned = 0;
        for (int s = 0; s < 40; ++s) {
            const size_t off = rng() % (d.size() - 64);
            patterns::RuntimePattern p(signature_at(d, off).c_str());
            const uint8_t* hit = nullptr;
            total += ms([&] { hit = p.find<const uint8_t*>(d.data(), d.size()); });
            scanned += hit - d.data() + 16;   // signatures can match earlier than where they were sampled
        }
        printf("real: 40 signatures from %s (%.1f MB)  %7.2f ms  (%.1f GB/s)\n", argv[1], d.size() / 1048576.0, total,
               scanned / 1073741824.0 / (total / 1000));
    }
}
