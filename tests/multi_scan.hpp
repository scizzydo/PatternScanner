#pragma once
// Strategies for resolving many patterns over one module, for comparison with patterns::find_all.
// Test/benchmark code, not part of the library. Built only on the public Pattern API (match / resolve).
#include "Pattern.hpp"
#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>

namespace multi {
    // One full scan per pattern, one after another (what a list of find() calls does)
    inline void sequential(const uint8_t* start, size_t size, const std::vector<const patterns::Pattern*>& pats, std::vector<void*>& out) {
        out.assign(pats.size(), nullptr);
        for (size_t i = 0; i < pats.size(); ++i)
            out[i] = pats[i]->find(start, size);
    }

    // One full scan per pattern, patterns spread over threads
    inline void per_pattern(const uint8_t* start, size_t size, const std::vector<const patterns::Pattern*>& pats, std::vector<void*>& out,
                            unsigned threads = std::thread::hardware_concurrency()) {
        out.assign(pats.size(), nullptr);
        std::atomic<size_t> next{0};
        std::vector<std::thread> pool;
        for (unsigned t = 0; t < std::max(1u, threads); ++t)
            pool.emplace_back([&] {
                for (size_t i; (i = next++) < pats.size();)
                    out[i] = pats[i]->find(start, size);
            });
        for (auto& t : pool) t.join();
    }

    // Module split into cache-sized chunks; every pattern runs over a chunk while it's hot in cache, so the module
    // is read from RAM once instead of once per pattern. Chunks are spread over threads; threads = 1 runs inline.
    inline void chunked(const uint8_t* start, size_t size, const std::vector<const patterns::Pattern*>& pats, std::vector<void*>& out,
                        unsigned threads = std::thread::hardware_concurrency(), size_t chunk = 1 << 20) {
        size_t overlap = 0;
        for (auto p : pats) overlap = std::max<size_t>(overlap, p->length());
        // Lowest match per pattern; chunks finish out of order, so keep the minimum rather than the first found
        std::vector<std::atomic<uintptr_t>> best(pats.size());
        for (auto& b : best) b = UINTPTR_MAX;
        const size_t chunks = (size + chunk - 1) / chunk;
        std::atomic<size_t> next{0};
        auto work = [&] {
            for (size_t c; (c = next++) < chunks;) {
                const uint8_t* s = start + c * chunk;
                // Overlap into the next chunk so matches straddling the boundary are found
                const size_t n = std::min(chunk + overlap - 1, size - c * chunk);
                for (size_t i = 0; i < pats.size(); ++i) {
                    if (best[i].load(std::memory_order_relaxed) < reinterpret_cast<uintptr_t>(s))
                        continue;   // an earlier chunk already matched
                    if (auto hit = pats[i]->match(s, n)) {
                        uintptr_t v = reinterpret_cast<uintptr_t>(hit), cur = best[i];
                        while (v < cur && !best[i].compare_exchange_weak(cur, v)) {}
                    }
                }
            }
        };
        if (threads <= 1) {
            work();
        } else {
            std::vector<std::thread> pool;
            for (unsigned t = 0; t < threads; ++t) pool.emplace_back(work);
            for (auto& t : pool) t.join();
        }
        out.assign(pats.size(), nullptr);
        for (size_t i = 0; i < pats.size(); ++i)
            if (best[i] != UINTPTR_MAX)
                out[i] = pats[i]->resolve(reinterpret_cast<const uint8_t*>(best[i].load()), start + size);
    }
}
