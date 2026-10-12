# Tests & benchmarks

`tests/` is a separate CMake project (the library itself stays header-only):
```sh
cmake -S tests -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
./build/bench_scan  [module file]   # single-pattern speed; with a file, 40 real signatures sampled from it
./build/bench_multi [module file]   # many patterns: find() per pattern vs find_all vs threaded
```
- `test_patterns`: edge cases, fuzzing against a naive scanner, per-definition XOR keys. Also built with `PATTERNS_NO_SIMD`.
- `test_artifacts_*`: every compile-time pattern type (macros, and C++20 literals) must leave no pattern text in its binary, and the XOR ones no plaintext bytes, words or masks. All patterns are scanned from one function, as in a project's signature file, and built at each optimization level (`-O0`..`-O3`, `-Os`; MSVC `/Od /O1 /O2`) plus LTO, with debug info, as C++17 and C++20: optimizers fold constants differently at each.
- `test_cpp17`: the macro path.
- `test_arm`: ArmPattern encodings checked against clang's assembler (concrete instructions must encode exactly, wildcard patterns must match / not match), line formats, RuntimeArmPattern parsing the same, and `/d` resolution. On Apple arm64 it also re-assembles its tables and resolves `/d` on linker-relocated ADRP/ADD/LDR/BL code.
- `example_usage`: usage styles 3-5 from [usage.md](usage.md) against a module that has to be decrypted first, logging each result as `[count] name address (rebased address)`.
- `test_tls` (Windows): style 6, `find_all` run from a TLS callback over the executable's own image.
- `multi_scan.hpp`: other multi-pattern strategies (per-pattern threads, chunks over threads) for the benchmark.
