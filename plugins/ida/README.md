# PatternScanner for IDA

Search an IDA database with PatternScanner patterns, the way Search > Sequence of bytes works. IDA 9.x on Windows,
macOS and Linux.

- **Shift-Alt-B** (also Search > PatternScanner pattern...): enter a byte pattern (`48 8B 05 X4 ? ? ? ? /d`) or
  arm64 assembly (one instruction per line, `X` before the one to resolve, flags last). Options:
  - **Find all occurrences**: lists every match with its result, segment, function and instruction. Enter or
    double-click jumps to the match.
  - **Search up**: the previous match instead of the next one.
  - **From cursor**: start at the cursor rather than at the start (or end, searching up) of the database.
- **Ctrl-Shift-B**: repeat the last search from the cursor.

A single search jumps to the match and prints the result (after X and /d /r) to the output window.

/d, /r, `X<len>` and /a follow the database's architecture, not the machine running IDA: byte patterns in an
arm64 database decode /d as arm64 instructions, and /a steps 4 bytes in 32-bit databases. Matches never span
segments or uninitialized bytes.

## Build

Needs the [IDA SDK](https://github.com/HexRaysSA/ida-sdk) with [ida-cmake](https://github.com/allthingsida/ida-cmake)
(neither is part of this repo):
- GitHub checkout of the SDK: `git submodule update --init src/cmake`
- Zip SDK: `git clone https://github.com/allthingsida/ida-cmake <sdk>/ida-cmake`

```sh
cmake -S plugins/ida -B build-ida -DIDASDK=/path/to/ida-sdk
cmake --build build-ida --config Release
```
The plugin (`pattern_scanner.dll` / `.so` / `.dylib`) is written to `$IDABIN/plugins`; IDABIN defaults to the SDK's
`bin` folder. Copy it to your IDA user plugins folder (`%APPDATA%\Hex-Rays\IDA Pro\plugins` on Windows,
`~/.idapro/plugins` on macOS and Linux), or pass `-DIDABIN=/path/to/ida` to build straight into IDA.

The SDK ships link libraries for MSVC on Windows, clang on macOS and **gcc on Linux**: on Linux, configure with
`-DCMAKE_CXX_COMPILER=g++` if your default compiler is clang.

## Test

`test/test_search.cpp` runs the plugin's search (`search.hpp`) through idalib on small x86, x64 and arm64 ELF files
assembled from `test/*.S` with clang and lld. It needs an IDA install with idalib and a license:
```sh
cmake -S plugins/ida -B build-ida -DIDASDK=/path/to/ida-sdk -DIDA_INSTALL_DIR=/path/to/ida
cmake --build build-ida --config Release
ctest --test-dir build-ida -C Release --output-on-failure
```
