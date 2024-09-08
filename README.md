# Pattern Scanning

#### Classes
- Pattern (base class)
- RuntimePattern
- CompileTimePattern
- XORPattern

RuntimePattern will allocate the pattern & mask with std::vectors default allocator along with leaving the pattern string in the binary.

CompileTimePattern creates the pattern & mask during compile time and stored in a std::array. This means the data is in the binaries module, and no pattern string left.

XORPattern creates the pattern & mask along with a keys array during compile time. Pattern stored is XOR'd bytes, otherwise it acts just the same as the CompileTimePattern. (the pattern() method however will return the XOR'd pattern, access the original bytes with the [] operator)

If using C++20 there is a user defined literal for the compile time pattern. 

#### Pattern Flags:
- d: Dereference from the found address, or found address + offset ( addr + size + relative address )
- r: Read the relative value at the address, or at the address + offset (not used on arm)
- a: Perform a byte aligned scan for a faster scan. 4 byte alignment x32, 8 byte alignment x64 (rather than byte by byte scan)
- x: This one is used inside of the pattern itself, to show where the offset is at (start address of what we want to capture). This can be followed by a 1/2/4 or 8 for the size of the operand when doing /r or /d


#### Examples:
```c++
// Scan will read the relative value from the X offset as 4 bytes
constexpr auto compiletime_pattern = "AB CC 11 22 33 44 AB 6D X4 EF BE AD DE /r"_ctpattern;
// Scan will read the address from where the marked X is pointed to (defaults as a relative address), and perform the scan byte aligned (4 - 32bit, 8 - 64bit)
// This also uses the instruction len (notice 4 after X). This tells it during the dereference to start the RIP after the E8 instruction
constexpr auto xor_pattern = "FE ED FA CE E8 X4 ? ? ? ? EF BE AD DE /da"_xorpattern;
// Scan will read the address from where the marked X is pointed to (as a single byte; i.e. short jump)
auto runtime_pattern = "BA BE CA FE 72 X1 ? 11 22 /d"_rtpattern
```
