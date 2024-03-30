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

*Development on arm is very new and being tested as I go, if issues are found please give a working example of bytes around the area needed*

*You must define the patterns::detail::ldissasm if you intend to use without insn_len_*
```c++
size_t patterns::ldisasm(const void* buffer, size_t buffer_size) {
    // Just return 0 if not using the dereference, otherwise place in the code from another library/source to obtain the instructions length
    return 0;
}
```

#### Examples:
```c++
// Scan will read the relative value from the X offset as 4 bytes
constexpr auto compiletime_pattern = "AB CC 11 22 33 44 AB 6D X EF BE AD DE /r4"_ctpattern;
// Scan will read the address from where the marked X is pointed to (defaults as a relative address), and perform the scan byte aligned (4 - 32bit, 8 - 64bit)
// This also uses the instruction len (notice 9 after X). This tells it during the dereference to start the RIP after the E8 instruction
constexpr auto xor_pattern = "FE ED FA CE E8 X9 ? ? ? ? EF BE AD DE /da"_xorpattern;
// Scan will read the address from where the marked X is pointed to (as a single byte; i.e. short jump)
auto runtime_pattern = "BA BE CA FE 72 X ? 11 22 /d1"_rtpattern
```