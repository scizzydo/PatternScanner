# Pattern Scanning

#### Classes
- Pattern (base class)
- RuntimePattern
- CompileTimePattern

RuntimePattern will allocate the pattern & mask with std::vectors default allocator along with leaving the pattern string in the binary.

CompileTimePattern creates the pattern & mask during compile time and stored in a std::array. This means the data is in the binaries module, and no pattern string left.

If using C++20 there is a user defined literal for the compile time pattern. 