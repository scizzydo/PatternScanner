// Shared by the x86 and x64 fixtures (see CMakeLists.txt): same layout, different databases
.intel_syntax noprefix
.text
.globl _start
_start:
    ret
marker1: .byte 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22
code_call:
    call target_func
    .byte 0xA3, 0xB4
marker2: .byte 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22
.balign 8
    .byte 0x90, 0x90, 0x90, 0x90
unaligned8: .byte 0xC7, 0xC8, 0xC9, 0xCA      // 4 mod 8: found by /a in x86 databases only
#ifdef __x86_64__
code_lea:
    lea rax, [rip + target_data]
    .byte 0xCC, 0xCC, 0xA1, 0xB2
#endif
marker3: .byte 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22
target_func:
    ret

.data
.balign 16
target_data: .quad 0x1122334455667788

.bss
.balign 16
zeros: .zero 64                                 // uninitialized: never matched
