.text
.globl _start
_start:
    ret
code_adrp:
    movz w9, #0x7777
    adrp x0, target_data
    add  x0, x0, :lo12:target_data
code_bl:
    movz w9, #0x6666
    bl   target_func
target_func:
    ret
// Two prologues: the first is a near miss for the STP/MOV pattern in test_search.cpp, the second matches it
near_miss:
    sub  sp, sp, #0x20
    stp  x29, x30, [sp, #0x10]
    add  x29, sp, #0x10
    mov  x19, x1
    mov  x0, x30
    ret
wanted:
    stp  x20, x19, [sp, #-0x20]!
    stp  x29, x30, [sp, #0x10]
    add  x29, sp, #0x10
    mov  x19, x1
    mov  x0, x30
    ret

.data
.balign 16
.zero 0x2340                                    // target_data in a later page, at a page offset
target_data: .quad 0x1122334455667788
