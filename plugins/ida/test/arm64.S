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

.data
.balign 16
.zero 0x2340                                    // target_data in a later page, at a page offset
target_data: .quad 0x1122334455667788
