BITS 64

global _start
extern kernel_main

section .text
_start:
    lea rsp, [stack_top]
    and rsp, -16
    call kernel_main

.hang:
    cli
    hlt
    jmp .hang

section .bss
align 16
stack_bottom:
    resb 65536
stack_top:
