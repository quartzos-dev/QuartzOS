BITS 64

global task_switch

; void task_switch(uint64_t *old_rsp, uint64_t new_rsp)
task_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov [rdi], rsp
    mov rsp, rsi

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
