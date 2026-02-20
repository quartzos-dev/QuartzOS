BITS 64

global user_enter_ring3
global user_return_from_syscall

extern g_user_saved_rsp

; void user_enter_ring3(uint64_t entry, uint64_t user_stack)
; rdi = entry, rsi = user_stack
user_enter_ring3:
    mov [rel g_user_saved_rsp], rsp

    mov ax, 0x23
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push qword 0x23
    push rsi
    pushfq
    or qword [rsp], 0x200
    push qword 0x1b
    push rdi
    iretq

user_return_from_syscall:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov rsp, [rel g_user_saved_rsp]
    ret
