.text
.align 2
.global tee_asm_syscall6
.type tee_asm_syscall6, %function
tee_asm_syscall6:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    svc #0
    ret
