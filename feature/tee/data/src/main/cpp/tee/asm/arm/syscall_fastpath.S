.syntax unified
.text
.align 2
.global tee_asm_syscall6
.type tee_asm_syscall6, %function
tee_asm_syscall6:
    push {r4, r5, r7, lr}
    ldr r4, [sp, #16]
    ldr r5, [sp, #20]
    ldr ip, [sp, #24]
    mov r7, r0
    mov r0, r1
    mov r1, r2
    mov r2, r3
    mov r3, r4
    mov r4, r5
    mov r5, ip
    svc #0
    pop {r4, r5, r7, pc}
