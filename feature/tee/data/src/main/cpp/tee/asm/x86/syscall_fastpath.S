.text
.align 4
.global tee_asm_syscall6
.type tee_asm_syscall6, @function
tee_asm_syscall6:
    pushl %ebp
    pushl %edi
    pushl %esi
    pushl %ebx
    movl 20(%esp), %eax
    movl 24(%esp), %ebx
    movl 28(%esp), %ecx
    movl 32(%esp), %edx
    movl 36(%esp), %esi
    movl 40(%esp), %edi
    movl 44(%esp), %ebp
    int $0x80
    popl %ebx
    popl %esi
    popl %edi
    popl %ebp
    ret
