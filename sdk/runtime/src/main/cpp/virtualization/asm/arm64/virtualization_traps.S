.text
.align 2
.global virtualization_arm64_read_cntvct
.type virtualization_arm64_read_cntvct, %function
virtualization_arm64_read_cntvct:
    isb
    mrs x0, cntvct_el0
    ret

.global virtualization_arm64_read_cntfrq
.type virtualization_arm64_read_cntfrq, %function
virtualization_arm64_read_cntfrq:
    isb
    mrs x0, cntfrq_el0
    ret

.global virtualization_arm64_getpid_syscall
.type virtualization_arm64_getpid_syscall, %function
virtualization_arm64_getpid_syscall:
    mov x8, #172
    svc #0
    ret
