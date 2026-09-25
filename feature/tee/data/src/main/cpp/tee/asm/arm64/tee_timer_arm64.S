.text
.align 2
.global tee_arm64_read_cntvct
.type tee_arm64_read_cntvct, %function
tee_arm64_read_cntvct:
    isb
    mrs x0, cntvct_el0
    ret

.global tee_arm64_read_cntfrq
.type tee_arm64_read_cntfrq, %function
tee_arm64_read_cntfrq:
    isb
    mrs x0, cntfrq_el0
    ret
