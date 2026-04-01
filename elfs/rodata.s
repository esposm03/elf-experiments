.intel_syntax noprefix

.global _start
_start:
    /* exit(42) */
    mov rdi, qword ptr [rip+code]
    mov rax, 60
    syscall

.section .rodata
code:
    .8byte 42
