.intel_syntax noprefix

.global _start
_start:
    /* exit(42) */
    mov rdi, 42
    mov rax, 60
    syscall
