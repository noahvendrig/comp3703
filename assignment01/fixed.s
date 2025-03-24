BITS 64

SECTION .text
global main

main:
    ; Stack alignment
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    and rsp, 0xFFFFFFFFFFFFFFF0  ; Align stack

    ; === First mmap Call (Allocate 8 bytes for rdi) ===
    mov rax, 9               ; syscall number for mmap
    xor rdi, rdi             ; addr = NULL (let kernel choose)
    mov rsi, 8               ; length = 8 bytes
    mov rdx, 3               ; PROT_READ | PROT_WRITE (0x1 | 0x2)
    mov r10, 0x22            ; MAP_PRIVATE | MAP_ANONYMOUS (0x2 | 0x20)
    xor r8, r8               ; fd = -1 (ignored for anonymous mapping)
    xor r9, r9               ; offset = 0
    syscall
    test rax, rax            ; Check for error (-1)
    js error_exit
    mov rdi, rax             ; store allocated address in rdi

    ; === Second mmap Call (Allocate 8 bytes for rsi) ===
    mov rax, 9               ; syscall number for mmap
    xor rdi, rdi             ; addr = NULL (let kernel choose)
    mov rsi, 8               ; length = 8 bytes
    mov rdx, 3               ; PROT_READ | PROT_WRITE (0x1 | 0x2)
    mov r10, 0x22            ; MAP_PRIVATE | MAP_ANONYMOUS (0x2 | 0x20)
    xor r8, r8               ; fd = -1
    xor r9, r9               ; offset = 0
    syscall
    test rax, rax            ; Check for error (-1)
    js error_exit
    mov rsi, rax             ; store allocated address in rsi

    ; === Set authenticated and seed correctly ===
    mov dword [0x561148], 1    ; set authenticated to the correct value 
    mov dword [0x561104], 0xbb672990 ; set seed to correct value   

    ; === Call print_flag ===
    mov rax, 0x55eaaf    ; Address of print_flag
    call rax

error_exit:
    mov rdi, 1           ; Exit status 1 (error)
    mov rax, 60          ; syscall number for exit
    syscall
