BITS 64

SECTION .text
global main

main:
    ; stack alignment stuff THAT BROKE THE PROGRAM in got_mod
    push rbp
    mov rbp, rsp

    sub rsp, 0x30
    and rsp,0xfffffffffffffff0
    ;
    ; mmap syscall to allocate 8 bytes. 
    mov rax, 9      ;mmap syscall
    mov rdi, 0      ;not passing any pointer
    mov rsi, 8      ;length in bytes
    mov rdx, 3      ;read and write permissions
    mov r8, -1      ;fill with 0s
    mov r9, 0       ;no offset
    mov r10, 0x22   ;private and anonymous memory
    syscall
    ;

    mov rdi, rax             ; store allocated address in rdi since we know that unmask_flag expects it in rdi

    push rbx                    ;

    mov rbx, 0x555555555C2E             ; address of print_flag() function 
    call rbx                    ; call the print_flag() function

    pop rbx                    
    ret