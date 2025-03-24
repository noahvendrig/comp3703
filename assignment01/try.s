BITS 64

SECTION .text
global main
 
main:
    ; mmap syscall to allocate 8 bytes rdi. 
    mov rax, 9      ;mmap syscall
    mov rdi, 0      ;not passing any pointer
    mov rsi, 8      ;length in bytes
    mov rdx, 3      ;read and write permissions
    mov r8, -1      ;fill with 0s
    mov r9, 0       ;no offset
    mov r10, 0x22   ;private and anonymous memory
    syscall
    ;

    mov rdi, rax             ; store allocated address in rdi

    ; mmap syscall to allocate 8 bytes rsi. 
    mov rax, 9      ;mmap syscall
    mov rdi, 0      ;not passing any pointer
    mov rsi, 8      ;length in bytes
    mov rdx, 3      ;read and write permissions
    mov r8, -1      ;fill with 0s
    mov r9, 0       ;no offset
    mov r10, 0x22   ;private and anonymous memory
    syscall
    ;

    mov rsi, rax             ; store allocated address in rsi
    ;

    mov dword [0x561148], 1    ; set authenticated to the correct value 
    mov dword [0x561104], 0xbb672990 ; set seed to correct value   


    ; stack alignment stuff
    push rbp
    mov rbp, rsp

    sub rsp, 0x30
    and rsp,0xfffffffffffffff0
    ;

    push rbx                        
    mov rbx, 0x55eaaf
    jmp rbx   
    ; mov rbx, 0x55e0a0
    ;jmp rbx             
                       
    ; pop rbx                          
    ;push 0x55e0a0 ; original entry point address                   
    ; ret