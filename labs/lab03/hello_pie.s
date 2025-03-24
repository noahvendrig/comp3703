BITS 64

%define orig_entry    0x6aa0 ; replace <address1> with the original entry point 
%define payload_entry 0x822000 ; replace <address2> with the address of the injected code

SECTION .data
hello: db "Hello world!",10

SECTION .text
global main
 
main:
    ; Save registers.  
    ; We are being a bit conservative here -- depending on the syscalls,
    ; not all registers need to be saved.  

    push rax
    push rbx 
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9 
    push r10  
    push r11
    push r12
    push r13
    push r14
    push r15

    ; make a write syscall to print hello 
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel hello]    ; always use relative addressing to ensure this code is portable 
    mov rdx, 13
    syscall

    ; restore registers
    pop r15
    pop r14
    pop r13 
    pop r12 
    pop r11
    pop r10 
    pop r9
    pop r8 
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx 
    pop rax 

    ; Since the target is a PIE binary, the actual
    ; entry point will be relocated to a random address 
    ; when the program starts, so we can't use orig_entry  
    ; directly. Instead, calculate its address relative 
    ; to the start of the payload (the main label above)
    jmp main+(orig_entry-payload_entry)
    
