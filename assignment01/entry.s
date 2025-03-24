BITS 64

SECTION .text
global main
 
main:
    ; Save registers.  
    ; We are being a bit conservative here -- depending on the function you call,
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

    ; replace <val1>,<val2>,<val3> with appropriate values
    ;mov dword [0x404034], 0x5924    ; set key to the correct value 
    ;mov rbx, 0x401126               ; address of win() function 
    ;call rbx                      ; call the win() function

    mov dword [0x561148], 0x1    ; set authenticated to the correct value 
    mov dword [0x561104], 0xbb672990 ; set seed to correct value 
    
    push rbp
    mov rbp, rsp

    sub rsp, 0x30
    and rsp, 0xfffffffffffffff0 ; align to 16 byte boundary

    mov rbx, 0x55eaaf                
    call rbx         

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

    push 0x401040 ; replace <val4> with the original entry point
    ret 
    
