
SECTION .text
global main

main:
mov qword [0xgot_location_printf], 0xoriginal_value_.got.plt
    mov ebx 0xaddr_of_func
    jmp rbx

hello: db "hello world",33,10
len  : dd 13