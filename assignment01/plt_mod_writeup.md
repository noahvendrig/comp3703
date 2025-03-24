We can see` plt_mod` is a PIE binary, which plt hijacking works with.

```bash
user1@comp3703:~/assignment01$ checksec plt_mod
[*] '/home/user1/assignment01/plt_mod'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

Lets examine the code:
```bash
user1@comp3703:~/assignment01$ objdump -M intel -dj .text  plt_mod
0000000000001c2e <print_flag>:
    1c2e:       f3 0f 1e fa             endbr64 
    1c32:       55                      push   rbp
    1c33:       48 89 e5                mov    rbp,rsp
    1c36:       48 83 ec 10             sub    rsp,0x10
    1c3a:       48 89 7d f8             mov    QWORD PTR [rbp-0x8],rdi
    1c3e:       48 8b 05 8b 24 00 00    mov    rax,QWORD PTR [rip+0x248b]        # 40d0 <key>
    1c45:       48 89 c7                mov    rdi,rax
    1c48:       e8 0c ff ff ff          call   1b59 <compute_key>
    1c4d:       8b 0d cd 23 00 00       mov    ecx,DWORD PTR [rip+0x23cd]        # 4020 <len>
    1c53:       48 8b 05 76 24 00 00    mov    rax,QWORD PTR [rip+0x2476]        # 40d0 <key>
    1c5a:       48 8b 55 f8             mov    rdx,QWORD PTR [rbp-0x8]
    1c5e:       41 89 c8                mov    r8d,ecx
    1c61:       b9 08 00 00 00          mov    ecx,0x8
    1c66:       48 8d 35 d3 23 00 00    lea    rsi,[rip+0x23d3]        # 4040 <ct>
    1c6d:       48 89 c7                mov    rdi,rax
    1c70:       e8 34 f6 ff ff          call   12a9 <decrypt>
    1c75:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
    1c79:       48 89 c6                mov    rsi,rax
    1c7c:       48 8d 05 f9 03 00 00    lea    rax,[rip+0x3f9]        # 207c <_IO_stdin_used+0x7c>
    1c83:       48 89 c7                mov    rdi,rax
    1c86:       b8 00 00 00 00          mov    eax,0x0
    1c8b:       e8 e0 f4 ff ff          call   1170 <printf@plt>
    1c90:       90                      nop
    1c91:       c9                      leave  
    1c92:       c3                      ret    

0000000000001c93 <main>:
    1c93:       f3 0f 1e fa             endbr64 
    1c97:       55                      push   rbp
    1c98:       48 89 e5                mov    rbp,rsp
    1c9b:       48 8d 05 de 03 00 00    lea    rax,[rip+0x3de]        # 2080 <_IO_stdin_used+0x80>
    1ca2:       48 89 c7                mov    rdi,rax
    1ca5:       e8 66 f4 ff ff          call   1110 <puts@plt>
    1caa:       b8 00 00 00 00          mov    eax,0x0
    1caf:       5d                      pop    rbp
    1cb0:       c3                      ret  
```
Similarly to `got_mod`, we can see that `main` function only makes a call to `puts@plt`, so we should investigate this for our exploit. We also note that address of `print_flag` is `0x1c2e`

The exploitation will involve replacing a virtual address in the binary, with a jump to the injected code. hence we need to know the address for `puts@plt`:

```bash
user1@comp3703:~/assignment01$ objdump -M intel -dj .plt.sec plt_mod | grep puts -A 2
0000000000001110 <puts@plt>:
    1110:       f3 0f 1e fa             endbr64 
    1114:       f2 ff 25 65 2e 00 00    bnd jmp QWORD PTR [rip+0x2e65]        # 3f80 <puts@GLIBC_2.2.5>
    111b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
```

No we know we need to overwrite the instruction at `0x1110`.

Next we need to craft the injection assembly code. from Ghidra we can see that `print_flag` takes a parameter `char*    RDI:8     pt`. Hence we need to allocate 8 bytes of memory and store the address in `rdi`. Before implementing all this we'll check that our approach will work - by using hello world example from lab03.

```x86asm
BITS 64

;%define orig_entry    0x11c0 ; replace <address1> with the original entry point
;%define payload_entry 0x806000 ; replace <address2> with the address of the injected code

SECTION .text
global main

main:
    ; stack alignment stuff THAT BROKE THE PROGRAM
    ;push rbp
    ;mov rbp, rsp

    ;sub rsp, 0x30
    ;and rsp,0xfffffffffffffff0
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

    ;mov rbx, 0x1c2e             ; address of print_flag() function 
    ;call rbx                    ; call the print_flag() function
    ;jmp main+(orig_entry-payload_entry)

    ; HELLO WORLD
    mov rax,1            ; sys_write
    mov rdi,1            ; stdout
    lea rsi,[rel hello]  ; hello
    mov edx,[rel len]    ; len
    syscall
    ;

    pop rbx                     ; 
    ret

hello: db "hello world",33,10
len  : dd 13
```

Now compile and run:
```bash
user1@comp3703:~/assignment01$ nasm -f bin -o plt.bin plt.s

user1@comp3703:~/assignment01$ python3 ./elfins.py plt_mod plt.bin -o hijack_plt --patchaddress 0x1110
Reusing a NOTE segment for the injected code.
Creating a new section header for .injected
Code injected at offset: 0x6000, virtual address 0x806000. 
Address 0x1110 patched to jump to injected code.
Modified binary saved to hijack_plt

user1@comp3703:~/assignment01$ ./hijack_plt
hello world!
```

We can see that it works! now we need to adapt the injection code to call the `print_flag` function

Since this is a PIE binary, everything is shifted by a static offset. We need to figure it out. 
In the dissassembled code, the address for `main` function is `0x1c93`.
We can run debugger to see the address when program is run:
```bash
gdb plt_mod
break main
...
→ 0x555555555c9b <main+0008>      lea    rax, [rip+0x3de]
```

Hence the new `main` function address is `0x555555555c93`. 
The difference between the two is `0x555555554000`.

We know the original `print_flag` function address is `0x1c2e`. We can calculate the live address using `0x1c2e + 0x555555554000` = `0x555555555C2E`. This is the address we will call in the code injection.

```x86asm
BITS 64

SECTION .text
global main

main:
    ; stack alignment stuff THAT BROKE THE PROGRAM in got_mod
    ;push rbp
    ;mov rbp, rsp

    ;sub rsp, 0x30
    ;and rsp,0xfffffffffffffff0
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
```

we compile and test the program, but we are getting a segmentation fault :(   
```bash
user1@comp3703:~/assignment01$ nasm -f bin -o plt.bin plt.s

user1@comp3703:~/assignment01$ python3 ./elfins.py plt_mod plt.bin -o hijack_plt --patchaddress 0x1110
Reusing a NOTE segment for the injected code.
Creating a new section header for .injected
Code injected at offset: 0x6000, virtual address 0x806000. 
Address 0x1110 patched to jump to injected code.
Modified binary saved to hijack_plt

user1@comp3703:~/assignment01$ ./hijack_plt
Segmentation fault (core dumped)
```

