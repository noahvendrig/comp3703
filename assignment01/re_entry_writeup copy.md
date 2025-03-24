Using Ghidra to first inspect the program, we can see that the functions of interest are `main`, `auth`, and `print_flag`.

We want to find original entry point
```bash
user1@comp3703:~/assignment01$ readelf --wide re_entry -h
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x55e0a0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          15400 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 29
```

We can see the entry point is `0x55e0a0`. this is `val4` in `entry.s` template (from lab03).
We need to dissassemble using objdump:

```bash
user1@comp3703:~/assignment01$ objdump --wide re_entry -dj .text
..... [some output omitted] .......
000000000055eaaf <print_flag>:
  55eaaf:       55                      push   %rbp
  55eab0:       48 89 e5                mov    %rsp,%rbp
  55eab3:       b8 00 00 00 00          mov    $0x0,%eax
  55eab8:       e8 65 ff ff ff          call   55ea22 <compute_key>
  55eabd:       8b 05 85 26 00 00       mov    0x2685(%rip),%eax        # 561148 <authenticated>
  55eac3:       85 c0                   test   %eax,%eax
  55eac5:       74 58                   je     55eb1f <print_flag+0x70>
  55eac7:       8b 05 37 26 00 00       mov    0x2637(%rip),%eax        # 561104 <seed>
  55eacd:       3d 90 29 67 bb          cmp    $0xbb672990,%eax
  55ead2:       75 4b                   jne    55eb1f <print_flag+0x70>
  55ead4:       8b 15 a6 25 00 00       mov    0x25a6(%rip),%edx        # 561080 <len>
  55eada:       48 8b 05 5f 26 00 00    mov    0x265f(%rip),%rax        # 561140 <key_str>
  55eae1:       41 89 d0                mov    %edx,%r8d
  55eae4:       b9 08 00 00 00          mov    $0x8,%ecx
  55eae9:       48 8d 15 b0 25 00 00    lea    0x25b0(%rip),%rdx        # 5610a0 <pt>
  55eaf0:       48 8d 35 e9 25 00 00    lea    0x25e9(%rip),%rsi        # 5610e0 <ct>
  55eaf7:       48 89 c7                mov    %rax,%rdi
  55eafa:       e8 87 f6 ff ff          call   55e186 <decrypt>
  55eaff:       48 8d 05 9a 25 00 00    lea    0x259a(%rip),%rax        # 5610a0 <pt>
  55eb06:       48 89 c6                mov    %rax,%rsi
  55eb09:       48 8d 05 40 05 00 00    lea    0x540(%rip),%rax        # 55f050 <_IO_stdin_used+0x50>
  55eb10:       48 89 c7                mov    %rax,%rdi
  55eb13:       b8 00 00 00 00          mov    $0x0,%eax
  55eb18:       e8 13 f5 ff ff          call   55e030 <printf@plt>
  55eb1d:       eb 14                   jmp    55eb33 <print_flag+0x84>
  55eb1f:       48 8d 05 2e 05 00 00    lea    0x52e(%rip),%rax        # 55f054 <_IO_stdin_used+0x54>
  55eb26:       48 89 c7                mov    %rax,%rdi
  55eb29:       b8 00 00 00 00          mov    $0x0,%eax
  55eb2e:       e8 fd f4 ff ff          call   55e030 <printf@plt>
  55eb33:       bf 00 00 00 00          mov    $0x0,%edi
  55eb38:       e8 33 f5 ff ff          call   55e070 <exit@plt>
```
We can see `print_flag` function is located at `0x55eaaf`. It compares the content of memory address `0x561148` (`authenticated`) with itself through the `test` instruction. To proceed through the program, we must set `authenticated` to a value that is not `0x0`, so we will choose `0x1`. Hence we need: `<val1>=0x561148`, `<val2>=0x1`,`<val3>=0x55eaaf` and `<val4>=0x55e0a0`. 
```x86asm
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
    mov dword [0x561148], 0x1    ; set key to the correct value 
    mov rbx, 0x55eaaf               ; address of win() function 
    call rbx                      ; call the win() function

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

    push 0x55e0a0 ; replace <val4> with the original entry point
    ret 
```

finding addresses for `print_flag`, `authenticated`, and `seed` were found using Ghidra, but can also be found in the `.text` and `.bss` sections:  `objdump re_entry.elf -dj .text --wide` and `objdump injected.elf -dj .bss --wide`


use injected code to set  `authenticated` to `1` and set `seed` to `0xbb672990` (same as `-0x4498d670` which the code is looking for ). then we can call `print_flag`, to print the flag (since the program now will now think that the user has been authenticated). We also note that the the function takes two 8 byte params, in `RDI` and `RSI` (ghidra). So we must allocate memory for this and store the addresses in `rdi`, `rsi`:

```x86asm
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
```
The stack was out of alignment after the mmap calls but i still get "[1]+ Stopped   injected.elf"...



!! also i tried disabling the anti_debug but then the program was having a seg fault at the end of the `int2hex` function. i have no idea why.