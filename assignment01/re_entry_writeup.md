
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

Now we compile it to binary using `nasm` and inject into `re_entry` using `elfins.py` (from lab03):
```bash
user1@comp3703:~/assignment01$ nasm -f bin -o entry_q2.bin entry.s
user1@comp3703:~/assignment01$ python3 elfins.py re_entry entry_q2.bin --patchentry
Reusing a NOTE segment for the injected code.
Creating a new section header for .injected
Code injected at offset: 0x5000, virtual address 0x805000. 
Patching entry point to 0x805000
Modified binary saved to injected.elf
```




---
```bash
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

compute_key located at 0x55ea22


```bash
000000000055ea22 <compute_key>:
  55ea22:       55                      push   %rbp
  55ea23:       48 89 e5                mov    %rsp,%rbp
  55ea26:       48 83 ec 20             sub    $0x20,%rsp
  55ea2a:       48 8d 05 70 fc ff ff    lea    -0x390(%rip),%rax        # 55e6a1 <start_protect>
  55ea31:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  55ea35:       48 8d 05 38 01 00 00    lea    0x138(%rip),%rax        # 55eb74 <end_protect>
  55ea3c:       48 89 45 e8             mov    %rax,-0x18(%rbp)
  55ea40:       b8 00 00 00 00          mov    $0x0,%eax
  55ea45:       e8 85 fc ff ff          call   55e6cf <anti_debug>
  55ea4a:       8b 05 b4 26 00 00       mov    0x26b4(%rip),%eax        # 561104 <seed>
  55ea50:       89 45 f4                mov    %eax,-0xc(%rbp)
  55ea53:       eb 0e                   jmp    55ea63 <compute_key+0x41>
  55ea55:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea59:       8b 00                   mov    (%rax),%eax
  55ea5b:       31 45 f4                xor    %eax,-0xc(%rbp)
  55ea5e:       48 83 45 f8 04          addq   $0x4,-0x8(%rbp)
  55ea63:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea67:       48 3b 45 e8             cmp    -0x18(%rbp),%rax
  55ea6b:       72 e8                   jb     55ea55 <compute_key+0x33>
  55ea6d:       48 8b 15 cc 26 00 00    mov    0x26cc(%rip),%rdx        # 561140 <key_str>
  55ea74:       8b 45 f4                mov    -0xc(%rbp),%eax
  55ea77:       48 89 d6                mov    %rdx,%rsi
  55ea7a:       89 c7                   mov    %eax,%edi
  55ea7c:       e8 ec fe ff ff          call   55e96d <int2hex>
  55ea81:       90                      nop
  55ea82:       c9                      leave
  55ea83:       c3                      ret
```
we're looking for e8 85 fc ff ff
The `.text` section starts at address `0x55e0a0` in virtual memory and at offset `0x10a0` in the file. Hence the address `0x55ea45` (where our jump instr of interest is located), is at offset `(0x55ea45 - 0x55e0a0 + 0x10a0) = 0x1A45` in the file. 


now we see
```bash
000000000055ea22 <compute_key>:
  55ea22:       55                      push   %rbp
  55ea23:       48 89 e5                mov    %rsp,%rbp
  55ea26:       48 83 ec 20             sub    $0x20,%rsp
  55ea2a:       48 8d 05 70 fc ff ff    lea    -0x390(%rip),%rax        # 55e6a1 <start_protect>
  55ea31:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  55ea35:       48 8d 05 38 01 00 00    lea    0x138(%rip),%rax        # 55eb74 <end_protect>
  55ea3c:       48 89 45 e8             mov    %rax,-0x18(%rbp)
  55ea40:       b8 00 00 00 00          mov    $0x0,%eax
  55ea45:       90                      nop
  55ea46:       90                      nop
  55ea47:       90                      nop
  55ea48:       90                      nop
  55ea49:       90                      nop
  55ea4a:       8b 05 b4 26 00 00       mov    0x26b4(%rip),%eax        # 561104 <seed>
  55ea50:       89 45 f4                mov    %eax,-0xc(%rbp)
  55ea53:       eb 0e                   jmp    55ea63 <compute_key+0x41>
  55ea55:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea59:       8b 00                   mov    (%rax),%eax
  55ea5b:       31 45 f4                xor    %eax,-0xc(%rbp)
  55ea5e:       48 83 45 f8 04          addq   $0x4,-0x8(%rbp)
  55ea63:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea67:       48 3b 45 e8             cmp    -0x18(%rbp),%rax
  55ea6b:       72 e8                   jb     55ea55 <compute_key+0x33>
  55ea6d:       48 8b 15 cc 26 00 00    mov    0x26cc(%rip),%rdx        # 561140 <key_str>
  55ea74:       8b 45 f4                mov    -0xc(%rbp),%eax
  55ea77:       48 89 d6                mov    %rdx,%rsi
  55ea7a:       89 c7                   mov    %eax,%edi
  55ea7c:       e8 ec fe ff ff          call   55e96d <int2hex>
  55ea81:       90                      nop
  55ea82:       c9                      leave
  55ea83:       c3                      ret
```




-------
lets examine decompiled code for print_flag:
```c
void print_flag(undefined8 usr_input,undefined8 param_2)

{
  compute_key(usr_input,param_2);
  if ((authenticated == 0) || (seed != -0x4498d670)) {
    printf("Nice try\n");
  }
  else {
    decrypt(key_str,ct,(size_t *)pt,(uchar *)0x8,(ulong)len);
    printf("%s\n",pt);
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

finding addresses for `print_flag`, `authenticated`, and `seed` were found using Ghidra, but can also be found in the `.text` and `.bss` sections:  `objdump re_entry.elf -dj .text --wide` and `objdump injected.elf -dj .bss --wide`


use injected code to set  `authenticated` to `1` and set `seed` to `0xbb672990` (same as `-0x4498d670` which the code is looking for ). then we can call `print_flag`, to print the flag (since the program now will now think that the user has been authenticated).

```x86asm
BITS 64

SECTION .text
global main
 
main:
    ; stack alignment stuff
    push rbp
    mov rbp, rsp

    sub rsp, 0x30
    and rsp,0xfffffffffffffff0
    ;

    mov dword [0x561148], 1    ; set authenticated to the correct value 
    mov dword [0x561104], 0xbb672990 ; set seed to correct value   
    push rbx                        

    mov rbx, 0x55eaaf ; addr for print_flag
    jmp rbx                
    ;call rbx                        
    ;pop rbx                          
    ;push 0x401040                   
    ;ret
```

testing it out:
```bash
user1@comp3703:~/assignment01$ python3 elfins.py re_entry entry_q2.bin --patchentry
Reusing a NOTE segment for the injected code.
Creating a new section header for .injected
Code injected at offset: 0x5000, virtual address 0x805000. 
Patching entry point to 0x805000
Modified binary saved to injected.elf
user1@comp3703:~/assignment01$ ./injected.elf

[1]+  Stopped                 ./injected.elf
```
we've implemented the stack alignment, so it cant be that the stack is out of alignment.. i have no idea why this is happening.


we can try to disable the anti debug function in `compute_key` to debug (and figure out whats going wrong). 
`compute_key` function:
```bash
000000000055ea22 <compute_key>:
  55ea22:       55                      push   %rbp
  55ea23:       48 89 e5                mov    %rsp,%rbp
  55ea26:       48 83 ec 20             sub    $0x20,%rsp
  55ea2a:       48 8d 05 70 fc ff ff    lea    -0x390(%rip),%rax        # 55e6a1 <start_protect>
  55ea31:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  55ea35:       48 8d 05 38 01 00 00    lea    0x138(%rip),%rax        # 55eb74 <end_protect>
  55ea3c:       48 89 45 e8             mov    %rax,-0x18(%rbp)
  55ea40:       b8 00 00 00 00          mov    $0x0,%eax
  55ea45:       e8 85 fc ff ff          call   55e6cf <anti_debug>
  55ea4a:       8b 05 b4 26 00 00       mov    0x26b4(%rip),%eax        # 561104 <seed>
  55ea50:       89 45 f4                mov    %eax,-0xc(%rbp)
  55ea53:       eb 0e                   jmp    55ea63 <compute_key+0x41>
  55ea55:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea59:       8b 00                   mov    (%rax),%eax
  55ea5b:       31 45 f4                xor    %eax,-0xc(%rbp)
  55ea5e:       48 83 45 f8 04          addq   $0x4,-0x8(%rbp)
  55ea63:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea67:       48 3b 45 e8             cmp    -0x18(%rbp),%rax
  55ea6b:       72 e8                   jb     55ea55 <compute_key+0x33>
  55ea6d:       48 8b 15 cc 26 00 00    mov    0x26cc(%rip),%rdx        # 561140 <key_str>
  55ea74:       8b 45 f4                mov    -0xc(%rbp),%eax
  55ea77:       48 89 d6                mov    %rdx,%rsi
  55ea7a:       89 c7                   mov    %eax,%edi
  55ea7c:       e8 ec fe ff ff          call   55e96d <int2hex>
  55ea81:       90                      nop
  55ea82:       c9                      leave
  55ea83:       c3                      ret
```

we see `anti_debug` function is called through `55ea45:       e8 85 fc ff ff          call   55e6cf <anti_debug>`. It's located at `55ea45` and is composed of `e8 85 fc ff ff`.
.text located at `0x55e0a0`, offset `10a0`.
hence the `call   55e6cf <anti_debug>` will be located at offset `(0x55ea45 - 0x55e0a0 + 0x10a0) = 0x1A45` in the file. now we hexedit to replace it with NOP instr's (`90`).

now we see:
```bash
objdump re_entry -dj .text --wide
... 
000000000055ea22 <compute_key>:
  55ea22:       55                      push   %rbp
  55ea23:       48 89 e5                mov    %rsp,%rbp
  55ea26:       48 83 ec 20             sub    $0x20,%rsp
  55ea2a:       48 8d 05 70 fc ff ff    lea    -0x390(%rip),%rax        # 55e6a1 <start_protect>
  55ea31:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  55ea35:       48 8d 05 38 01 00 00    lea    0x138(%rip),%rax        # 55eb74 <end_protect>
  55ea3c:       48 89 45 e8             mov    %rax,-0x18(%rbp)
  55ea40:       b8 00 00 00 00          mov    $0x0,%eax
  55ea45:       90                      nop
  55ea46:       90                      nop
  55ea47:       90                      nop
  55ea48:       90                      nop
  55ea49:       90                      nop
  55ea4a:       8b 05 b4 26 00 00       mov    0x26b4(%rip),%eax        # 561104 <seed>
  55ea50:       89 45 f4                mov    %eax,-0xc(%rbp)
  55ea53:       eb 0e                   jmp    55ea63 <compute_key+0x41>
  55ea55:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea59:       8b 00                   mov    (%rax),%eax
  55ea5b:       31 45 f4                xor    %eax,-0xc(%rbp)
  55ea5e:       48 83 45 f8 04          addq   $0x4,-0x8(%rbp)
  55ea63:       48 8b 45 f8             mov    -0x8(%rbp),%rax
  55ea67:       48 3b 45 e8             cmp    -0x18(%rbp),%rax
  55ea6b:       72 e8                   jb     55ea55 <compute_key+0x33>
  55ea6d:       48 8b 15 cc 26 00 00    mov    0x26cc(%rip),%rdx        # 561140 <key_str>
  55ea74:       8b 45 f4                mov    -0xc(%rbp),%eax
  55ea77:       48 89 d6                mov    %rdx,%rsi
  55ea7a:       89 c7                   mov    %eax,%edi
  55ea7c:       e8 ec fe ff ff          call   55e96d <int2hex>
  55ea81:       90                      nop
  55ea82:       c9                      leave
  55ea83:       c3                      ret
```

we can see it has been successfully applied:
```bash
user1@comp3703:~/assignment01$ nasm -f bin -o entry_q2.bin try.s
user1@comp3703:~/assignment01$ python3 elfins.py re_entry2 entry_q2.bin --patchentry
Reusing a NOTE segment for the injected code.
Creating a new section header for .injected
Code injected at offset: 0x5000, virtual address 0x805000. 
Patching entry point to 0x805000
Modified binary saved to injected.elf
user1@comp3703:~/assignment01$ ./injected.elf
Segmentation fault (core dumped)
```

segmentation fault! this is new? maybe it was caused by disabling the anti-debug?!
we debug to investigate


```

gef➤  break *0x55e0a0
Breakpoint 1 at 0x55e0a0
gef➤  break *0x55eaaf
Breakpoint 2 at 0x55eaaf
gef➤  break *0x55ea22
Breakpoint 3 at 0x55ea22
gef➤  break *0x55e96d
Breakpoint 4 at 0x55e96d

...
→   0x55e9c8 <int2hex+005b>   mov    BYTE PTR [rax], dl
Id 1, Name: "injected.elf", stopped 0x55e9c8 in int2hex (), reason: SIGSEGV
```

we can see the program is having a seg fault at the end of the `int2hex` function. i have no idea why.



----

Noticed stack was out of alignment after doing the mmap calls.
so put another stack alignment thingo in which fixed it. but still says "[1]+ Stopped   injected.elf". 


