We know we need to use code injection and GOT modification. 
First we look at all the section headers. we can note there is no `.plt.sec` section, so we use `.plt` section  instead
```bash
user1@comp3703:~/assignment01$ readelf got_mod --wide -S
There are 36 section headers, starting at offset 0x64f0:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000444cb8 000cb8 00001c 00   A  0   0  1
  [ 2] .note.gnu.property NOTE            0000000000444cd8 000cd8 000020 00   A  0   0  8
  [ 3] .note.gnu.build-id NOTE            0000000000444cf8 000cf8 000024 00   A  0   0  4
  [ 4] .note.ABI-tag     NOTE            0000000000444d1c 000d1c 000020 00   A  0   0  4
  [ 5] .gnu.hash         GNU_HASH        0000000000444d40 000d40 000030 00   A  6   0  8
  [ 6] .dynsym           DYNSYM          0000000000444d70 000d70 000168 18   A  7   1  8
  [ 7] .dynstr           STRTAB          0000000000444ed8 000ed8 000092 00   A  0   0  1
  [ 8] .gnu.version      VERSYM          0000000000444f6a 000f6a 00001e 02   A  6   0  2
  [ 9] .gnu.version_r    VERNEED         0000000000444f88 000f88 000030 00   A  7   1  8
  [10] .rela.dyn         RELA            0000000000444fb8 000fb8 000078 18   A  6   0  8
  [11] .rela.plt         RELA            0000000000445030 001030 0000d8 18  AI  6  23  8
  [12] .init             PROGBITS        0000000000446000 002000 00001b 00  AX  0   0  4
  [13] .plt              PROGBITS        0000000000446020 002020 0000a0 10  AX  0   0 16
  [14] .text             PROGBITS        00000000004460c0 0020c0 000a12 00  AX  0   0 16
  [15] .fini             PROGBITS        0000000000446ad4 002ad4 00000d 00  AX  0   0  4
  [16] .rodata           PROGBITS        0000000000447000 003000 0000d3 00   A  0   0  8
  [17] .eh_frame_hdr     PROGBITS        00000000004470d4 0030d4 0000ac 00   A  0   0  4
  [18] .eh_frame         PROGBITS        0000000000447180 003180 00028c 00   A  0   0  8
  [19] .init_array       INIT_ARRAY      0000000000448e08 003e08 000010 08  WA  0   0  8
  [20] .fini_array       FINI_ARRAY      0000000000448e18 003e18 000008 08  WA  0   0  8
  [21] .dynamic          DYNAMIC         0000000000448e20 003e20 0001d0 10  WA  7   0  8
  [22] .got              PROGBITS        0000000000448ff0 003ff0 000010 08  WA  0   0  8
  [23] .got.plt          PROGBITS        0000000000449000 004000 000060 08  WA  0   0  8
  [24] .data             PROGBITS        0000000000449060 004060 000068 00  WA  0   0 32
  [25] .bss              NOBITS          00000000004490e0 0040c8 000050 00  WA  0   0 32
  [26] .comment          PROGBITS        0000000000000000 0040c8 00002b 01  MS  0   0  1
  [27] .debug_aranges    PROGBITS        0000000000000000 0040f3 000060 00      0   0  1
  [28] .debug_info       PROGBITS        0000000000000000 004153 000ae7 00      0   0  1
  [29] .debug_abbrev     PROGBITS        0000000000000000 004c3a 0003ed 00      0   0  1
  [30] .debug_line       PROGBITS        0000000000000000 005027 0003a2 00      0   0  1
  [31] .debug_str        PROGBITS        0000000000000000 0053c9 0004ca 01  MS  0   0  1
  [32] .debug_line_str   PROGBITS        0000000000000000 005893 00010f 01  MS  0   0  1
  [33] .symtab           SYMTAB          0000000000000000 0059a8 000678 18     34  20  8
  [34] .strtab           STRTAB          0000000000000000 006020 000365 00      0   0  1
  [35] .shstrtab         STRTAB          0000000000000000 006385 000166 00      0   0  1
```

By looking at the dissassembly of the `main` function, we can see that the only call to `plt` is using the `printf`. We can also see there exists an `unmask_flag` function (`0x4469ec`), which appears to display the flag when called.
```bash
00000000004469ec <unmask_flag>:
  4469ec:       55                      push   rbp
  4469ed:       48 89 e5                mov    rbp,rsp
  4469f0:       48 83 ec 30             sub    rsp,0x30
  4469f4:       48 89 7d d8             mov    QWORD PTR [rbp-0x28],rdi
  4469f8:       8b 05 c6 26 00 00       mov    eax,DWORD PTR [rip+0x26c6]        # 4490c4 <unmasked>
  4469fe:       85 c0                   test   eax,eax
  446a00:       74 16                   je     446a18 <unmask_flag+0x2c>
  446a02:       48 8d 05 68 06 00 00    lea    rax,[rip+0x668]        # 447071 <_IO_stdin_used+0x71>
  446a09:       48 89 c7                mov    rdi,rax
  446a0c:       b8 00 00 00 00          mov    eax,0x0
  446a11:       e8 5a f6 ff ff          call   446070 <printf@plt>
  446a16:       eb 7e                   jmp    446a96 <unmask_flag+0xaa>
  446a18:       48 8d 05 6a 06 00 00    lea    rax,[rip+0x66a]        # 447089 <_IO_stdin_used+0x89>
  446a1f:       48 89 c7                mov    rdi,rax
  446a22:       b8 00 00 00 00          mov    eax,0x0
  446a27:       e8 44 f6 ff ff          call   446070 <printf@plt>
  446a2c:       48 8d 45 e0             lea    rax,[rbp-0x20]
  446a30:       48 89 c7                mov    rdi,rax
  446a33:       e8 03 ff ff ff          call   44693b <compute_key>
  446a38:       8b 0d 42 26 00 00       mov    ecx,DWORD PTR [rip+0x2642]        # 449080 <len>
  446a3e:       48 8b 55 d8             mov    rdx,QWORD PTR [rbp-0x28]
  446a42:       48 8d 45 e0             lea    rax,[rbp-0x20]
  446a46:       41 89 c8                mov    r8d,ecx
  446a49:       b9 08 00 00 00          mov    ecx,0x8
  446a4e:       48 8d 35 4b 26 00 00    lea    rsi,[rip+0x264b]        # 4490a0 <ct>
  446a55:       48 89 c7                mov    rdi,rax
  446a58:       e8 49 f7 ff ff          call   4461a6 <decrypt>
  446a5d:       c7 05 5d 26 00 00 01 00 00 00   mov    DWORD PTR [rip+0x265d],0x1        # 4490c4 <unmasked>
  446a67:       48 8d 05 2d 06 00 00    lea    rax,[rip+0x62d]        # 44709b <_IO_stdin_used+0x9b>
  446a6e:       48 89 c7                mov    rdi,rax
  446a71:       b8 00 00 00 00          mov    eax,0x0
  446a76:       e8 f5 f5 ff ff          call   446070 <printf@plt>
  446a7b:       48 8b 45 d8             mov    rax,QWORD PTR [rbp-0x28]
  446a7f:       48 89 c6                mov    rsi,rax
  446a82:       48 8d 05 19 06 00 00    lea    rax,[rip+0x619]        # 4470a2 <_IO_stdin_used+0xa2>
  446a89:       48 89 c7                mov    rdi,rax
  446a8c:       b8 00 00 00 00          mov    eax,0x0
  446a91:       e8 da f5 ff ff          call   446070 <printf@plt>
  446a96:       c9                      leave  
  446a97:       c3                      ret    

...

0000000000446a98 <main>:
  446a98:       55                      push   rbp
  446a99:       48 89 e5                mov    rbp,rsp
  446a9c:       48 8d 05 05 06 00 00    lea    rax,[rip+0x605]        # 4470a8 <_IO_stdin_used+0xa8>
  446aa3:       48 89 c7                mov    rdi,rax
  446aa6:       b8 00 00 00 00          mov    eax,0x0
  446aab:       e8 c0 f5 ff ff          call   446070 <printf@plt>
  446ab0:       b8 00 00 00 00          mov    eax,0x0
  446ab5:       5d                      pop    rbp
  446ab6:       c3                      ret    
```

Additionally, by examining the Ghidra decompilation of `unmask_flag`, we can see that there is a check on the value of `unmasked`, which is located at `0x4490c4`. We will need to set this to `0`.  
```c
void unmask_flag(char *pt)

{
  char *pt_local;
  char key [32];
  
  if (unmasked == 0) {
    printf("Unmasking flag...");
    compute_key(key);
    decrypt((EVP_PKEY_CTX *)key,(uchar *)ct,(size_t *)pt,(uchar *)0x8,(ulong)(uint)len);
    unmasked = 1;
    printf("done.\n");
    printf("%s\n",pt);
  }
  else {
    printf("Flag already unmasked!\n");
  }
  return;
}
```

So, we should hijack the GOT entry for `printf@plt`. But we can aslo see that `unmask_flag` also makes call to `printf`, so once we hijack the GOT entry to `printf`, we need to restore it back to its original value after we do the exploitation.

```bash
user1@comp3703:~/assignment01$ objdump -M intel -dj .plt got_mod --wide

got_mod:     file format elf64-x86-64


Disassembly of section .plt:

...

0000000000446070 <printf@plt>:
  446070:       ff 25 c2 2f 00 00       jmp    QWORD PTR [rip+0x2fc2]        # 449038 <printf@GLIBC_2.2.5>
  446076:       68 04 00 00 00          push   0x4
  44607b:       e9 a0 ff ff ff          jmp    446020 <_init+0x20>
```

We can see that the GOT entry address is located at `0x449038`. Now lets find it in the  `.got.plt` section:
```bash
user1@comp3703:~/assignment01$ objdump -sj .got.plt got_mod

got_mod:     file format elf64-x86-64

Contents of section .got.plt:
 449000 208e4400 00000000 00000000 00000000   .D.............
 449010 00000000 00000000 36604400 00000000  ........6`D.....
 449020 46604400 00000000 56604400 00000000  F`D.....V`D.....
 449030 66604400 00000000 76604400 00000000  f`D.....v`D.....
 449040 86604400 00000000 96604400 00000000  .`D......`D.....
 449050 a6604400 00000000 b6604400 00000000  .`D......`D.....
```

Address `0x449038` contains bytes `76 60 44 00` (little endian), meaning it actually contains address `0x446076`.
We copy `.got.s` from lab03, but modify the values. Note that we also set `unmasked` to `0`:
```x86asm
BITS 64

SECTION .text
global main

main:
    mov qword [0x4490c4], 0  ; set unmasked to the correct value 
    mov qword [0x449038], 0x446076  ; restore the GOT entry for printf
    push rbx                    ;
    mov rbx, 0x4469ec             ; address of unmask_flag() function 
    call rbx                    ; call the unmask_flag() function
    pop rbx                     ; 
    ret
```
This was resulting in the classic "Stopped.. " message. So I tried adding the suggested stack alignment code from lectures.
Wont show it to save space, buit Spoiler: it actually changed it to seg fault.

After re examining the `unmask_flag` function in Ghidra, we can see it takes param `char *  RDI:8   pt`.
Hence we need to allocate 8 bytes of memory. 

```x86asm
BITS 64

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

    mov qword [0x4490c4], 0  ; set unmasked to the correct value 
    mov qword [0x449038], 0x446076  ; restore the GOT entry for printf
    push rbx                    ;
    mov rbx, 0x4469ec             ; address of unmask_flag() function 
    call rbx                    ; call the unmask_flag() function
    pop rbx                     ; 
    ret
```

Now we can compile this and inject it - we can use the --patchgot option from elfins.py
```bash
user1@comp3703:~/assignment01$ nasm -f bin -o got.bin got.s
user1@comp3703:~/assignment01$ python3 ./elfins.py got_mod got.bin -o hijack_got --patchgot printf
Reusing a NOTE segment for the injected code.
Creating a new section header for .injected
Code injected at offset: 0x7000, virtual address 0x807000. 
Patching the GOT entry for printf.
Modified binary saved to hijack_got
```

Now we run the binary and pray
```
user1@comp3703:~/assignment01$ ./hijack_got
Unmasking flag...done.
flag{broad-fork}
```
We have the flag. great success.